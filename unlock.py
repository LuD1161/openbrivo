#!/usr/bin/env python3
"""Log in and list all nearby BLE advertisers without connecting to them."""
from __future__ import annotations

import asyncio
import getpass
import json
import os
import queue
import shutil
import stat
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

OPENBRIVO_DIR = Path(__file__).resolve().parent
REPO_ROOT = OPENBRIVO_DIR.parent
ANALYSIS_DIR = REPO_ROOT / "analysis"
if (OPENBRIVO_DIR / "brivo_poc").is_dir() and str(OPENBRIVO_DIR) not in sys.path:
    sys.path.insert(0, str(OPENBRIVO_DIR))
elif str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))

from brivo_poc import provisioning as prov  # noqa: E402
from brivo_poc.allegion_xe360 import (  # noqa: E402
    PlatinumVersion,
    parse_transport_packet,
)
from brivo_poc.app_config_resolver import (  # noqa: E402
    AppConfigResolver,
    default_resources_root,
)
from brivo_poc.provisioned_bundle import (
    load_provisioned_credential_bundle,  # noqa: E402
)
from brivo_poc.session_orchestrator import (  # noqa: E402
    AdapterMode,
    BenchAuthorization,
    BridgeEvent,
    BridgeEventKind,
    PlatinumSessionOrchestrator,
    SessionConfiguration,
    SessionError,
    SessionState,
)

try:  # Supports both `python openbrivo.py` and package imports in tests.
    from .terminal_ui import (
        BOLD,
        CYAN,
        DIM,
        GREEN,
        RED,
        YELLOW,
        banner,
        paint,
        prompt,
        status,
    )
except ImportError:  # pragma: no cover - exercised by the script entrypoint
    from terminal_ui import (
        BOLD,
        CYAN,
        DIM,
        GREEN,
        RED,
        YELLOW,
        banner,
        paint,
        prompt,
        status,
    )

FIREBASE_KEYS = {
    "US": "AIzaSyCnOoSRkfsWoIRQfdARd2LmTXO-WyOo-fI",
    "EU": "AIzaSyDZycLr7MnBcVI2HpltJyWXsTqvM9tSP5w",
}
VERIFY_URL = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key="
ANDROID_PACKAGE = "com.brivo.pass"
ANDROID_CERT_SHA1 = "755739e38803fb04a8174bc82478b9dcc3176f78"

BASE_DIR = Path.cwd() / ".openbrivo" / "xe360"
CACHE_FILES = (
    "bundle.json",
    "credential.bin",
    "signing-material.bin",
    "reader-device-pins.json",
)


class CredentialLoginError(RuntimeError):
    pass


def ask(prompt: str, secret: bool = False) -> str:
    value = getpass.getpass(prompt + ": ") if secret else input(prompt + ": ")
    value = value.strip()
    if not value:
        print("(required)", file=sys.stderr)
        sys.exit(2)
    return value


def replace_cached_bundle(source: Path, destination: Path) -> Path:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(mode=0o700, parents=True)
    os.chmod(destination, 0o700)
    for name in CACHE_FILES:
        target = destination / name
        shutil.copyfile(source / name, target)
        os.chmod(target, 0o600)
    load_provisioned_credential_bundle(destination, allows_live=True)
    return destination


def remove_cached_bundle(destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)


def has_existing_identity() -> bool:
    profile = BASE_DIR / "profile.json"
    identity = BASE_DIR / "device-identity.der"
    try:
        values = json.loads(profile.read_text())
    except (OSError, ValueError):
        return False
    required = ("device_id", "account_id", "connected_account_id")
    return identity.is_file() and all(isinstance(values.get(key), str) and values[key] for key in required)


def firebase_login(username: str, password: str, region: str) -> dict:
    import urllib.request

    body = json.dumps(
        {
            "email": username,
            "password": password,
            "returnSecureToken": True,
            "clientType": "CLIENT_TYPE_ANDROID",
        }
    ).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Android-Package": ANDROID_PACKAGE,
        "X-Android-Cert": ANDROID_CERT_SHA1,
    }
    req = urllib.request.Request(
        VERIFY_URL + FIREBASE_KEYS[region], data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as err:  # type: ignore[attr-defined]
        try:
            error = json.loads(err.read()).get("error", {})
            message = error.get("message") or f"HTTP {err.code}"
        except (ValueError, AttributeError):
            message = f"HTTP {err.code}"
        raise CredentialLoginError(str(message)) from err
    for name in ("idToken", "refreshToken", "localId"):
        if not data.get(name):
            raise CredentialLoginError(f"login response omitted {name}")
    status("✓", "Signed in", data.get("email", username), GREEN)
    return data


def pick_right(compatible: list[dict]) -> dict | None:
    """Interactive picker shown when the account has multiple BLE credentials."""
    print(f"\n  {paint('🔑  BLE credentials', BOLD, CYAN)}")
    print(paint(f"  Found {len(compatible)} available credential(s)", DIM))
    for index, right in enumerate(compatible, start=1):
        label = (
            right.get("name")
            or right.get("accessRightName")
            or right.get("displayName")
            or prov._opaque_choice(right["id"])
        )
        locks = prov._lock_ids_from_metadata(right)
        types = ",".join(sorted(prov._payload_types(right)))
        suffix = f"  ·  locks: {', '.join(locks)}" if locks else ""
        print(f"    {paint(index, BOLD, CYAN)}) {label}  {paint(f'[{types}]', DIM)}{suffix}")
    choice = input(prompt("\n  Use which credential? [1]: ")).strip() or "1"
    try:
        return compatible[int(choice) - 1]
    except (ValueError, IndexError):
        print("invalid choice", file=sys.stderr)
        return None


def fetch_credentials(username_token: dict, region: str, bundle_dest: Path) -> Path:
    run_dir = BASE_DIR / f"run-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    run_dir.mkdir(mode=0o700, parents=True)
    os.chmod(run_dir, 0o700)

    profile_file = BASE_DIR / "profile.json"
    identity_file = BASE_DIR / "device-identity.der"
    profile: dict = {}
    if profile_file.exists():
        try:
            profile = json.loads(profile_file.read_text())
        except (OSError, ValueError):
            profile = {}

    argv = [
        "--run-dir", str(run_dir),
        "--live",
        "--authorization-ack", prov.LIVE_ACK,
        "--bundle-destination", str(bundle_dest),
        "--region", region.lower(),
    ]
    values: dict[str, object] = {
        "firebase_id_token": username_token["idToken"],
        "firebase_uid": username_token["localId"],
    }
    existing = bool(profile.get("device_id")) and identity_file.exists()
    if existing:
        argv += [
            "--enrollment-mode", "existing",
            "--device-identity-file", str(identity_file),
        ]
        values.update(
            device_id=profile["device_id"],
            account_id=profile["account_id"],
            connected_account_id=profile["connected_account_id"],
        )
    else:
        argv += ["--enrollment-mode", "create"]

    args = prov.parser().parse_args(argv)
    args.dry_run = False
    config = AppConfigResolver(default_resources_root(), run_dir, None).resolve(args.region)
    prov._merge_config(args, values, config)
    prov._preflight_live(args, values)

    status("☁", "Credentials", "fetching securely from the cloud…", CYAN)
    with prov.ProvisioningRecorder.open(run_dir, stages=prov.STAGES) as recorder:
        workflow = prov.Workflow(
            args, values, config, recorder, None, rights_choice_callback=pick_right
        )
        try:
            workflow.run()
        finally:
            enrollment_ids = {
                name: workflow.state.get(name)
                for name in ("device_id", "account_id", "connected_account_id")
            }
            if all(isinstance(value, str) and value for value in enrollment_ids.values()):
                generated_identity = run_dir / "device-identity.der"
                if not existing and generated_identity.exists():
                    shutil.copyfile(generated_identity, identity_file)
                    os.chmod(identity_file, 0o600)
                profile.update(enrollment_ids)
                profile["access_right_id"] = workflow.state.get("access_right_id")
                fd = os.open(profile_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as handle:
                    json.dump(profile, handle, indent=2)
                os.chmod(profile_file, stat.S_IRUSR | stat.S_IWUSR)
    chosen = workflow.state.get("right_metadata") or {}
    label = chosen.get("name") or chosen.get("accessRightName") or prov._opaque_choice(str(chosen.get("id")))
    status("✓", "Credential ready", label, GREEN)
    return bundle_dest


XE360_SERVICE_UUID = "1E345CBB-1103-43F4-8D53-D19CAE536400"
XE360_CHARACTERISTIC_UUID = "1E345CBB-1103-43F4-8D53-D19CAE536401"


def _sapphire_version(manufacturer: bytes) -> int | None:
    if not manufacturer.startswith(bytes.fromhex("3B01020022")):
        return None
    offset = 5
    version = None
    while offset < len(manufacturer):
        length = manufacturer[offset]
        if not length or offset + 1 + length > len(manufacturer):
            return None
        if manufacturer[offset + 1] == 3 and length == 3:
            candidate = manufacturer[offset + 3]
            if candidate not in (1, 2, 3) or version is not None:
                return None
            version = candidate
        offset += length + 1
    return version


class CoreBluetoothController:
    """One persistent PyObjC central used for discovery and the selected GATT session."""

    def __init__(self) -> None:
        try:
            import CoreBluetooth
            import Foundation
        except ImportError as exc:
            raise RuntimeError(
                "PyObjC CoreBluetooth is required; install pyobjc-framework-CoreBluetooth"
            ) from exc

        self.cb = CoreBluetooth
        self.foundation = Foundation

        class Delegate(Foundation.NSObject):
            def centralManagerDidUpdateState_(delegate, central):
                delegate.owner._central_state_changed(central)

            def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
                delegate, central, peripheral, advertisement, rssi
            ):
                delegate.owner._discovered(peripheral, advertisement, rssi)

            def centralManager_didConnectPeripheral_(delegate, central, peripheral):
                delegate.owner._connected(peripheral)

            def centralManager_didFailToConnectPeripheral_error_(
                delegate, central, peripheral, error
            ):
                delegate.owner._fail(f"BLE connection failed: {error}")

            def centralManager_didDisconnectPeripheral_error_(
                delegate, central, peripheral, error
            ):
                delegate.owner._disconnected(error)

            def peripheral_didDiscoverServices_(delegate, peripheral, error):
                delegate.owner._services_discovered(peripheral, error)

            def peripheral_didDiscoverCharacteristicsForService_error_(
                delegate, peripheral, service, error
            ):
                delegate.owner._characteristics_discovered(peripheral, service, error)

            def peripheral_didUpdateNotificationStateForCharacteristic_error_(
                delegate, peripheral, characteristic, error
            ):
                delegate.owner._notification_state(characteristic, error)

            def peripheral_didUpdateValueForCharacteristic_error_(
                delegate, peripheral, characteristic, error
            ):
                delegate.owner._notification(characteristic, error)

            def peripheralIsReadyToSendWriteWithoutResponse_(delegate, peripheral):
                delegate.owner._writer_ready()

        self.delegate = Delegate.alloc().init()
        self.delegate.owner = self
        self.manager = CoreBluetooth.CBCentralManager.alloc().initWithDelegate_queue_options_(
            self.delegate, None, None
        )
        self.devices: dict[str, dict] = {}
        self.target = None
        self.characteristic = None
        self.events: deque[BridgeEvent] = deque()
        self.error: str | None = None
        self.powered_on = False
        self.connected = False
        self.ready = False
        self.closed = False
        self.maximum_write_value_length = 0
        self.write_count = 0
        self.notification_count = 0
        self.disconnect_error: str | None = None
        self._service_uuid = CoreBluetooth.CBUUID.UUIDWithString_(XE360_SERVICE_UUID)
        self._characteristic_uuid = CoreBluetooth.CBUUID.UUIDWithString_(
            XE360_CHARACTERISTIC_UUID
        )

    def _pump(self, seconds: float = 0.03) -> None:
        until = self.foundation.NSDate.dateWithTimeIntervalSinceNow_(seconds)
        self.foundation.NSRunLoop.currentRunLoop().runUntilDate_(until)

    def _wait(self, predicate, timeout: float, message: str) -> None:
        deadline = time.monotonic() + timeout
        while not predicate():
            if self.error:
                raise RuntimeError(self.error)
            if time.monotonic() >= deadline:
                raise RuntimeError(message)
            self._pump()

    def _fail(self, message: str) -> None:
        self.error = message

    def _central_state_changed(self, central) -> None:
        state = int(central.state())
        if state == int(self.cb.CBManagerStatePoweredOn):
            self.powered_on = True
        elif state in (
            int(self.cb.CBManagerStateUnsupported),
            int(self.cb.CBManagerStateUnauthorized),
            int(self.cb.CBManagerStatePoweredOff),
        ):
            self._fail("Bluetooth is unavailable or unauthorized")

    @staticmethod
    def _data(value) -> bytes:
        return bytes(value) if value is not None else b""

    def _discovered(self, peripheral, advertisement, rssi) -> None:
        identifier = str(peripheral.identifier().UUIDString()).upper()
        local_name = advertisement.get(self.cb.CBAdvertisementDataLocalNameKey)
        name = str(local_name or peripheral.name() or "<unnamed>")
        measured = int(rssi) if int(rssi) != 127 else None
        manufacturer = self._data(
            advertisement.get(self.cb.CBAdvertisementDataManufacturerDataKey)
        )
        version = _sapphire_version(manufacturer)
        uid = None
        service_data = advertisement.get(self.cb.CBAdvertisementDataServiceDataKey) or {}
        for key, value in service_data.items():
            if str(key.UUIDString()).upper() == "180A":
                raw_uid = self._data(value)
                if len(raw_uid) == 8 and raw_uid != b"\0" * 8:
                    uid = raw_uid.hex().upper()
        device = self.devices.setdefault(
            identifier,
            {
                "uuid": identifier,
                "name": name,
                "rssi": measured,
                "uid": uid,
                "platinum_version": version,
                "_peripheral": peripheral,
                "_controller": self,
            },
        )
        if device["name"] == "<unnamed>" and name != "<unnamed>":
            device["name"] = name
        if measured is not None and (device["rssi"] is None or measured > device["rssi"]):
            device["rssi"] = measured
        if uid:
            device["uid"] = uid
        if version:
            device["platinum_version"] = version
        device["_peripheral"] = peripheral

    def discover(self, seconds: int) -> list[dict]:
        self._wait(lambda: self.powered_on, 10, "Bluetooth did not become ready")
        self.manager.scanForPeripheralsWithServices_options_(
            None, {self.cb.CBCentralManagerScanOptionAllowDuplicatesKey: True}
        )
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.error:
                raise RuntimeError(self.error)
            self._pump(min(0.05, deadline - time.monotonic()))
        self.manager.stopScan()
        return sorted(
            self.devices.values(),
            key=lambda item: item["rssi"] if item["rssi"] is not None else -1000,
            reverse=True,
        )

    def connect(self, device: dict, timeout: int = 35) -> None:
        self.target = device["_peripheral"]
        self.target.setDelegate_(self.delegate)
        self.manager.connectPeripheral_options_(self.target, None)
        self._wait(lambda: self.ready, timeout, "XE360 GATT connection timed out")

    def _connected(self, peripheral) -> None:
        if peripheral != self.target:
            return
        self.connected = True
        peripheral.discoverServices_([self._service_uuid])

    def _services_discovered(self, peripheral, error) -> None:
        if error is not None:
            self._fail(f"service discovery failed: {error}")
            return
        service = next(
            (
                item for item in (peripheral.services() or [])
                if str(item.UUID().UUIDString()).upper() == XE360_SERVICE_UUID
            ),
            None,
        )
        if service is None:
            self._fail("selected device does not expose the XE360 service")
            return
        peripheral.discoverCharacteristics_forService_([self._characteristic_uuid], service)

    def _characteristics_discovered(self, peripheral, service, error) -> None:
        if error is not None:
            self._fail(f"characteristic discovery failed: {error}")
            return
        characteristic = next(
            (
                item for item in (service.characteristics() or [])
                if str(item.UUID().UUIDString()).upper() == XE360_CHARACTERISTIC_UUID
            ),
            None,
        )
        if characteristic is None:
            self._fail("selected device does not expose the XE360 characteristic")
            return
        properties = int(characteristic.properties())
        required = int(self.cb.CBCharacteristicPropertyNotify) | int(
            self.cb.CBCharacteristicPropertyWriteWithoutResponse
        )
        if properties & required != required:
            self._fail("XE360 characteristic lacks notify or write-without-response")
            return
        self.characteristic = characteristic
        self.maximum_write_value_length = int(
            peripheral.maximumWriteValueLengthForType_(
                self.cb.CBCharacteristicWriteWithoutResponse
            )
        )
        peripheral.setNotifyValue_forCharacteristic_(True, characteristic)

    def _notification_state(self, characteristic, error) -> None:
        if error is not None or not bool(characteristic.isNotifying()):
            self._fail(f"notification subscription failed: {error}")
            return
        self.ready = True
        self.events.append(BridgeEvent(BridgeEventKind.DESCRIPTOR_ENABLED))

    def _notification(self, characteristic, error) -> None:
        if error is not None:
            self._fail(f"notification failed: {error}")
            return
        frame = self._data(characteristic.value())
        if frame:
            self.notification_count += 1
            self.events.append(BridgeEvent(BridgeEventKind.INBOUND_FRAME, frame))

    def _writer_ready(self) -> None:
        self.events.append(BridgeEvent(BridgeEventKind.WRITER_READY))

    def disconnect(self) -> None:
        if self.target is None or self.closed:
            return
        self.manager.cancelPeripheralConnection_(self.target)

    def _disconnected(self, error) -> None:
        self.disconnect_error = str(error) if error is not None else None
        self.connected = False
        self.ready = False
        self.closed = True
        self.events.append(BridgeEvent(BridgeEventKind.DISCONNECTED))


class PyObjCCoreBluetoothTransport:
    adapter_mode = AdapterMode.LIVE
    adapter_identity = "macos-corebluetooth-pyobjc"
    notification_bytes_emitted = True

    def __init__(self, controller: CoreBluetoothController, device: dict) -> None:
        self.controller = controller
        self.bench_reader_serial = device["uid"]
        self.observed_platinum_version = PlatinumVersion[
            f"V{device.get('platinum_version') or 3}"
        ]
        controller.connect(device)
        self.maximum_write_value_length = controller.maximum_write_value_length

    @property
    def can_write_without_response(self) -> bool:
        return bool(
            self.controller.ready
            and not self.controller.closed
            and self.controller.target.canSendWriteWithoutResponse()
        )

    def write_frame(self, frame: bytes, *, purpose: str) -> bool:
        del purpose
        if not self.can_write_without_response:
            raise SessionError("CoreBluetooth write attempted while writer is not ready")
        if not frame or len(frame) > self.maximum_write_value_length:
            raise SessionError("invalid CoreBluetooth frame length")
        data = self.controller.foundation.NSData.dataWithBytes_length_(frame, len(frame))
        self.controller.target.writeValue_forCharacteristic_type_(
            data,
            self.controller.characteristic,
            self.controller.cb.CBCharacteristicWriteWithoutResponse,
        )
        self.controller.write_count += 1
        self.controller.events.append(BridgeEvent(BridgeEventKind.WRITER_READY))
        return True

    def next_event(self) -> BridgeEvent:
        self.controller._wait(
            lambda: bool(self.controller.events),
            40,
            "timed out waiting for the XE360 reader",
        )
        return self.controller.events.popleft()

    def close(self) -> None:
        self.controller.disconnect()


class BleakController:
    """Persistent async Bleak backend used by Linux and Windows."""

    def __init__(self) -> None:
        try:
            from bleak import BleakClient, BleakScanner
        except ImportError as exc:
            raise RuntimeError(
                "Bleak is required on Linux and Windows; install dependencies with "
                "python -m pip install -r requirements.txt"
            ) from exc

        self._client_type = BleakClient
        self._scanner_type = BleakScanner
        self._loop = asyncio.new_event_loop()
        self._loop_started = threading.Event()
        self._thread = threading.Thread(
            target=self._run_event_loop,
            name="openbrivo-bleak",
            daemon=True,
        )
        self._thread.start()
        if not self._loop_started.wait(5):
            raise RuntimeError("Bleak event loop did not start")

        self.devices: dict[str, dict] = {}
        self.events: queue.Queue[BridgeEvent] = queue.Queue()
        self.client = None
        self.characteristic = None
        self.connected = False
        self.ready = False
        self.closed = False
        self.maximum_write_value_length = 0
        self.write_count = 0
        self.notification_count = 0
        self.disconnect_error: str | None = None

    def _run_event_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop_started.set()
        self._loop.run_forever()

    def _submit(self, coroutine, timeout: float):
        future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        try:
            return future.result(timeout=timeout)
        except BaseException:
            future.cancel()
            raise

    @staticmethod
    def _service_data_value(service_data: dict[str, bytes], short_uuid: str) -> bytes:
        canonical = f"0000{short_uuid.lower()}-0000-1000-8000-00805f9b34fb"
        for key, value in service_data.items():
            if str(key).lower() in (short_uuid.lower(), canonical):
                return bytes(value)
        return b""

    def _discovered(self, ble_device, advertisement) -> None:
        identifier = str(ble_device.address).upper()
        name = str(advertisement.local_name or ble_device.name or "<unnamed>")
        measured = advertisement.rssi if advertisement.rssi != 127 else None
        version = None
        for company_id, payload in advertisement.manufacturer_data.items():
            manufacturer = int(company_id).to_bytes(2, "little") + bytes(payload)
            version = _sapphire_version(manufacturer)
            if version is not None:
                break
        raw_uid = self._service_data_value(advertisement.service_data, "180a")
        uid = (
            raw_uid.hex().upper()
            if len(raw_uid) == 8 and raw_uid != b"\0" * 8
            else None
        )
        device = self.devices.setdefault(
            identifier,
            {
                "uuid": identifier,
                "name": name,
                "rssi": measured,
                "uid": uid,
                "platinum_version": version,
                "_ble_device": ble_device,
                "_controller": self,
            },
        )
        if device["name"] == "<unnamed>" and name != "<unnamed>":
            device["name"] = name
        if measured is not None and (
            device["rssi"] is None or measured > device["rssi"]
        ):
            device["rssi"] = measured
        if uid:
            device["uid"] = uid
        if version:
            device["platinum_version"] = version
        device["_ble_device"] = ble_device

    async def _discover(self, seconds: int) -> list[dict]:
        self.devices.clear()
        scanner = self._scanner_type(self._discovered)
        async with scanner:
            await asyncio.sleep(seconds)
        return sorted(
            self.devices.values(),
            key=lambda item: item["rssi"] if item["rssi"] is not None else -1000,
            reverse=True,
        )

    def discover(self, seconds: int) -> list[dict]:
        try:
            return self._submit(self._discover(seconds), seconds + 15)
        except Exception as exc:
            raise RuntimeError(f"Bluetooth discovery failed: {exc}") from exc

    def _clear_events(self) -> None:
        while True:
            try:
                self.events.get_nowait()
            except queue.Empty:
                return

    def _notification(self, _characteristic, data: bytearray) -> None:
        frame = bytes(data)
        if frame:
            self.notification_count += 1
            self.events.put(BridgeEvent(BridgeEventKind.INBOUND_FRAME, frame))

    def _disconnected(self, _client) -> None:
        self.connected = False
        self.ready = False
        self.closed = True
        self.events.put(BridgeEvent(BridgeEventKind.DISCONNECTED))

    async def _connect(self, device: dict, timeout: int) -> None:
        self._clear_events()
        self.closed = False
        self.disconnect_error = None
        self.client = self._client_type(
            device["_ble_device"],
            disconnected_callback=self._disconnected,
            services=[XE360_SERVICE_UUID],
            timeout=timeout,
        )
        try:
            await self.client.connect()
            self.connected = bool(self.client.is_connected)
            if not self.connected:
                raise RuntimeError("BLE connection did not become active")
            characteristic = self.client.services.get_characteristic(
                XE360_CHARACTERISTIC_UUID
            )
            if characteristic is None:
                raise RuntimeError("selected device does not expose the XE360 characteristic")
            properties = {str(value).lower() for value in characteristic.properties}
            if "notify" not in properties or "write-without-response" not in properties:
                raise RuntimeError(
                    "XE360 characteristic lacks notify or write-without-response"
                )
            self.characteristic = characteristic

            # BlueZ updates this value after MTU negotiation. Give it a short
            # window instead of permanently accepting its initial 20-byte default.
            deadline = time.monotonic() + 10
            maximum = int(characteristic.max_write_without_response_size)
            while maximum <= 20 and time.monotonic() < deadline:
                await asyncio.sleep(0.25)
                maximum = int(characteristic.max_write_without_response_size)
            if maximum <= 20:
                raise RuntimeError(
                    "negotiated BLE write size is too small; Linux requires BlueZ 5.62 or newer"
                )
            self.maximum_write_value_length = maximum
            await self.client.start_notify(characteristic, self._notification)
            self.ready = True
            self.events.put(BridgeEvent(BridgeEventKind.DESCRIPTOR_ENABLED))
        except BaseException:
            if self.client is not None and self.client.is_connected:
                await self.client.disconnect()
            raise

    def connect(self, device: dict, timeout: int = 35) -> None:
        try:
            self._submit(self._connect(device, timeout), timeout + 15)
        except Exception as exc:
            raise RuntimeError(f"XE360 GATT connection failed: {exc}") from exc

    async def _write(self, frame: bytes) -> None:
        if self.client is None or self.characteristic is None:
            raise RuntimeError("Bleak transport is not connected")
        await self.client.write_gatt_char(self.characteristic, frame, response=False)

    def write(self, frame: bytes) -> None:
        self._submit(self._write(frame), 10)
        self.write_count += 1
        self.events.put(BridgeEvent(BridgeEventKind.WRITER_READY))

    async def _disconnect(self) -> None:
        if self.client is not None and self.client.is_connected:
            await self.client.disconnect()
        self.connected = False
        self.ready = False
        self.closed = True

    def disconnect(self) -> None:
        if self.closed:
            return
        try:
            self._submit(self._disconnect(), 10)
        except Exception as exc:
            self.disconnect_error = str(exc)

    def shutdown(self) -> None:
        """Stop the private event loop after disconnecting (primarily for tests)."""

        self.disconnect()
        if self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)

    def next_event(self, timeout: int = 40) -> BridgeEvent:
        try:
            return self.events.get(timeout=timeout)
        except queue.Empty as exc:
            raise RuntimeError("timed out waiting for the XE360 reader") from exc


class BleakTransport:
    adapter_mode = AdapterMode.LIVE
    notification_bytes_emitted = True

    def __init__(self, controller: BleakController, device: dict) -> None:
        self.controller = controller
        self.adapter_identity = f"{sys.platform}-bleak"
        self.bench_reader_serial = device["uid"]
        self.observed_platinum_version = PlatinumVersion[
            f"V{device.get('platinum_version') or 3}"
        ]
        controller.connect(device)
        self.maximum_write_value_length = controller.maximum_write_value_length

    @property
    def can_write_without_response(self) -> bool:
        return bool(
            self.controller.ready
            and self.controller.connected
            and not self.controller.closed
        )

    def write_frame(self, frame: bytes, *, purpose: str) -> bool:
        del purpose
        if not self.can_write_without_response:
            raise SessionError("Bleak write attempted while transport is not ready")
        if not frame or len(frame) > self.maximum_write_value_length:
            raise SessionError("invalid Bleak frame length")
        self.controller.write(frame)
        return True

    def next_event(self) -> BridgeEvent:
        return self.controller.next_event()

    def close(self) -> None:
        self.controller.disconnect()


_BLEAK_CONTROLLER: BleakController | None = None


def _platform_controller():
    global _BLEAK_CONTROLLER
    if sys.platform == "darwin":
        return CoreBluetoothController()
    if sys.platform == "win32" or sys.platform.startswith("linux"):
        if _BLEAK_CONTROLLER is None:
            _BLEAK_CONTROLLER = BleakController()
        return _BLEAK_CONTROLLER
    raise RuntimeError(f"unsupported Bluetooth platform: {sys.platform}")


def discover_all_devices(seconds: int) -> list[dict]:
    status("◌", "Bluetooth scan", f"searching nearby devices for {seconds}s…", CYAN)
    return _platform_controller().discover(seconds)


def print_devices(devices: list[dict], numbered: bool = False,
                  label: str = "unique BLE advertisers") -> None:
    title = "Nearby XE360 locks" if label == "XE360 locks" else "Nearby BLE devices"
    print(f"  {paint('⌁', CYAN)}  {paint(title, BOLD)}")
    print(paint(f"     {len(devices)} found · strongest observed signal in dBm", DIM))
    print()
    number_width = len(str(len(devices))) if devices else 1
    prefix = f"{'#':>{number_width}}  " if numbered else ""
    header = f"{prefix}{'RSSI':>4}  {'NAME':<27}  {'TYPE':<12}  IDENTIFIER"
    print("  " + paint(header, BOLD, DIM))
    for index, device in enumerate(devices, start=1):
        rssi = str(device["rssi"]) if device["rssi"] is not None else "n/a"
        name = device["name"][:27]
        kind = "XE360 LOCK" if device["uid"] and device.get("platinum_version") else "BLE"
        identity = device["uuid"]
        if device["uid"]:
            identity = f"UID {device['uid']}  ({identity})"
        signal_color = GREEN if device["rssi"] is not None and device["rssi"] >= -70 else (
            YELLOW if device["rssi"] is not None and device["rssi"] >= -85 else RED
        )
        row = paint(f"{index:>{number_width}}", BOLD, CYAN) + "  " if numbered else ""
        row += f"{paint(f'{rssi:>4}', signal_color)}  {paint(f'{name:<27}', BOLD)}  "
        row += f"{paint(f'{kind:<12}', CYAN if kind == 'XE360 LOCK' else DIM)}  {paint(identity, DIM)}"
        print("  " + row)


def scan_all_devices(seconds: int) -> int:
    try:
        devices = discover_all_devices(seconds)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print_devices(devices)
    status("✓", "Discovery", "complete · no devices were connected to", GREEN)
    return 0


def xe360_locks(devices: list[dict]) -> list[dict]:
    by_uid: dict[str, dict] = {}
    for device in devices:
        uid = device.get("uid")
        if not uid or device.get("platinum_version") not in (1, 2, 3):
            continue
        current = by_uid.get(uid)
        current_rssi = current.get("rssi") if current else None
        candidate_rssi = device.get("rssi")
        if current is None or (
            candidate_rssi is not None
            and (current_rssi is None or candidate_rssi > current_rssi)
        ):
            by_uid[uid] = device
    return sorted(
        by_uid.values(),
        key=lambda item: item["rssi"] if item["rssi"] is not None else -1000,
        reverse=True,
    )


def login_and_scan(region: str = "US", scan_seconds: int = 12,
                   username: str | None = None, password: str | None = None) -> int:
    username = username or ask("Username")
    password = password or ask("Password", secret=True)
    with ThreadPoolExecutor(max_workers=1) as executor:
        login = executor.submit(firebase_login, username, password, region)
        result = scan_all_devices(scan_seconds)
        login.result()
        return result


def unlock_reader(bundle_dir: Path, reader: dict, platinum_version: int = 3) -> int:
    uid = reader["uid"]
    bundle, pin_store, _ = load_provisioned_credential_bundle(bundle_dir, allows_live=True)
    evidence_root = BASE_DIR / f"unlock-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    evidence_root.mkdir(mode=0o700)
    audit_path = evidence_root / "session-audit.jsonl"
    session = None
    transport = None
    outcome = "error"
    error_name = None
    started = time.monotonic()
    try:
        controller = reader.get("_controller")
        if isinstance(controller, CoreBluetoothController):
            transport = PyObjCCoreBluetoothTransport(controller, reader)
        elif isinstance(controller, BleakController):
            transport = BleakTransport(controller, reader)
        else:
            raise RuntimeError("selected BLE device is no longer available")
        status("⚡", "Secure session", "connected · negotiating encrypted channel…", CYAN)
        session = PlatinumSessionOrchestrator(
            transport,
            SessionConfiguration(
                PlatinumVersion[f"V{platinum_version}"],
                uid,
                BenchAuthorization(BenchAuthorization.expected_token(uid)),
            ),
            bundle,
            pin_store=pin_store,
        )
        for _ in range(200):
            if session.state in (SessionState.FINISHED, SessionState.FAILED):
                break
            event = transport.next_event()
            if event.kind is BridgeEventKind.INBOUND_FRAME:
                assert event.frame is not None
                if parse_transport_packet(event.frame).message_type == 2:
                    session.abort("peer-transport-error-no-retry")
                    break
            session.process_bridge_event(event)
        else:
            session.abort("event-limit")
        outcome = {
            SessionState.FINISHED: "finished",
            SessionState.FAILED: "failed",
        }.get(session.state, "failed")
    except KeyboardInterrupt:
        outcome, error_name = "error", "KeyboardInterrupt"
        if session is not None:
            session.abort("interrupted")
        raise
    except Exception as exc:  # noqa: BLE001
        outcome = "error"
        error_name = f"{type(exc).__name__}: {exc}"
        if session is not None:
            session.abort("exception")
    finally:
        if session is not None:
            session.abort("cleanup")
        elif transport is not None:
            transport.close()
        if session is not None:
            audit_path.write_text(session.audit.json_lines(), encoding="utf-8")
            os.chmod(audit_path, 0o600)
    reply = session.last_reply.value if session and session.last_reply else None
    elapsed = time.monotonic() - started
    if outcome == "finished" and reply == "credAccepted":
        print()
        status("🔓", "Gate unlocked", f"credential accepted in {elapsed:.2f}s", GREEN)
    else:
        detail = getattr(transport.controller, "disconnect_error", None) if transport else None
        print()
        status("✗", "Unlock failed", reply or error_name or detail or outcome, RED, stream=sys.stderr)
    status("▣", "Audit trail", audit_path, DIM)
    if outcome == "finished" and session and session.last_reply:
        return 0 if session.last_reply.value == "credAccepted" else 3
    return 1


def run_unlock(region: str = "US", scan_seconds: int = 12, username: str | None = None,
               password: str | None = None) -> int:
    banner()
    BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BASE_DIR, 0o700)

    cache_dir = BASE_DIR / "bundle"
    bundle_dir = None
    if cache_dir.exists():
        try:
            load_provisioned_credential_bundle(cache_dir, allows_live=True)
            bundle_dir = cache_dir
            status("🔐", "Credential", f"validated cache · {cache_dir}", GREEN)
        except Exception as exc:
            print(f"cached credentials failed: {exc}", file=sys.stderr)
            remove_cached_bundle(cache_dir)

    def fetch_bundle() -> Path:
        token = firebase_login(username, password, region)
        refreshed = BASE_DIR / "bundle-refresh"
        remove_cached_bundle(refreshed)
        fetch_credentials(token, region, refreshed)
        try:
            return replace_cached_bundle(refreshed, cache_dir)
        finally:
            remove_cached_bundle(refreshed)

    if bundle_dir is None:
        username = username or ask("Username")
        password = password or ask("Password", secret=True)
        # CoreBluetooth needs the main thread on macOS; Bleak owns a persistent
        # event-loop thread on Linux and Windows. Cloud provisioning is independent.
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                credential_future = executor.submit(fetch_bundle)
                devices = discover_all_devices(scan_seconds)
                bundle_dir = credential_future.result()
        except CredentialLoginError as exc:
            print(f"credentials failed: {exc}", file=sys.stderr)
            while True:
                username = ask("Username")
                password = ask("Password", secret=True)
                try:
                    bundle_dir = fetch_bundle()
                    break
                except CredentialLoginError as retry_exc:
                    print(f"credentials failed: {retry_exc}; try again", file=sys.stderr)
                except prov.ProvisioningError as retry_exc:
                    print(f"first-time credential setup failed: {retry_exc}", file=sys.stderr)
                    return 1
        except prov.ProvisioningError as exc:
            print(f"first-time credential setup failed: {exc}", file=sys.stderr)
            return 1
    else:
        devices = discover_all_devices(scan_seconds)

    while True:
        while True:
            locks = xe360_locks(devices)
            print()
            print_devices(locks, numbered=True, label="XE360 locks")
            if not locks:
                choice = input(prompt("\n  No XE360 locks found. Re-scan or quit? [r/q]: ")).strip().lower()
                if choice == "q":
                    return 1
                if choice != "r":
                    print("Enter r to re-scan or q to quit.")
                    continue
            else:
                choice = input(prompt("\n  Unlock which device number? [r to re-scan]: ")).strip().lower()
                if choice != "r":
                    try:
                        index = int(choice)
                        if not 1 <= index <= len(locks):
                            raise IndexError
                        selected = locks[index - 1]
                        break
                    except (ValueError, IndexError):
                        print("Select a numbered XE360 lock or enter r to re-scan.")
                        continue
            print()
            devices = discover_all_devices(scan_seconds)

        print()
        status("→", "Selected lock", f"{selected['name']} · {selected['uid']}", CYAN)
        print()
        result = unlock_reader(bundle_dir, selected)
        if result != 3:
            return result

        status("!", "Access denied", "credential does not grant access to this reader", YELLOW, stream=sys.stderr)
        while True:
            choice = input(prompt("  Try another lock, refresh credentials, or quit? [a/f/q]: ")).strip().lower() or "a"
            if choice == "q":
                return result
            if choice == "a":
                print()
                devices = discover_all_devices(scan_seconds)
                break
            if choice != "f":
                print("Enter a to try another lock, f to refresh, or q to quit.")
                continue
            username = ask("Username")
            password = ask("Password", secret=True)
            try:
                bundle_dir = fetch_bundle()
                print("credential refreshed; choose a lock to retry")
                print()
                devices = discover_all_devices(scan_seconds)
                break
            except CredentialLoginError as exc:
                print(f"credentials failed: {exc}; try again", file=sys.stderr)
            except prov.ProvisioningError as exc:
                print(f"credential refresh failed: {exc}", file=sys.stderr)
                return result


if __name__ == "__main__":
    try:
        seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    except ValueError:
        seconds = 12
    sys.exit(run_unlock(scan_seconds=max(3, min(seconds, 60))))
