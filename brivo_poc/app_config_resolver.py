"""Resolve approved local Brivo app configuration into a private snapshot."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .private_files import posix_permissions_are_private, restrict_open_descriptor

APP_CONFIG_FORMAT = "xe360-mac-app-config-v1"
APP_CONFIG_SNAPSHOT_FORMAT = "xe360-mac-resolved-app-config-v1"
_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
_NATIVE_ALLEGION_LIBRARY = "liballegion-secure-keys.so"
# This is the arm64 library packaged by the verified 4.32.0 APK.  A changed
# library is deliberately not treated as the same configuration source.
_NATIVE_ALLEGION_SHA256 = "f6619a00b14dff050e554e0156543b589a0b69f3d341722ac035cade6f0bbe52"
_ACCESSHUB_BASE_URL = "https://api.allegion.com/mobileaccess/"
_API_MANAGEMENT_BASE_URL = "https://api.allegion.com/"
_ORIGIN_KEY_PATH = "/origin/publickeys/"
_NATIVE_XOR_KEY = 0x5A
_NATIVE_VALUE_LAYOUT = {
    # JNI registration maps these routines to getAllegionPin,
    # getSubscriptionKey, and getIntegrationId respectively.
    "pin": (0x15B54, 51),
    "subscription_key": (0x15B87, 32),
    "integration_id": (0x15BA7, 36),
}
_REGION_RESOURCES = {
    "us": "us_google_services.json",
    "eu": "eu_google_services.json",
}
_REGION_ENDPOINTS = {
    "us": {
        "pass_host": "us-central1-pass-prod.cloudfunctions.net",
        "brivo_auth_host": "auth.brivo.com",
        "rtdb_host": "pass-prod.firebaseio.com",
    },
    "eu": {
        "pass_host": "europe-west1-pass-prod.cloudfunctions.net",
        "brivo_auth_host": "auth.eu.brivo.com",
        "rtdb_host": "pass-prod-eu-default-rtdb.europe-west1.firebasedatabase.app",
    },
}
_OVERRIDE_KEYS = {
    "format",
    "allegion_subscription_key",
    "integration_id",
    "accesshub_host",
    "origin_key_0_file",
    "origin_key_1_file",
    "brivo_pass_host",
    "brivo_auth_host",
}


class AppConfigResolutionError(RuntimeError):
    """The approved local app configuration is absent or malformed."""


@dataclass(frozen=True)
class OriginKeyBootstrapRequest:
    """The fixed first-fetch route; callers must enforce the resolved TLS pin."""

    host: str = "api.allegion.com"
    path: str = _ORIGIN_KEY_PATH


def origin_key_bootstrap_request() -> OriginKeyBootstrapRequest:
    """Return the source-proven origin-key route without performing network I/O."""

    return OriginKeyBootstrapRequest()


def _owner_only_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise AppConfigResolutionError("approved app configuration file is missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AppConfigResolutionError("approved app configuration must be a regular file")
    if not posix_permissions_are_private(metadata):
        raise AppConfigResolutionError("approved app configuration must be owner-only")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AppConfigResolutionError("approved app configuration is unreadable") from exc


def _owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise AppConfigResolutionError("private configuration directory is missing") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise AppConfigResolutionError("private configuration root must be a directory")
    if not posix_permissions_are_private(metadata):
        raise AppConfigResolutionError("private configuration root must be owner-only")


def _atomic_owner_only_json(path: Path, document: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        _owner_only_regular_file(path)
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        restrict_open_descriptor(descriptor, _FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, _FILE_MODE)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _atomic_owner_only_bytes(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        _owner_only_regular_file(path)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        restrict_open_descriptor(descriptor, _FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, _FILE_MODE)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _canonical_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AppConfigResolutionError(f"{field} must be a canonical UUID")
    try:
        normalized = str(uuid.UUID(value))
    except ValueError as exc:
        raise AppConfigResolutionError(f"{field} must be a canonical UUID") from exc
    if value != normalized:
        raise AppConfigResolutionError(f"{field} must be lowercase canonical UUID")
    return normalized


def _read_google_services(path: Path, region: str) -> tuple[str, str, str]:
    """Extract only the Firebase values used by the app's own options builder."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        project = document["project_info"]
        firebase_url = project["firebase_url"]
        client = document["client"][0]
        package_name = client["client_info"]["android_client_info"]["package_name"]
        api_key = client["api_key"][0]["current_key"]
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise AppConfigResolutionError("approved Google-services resource has an unexpected schema") from exc
    parsed = urlsplit(firebase_url if isinstance(firebase_url, str) else "")
    expected_host = _REGION_ENDPOINTS[region]["rtdb_host"]
    if (
        package_name != "com.brivo.pass"
        or parsed.scheme != "https"
        or parsed.path not in ("", "/")
        or parsed.hostname != expected_host
        or not isinstance(api_key, str)
        or not api_key
    ):
        raise AppConfigResolutionError("approved Google-services resource failed validation")
    return api_key, parsed.hostname, str(project.get("project_id", ""))


def _read_override(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        document = json.loads(_owner_only_regular_file(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppConfigResolutionError("approved app configuration must be owner-only JSON") from exc
    if not isinstance(document, dict) or set(document) - _OVERRIDE_KEYS or document.get("format") != APP_CONFIG_FORMAT:
        raise AppConfigResolutionError("approved app configuration has an unexpected schema")
    for key in ("allegion_subscription_key", "accesshub_host", "brivo_pass_host", "brivo_auth_host"):
        if key in document and (not isinstance(document[key], str) or not document[key]):
            raise AppConfigResolutionError(f"approved app configuration has invalid {key}")
    if "integration_id" in document:
        document["integration_id"] = _canonical_uuid(document["integration_id"], "integration_id")
    paths = ("origin_key_0_file", "origin_key_1_file")
    if any(key in document for key in paths) and not all(isinstance(document.get(key), str) and document[key] for key in paths):
        raise AppConfigResolutionError("both origin key paths must be supplied together")
    return document


def _decode_native_xor_value(raw: bytes, offset: int, length: int, field: str) -> str:
    encoded = raw[offset : offset + length]
    if len(encoded) != length:
        raise AppConfigResolutionError("approved Allegion native configuration is truncated")
    try:
        value = bytes(byte ^ _NATIVE_XOR_KEY for byte in encoded).decode("ascii")
    except UnicodeDecodeError as exc:
        raise AppConfigResolutionError(f"approved Allegion native configuration has invalid {field}") from exc
    if not value:
        raise AppConfigResolutionError(f"approved Allegion native configuration has empty {field}")
    return value


def _read_native_allegion_configuration(path: Path) -> tuple[str, str, str, str]:
    """Extract the APK's JNI-returned production settings without logging them."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AppConfigResolutionError("approved Allegion native configuration is missing") from exc
    if hashlib.sha256(raw).hexdigest() != _NATIVE_ALLEGION_SHA256:
        raise AppConfigResolutionError("approved Allegion native configuration digest is unexpected")
    # getAllegionBaseURL builds this host one character at a time in JNI.
    host = "api.allegion.com"
    pin = _decode_native_xor_value(raw, *_NATIVE_VALUE_LAYOUT["pin"], "certificate pin")
    integration_id = _decode_native_xor_value(raw, *_NATIVE_VALUE_LAYOUT["integration_id"], "integration ID")
    subscription_key = _decode_native_xor_value(raw, *_NATIVE_VALUE_LAYOUT["subscription_key"], "subscription key")
    if not pin.startswith("sha256/") or len(pin) != 51:
        raise AppConfigResolutionError("approved Allegion native certificate pin is invalid")
    try:
        integration_id = str(uuid.UUID(integration_id))
    except ValueError as exc:
        raise AppConfigResolutionError("approved Allegion native integration ID is invalid") from exc
    if len(subscription_key) != 32 or any(character not in "0123456789abcdef" for character in subscription_key):
        raise AppConfigResolutionError("approved Allegion native subscription key is invalid")
    return host, pin, integration_id, subscription_key


def cache_origin_keys_from_bootstrap_response(response_body: bytes, private_root: Path) -> tuple[Path, Path]:
    """Cache a TLS-pin-authenticated origin-key response in the private root.

    This deliberately performs no HTTP.  The caller must fetch only
    ``origin_key_bootstrap_request()`` with the certificate pin from the
    resolved snapshot before passing its exact response body here.
    """

    if not isinstance(response_body, bytes):
        raise TypeError("origin-key bootstrap response must be bytes")
    try:
        document = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppConfigResolutionError("origin-key bootstrap response is not JSON") from exc
    if not isinstance(document, dict) or set(document) != {"publicKey0", "publicKey1"}:
        raise AppConfigResolutionError("origin-key bootstrap response has an unexpected schema")
    values: list[str] = []
    for field in ("publicKey0", "publicKey1"):
        value = document[field]
        if not isinstance(value, str) or len(value) != 130 or not value.startswith("04"):
            raise AppConfigResolutionError("origin-key bootstrap response has an invalid public key")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise AppConfigResolutionError("origin-key bootstrap response has non-hex public key") from exc
        try:
            from cryptography.hazmat.primitives.asymmetric import ec

            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
        except (ImportError, ValueError) as exc:
            raise AppConfigResolutionError("origin-key bootstrap response has an invalid P-256 public key") from exc
        values.append(raw.hex())
    root = Path(private_root)
    _owner_only_directory(root)
    paths = (root / "origin-key-0.hex", root / "origin-key-1.hex")
    for path, value in zip(paths, values, strict=True):
        _atomic_owner_only_bytes(path, value.encode("ascii") + b"\n")
    return paths


@dataclass(frozen=True)
class ResolvedAppConfig:
    region: str
    firebase_web_api_key: str
    firebase_host: str
    refresh_host: str
    rtdb_host: str
    brivo_pass_host: str
    brivo_auth_host: str
    accesshub_host: str
    accesshub_base_url: str
    api_management_base_url: str
    accesshub_certificate_pin: str
    allegion_subscription_key: str
    integration_id: str
    origin_key_0_file: Path | None
    origin_key_1_file: Path | None
    source_digest: str

    def missing_live_sources(self) -> tuple[str, ...]:
        missing: list[str] = []
        if self.origin_key_0_file is None or self.origin_key_1_file is None:
            missing.append("AccessHub origin trust keys: fetch/cache the TLS-pin-authenticated bootstrap response")
        return tuple(missing)

    def private_snapshot(self) -> dict[str, Any]:
        return {
            "format": APP_CONFIG_SNAPSHOT_FORMAT,
            "region": self.region,
            "firebase_web_api_key": self.firebase_web_api_key,
            "firebase_host": self.firebase_host,
            "refresh_host": self.refresh_host,
            "rtdb_host": self.rtdb_host,
            "brivo_pass_host": self.brivo_pass_host,
            "brivo_auth_host": self.brivo_auth_host,
            "accesshub_host": self.accesshub_host,
            "accesshub_base_url": self.accesshub_base_url,
            "api_management_base_url": self.api_management_base_url,
            "accesshub_certificate_pin": self.accesshub_certificate_pin,
            "allegion_subscription_key": self.allegion_subscription_key,
            "integration_id": self.integration_id,
            "origin_key_0_file": str(self.origin_key_0_file) if self.origin_key_0_file else None,
            "origin_key_1_file": str(self.origin_key_1_file) if self.origin_key_1_file else None,
            "source_digest": self.source_digest,
        }

    def safe_summary(self) -> dict[str, Any]:
        return {
            "region": self.region,
            "firebase_project_configured": True,
            "accesshub_configured": True,
            "subscription_configured": True,
            "integration_configured": True,
            "origin_trust_keys_configured": self.origin_key_0_file is not None and self.origin_key_1_file is not None,
            "source_digest": self.source_digest,
        }


class AppConfigResolver:
    """Materialize approved local app settings in a private run directory."""

    def __init__(self, resources_root: Path, private_root: Path, override_file: Path | None = None, native_library: Path | None = None):
        self.resources_root = Path(resources_root)
        self.private_root = Path(private_root)
        self.override_file = Path(override_file) if override_file is not None else None
        self.native_library = Path(native_library) if native_library is not None else default_allegion_native_library()

    def resolve(self, region: str = "auto") -> ResolvedAppConfig:
        if region not in {"auto", "us", "eu"}:
            raise AppConfigResolutionError("region must be auto, us, or eu")
        # AppUtils.getNeededGoogleServices() statically selects the US resource.
        selected_region = "us" if region == "auto" else region
        resource = self.resources_root / _REGION_RESOURCES[selected_region]
        api_key, rtdb_host, project_id = _read_google_services(resource, selected_region)
        override = _read_override(self.override_file)
        endpoints = _REGION_ENDPOINTS[selected_region]
        if override.get("brivo_pass_host", endpoints["pass_host"]) != endpoints["pass_host"]:
            raise AppConfigResolutionError("approved app configuration has an unexpected Brivo pass host")
        if override.get("brivo_auth_host", endpoints["brivo_auth_host"]) != endpoints["brivo_auth_host"]:
            raise AppConfigResolutionError("approved app configuration has an unexpected Brivo auth host")
        native_host, certificate_pin, integration_id, subscription_key = _read_native_allegion_configuration(self.native_library)
        if "accesshub_host" in override and override["accesshub_host"] != native_host:
            raise AppConfigResolutionError("approved app configuration conflicts with the native AccessHub host")
        if "allegion_subscription_key" in override and override["allegion_subscription_key"] != subscription_key:
            raise AppConfigResolutionError("approved app configuration conflicts with the native subscription key")
        if "integration_id" in override and override["integration_id"] != integration_id:
            raise AppConfigResolutionError("approved app configuration conflicts with the native integration ID")
        key_0 = Path(override["origin_key_0_file"]) if "origin_key_0_file" in override else self.private_root / "origin-key-0.hex"
        key_1 = Path(override["origin_key_1_file"]) if "origin_key_1_file" in override else self.private_root / "origin-key-1.hex"
        if not key_0.exists() and not key_1.exists():
            key_0 = key_1 = None
        elif not key_0.exists() or not key_1.exists():
            raise AppConfigResolutionError("both cached origin trust keys are required")
        if key_0 is not None:
            _owner_only_regular_file(key_0)
            _owner_only_regular_file(key_1)
        source_digest = hashlib.sha256(
            (selected_region + "\x00" + project_id + "\x00" + resource.name + "\x00" + _NATIVE_ALLEGION_SHA256).encode("utf-8")
        ).hexdigest()
        config = ResolvedAppConfig(
            region=selected_region,
            firebase_web_api_key=api_key,
            firebase_host="www.googleapis.com",
            refresh_host="securetoken.googleapis.com",
            rtdb_host=rtdb_host,
            brivo_pass_host=endpoints["pass_host"],
            brivo_auth_host=endpoints["brivo_auth_host"],
            accesshub_host=native_host,
            accesshub_base_url=_ACCESSHUB_BASE_URL,
            api_management_base_url=_API_MANAGEMENT_BASE_URL,
            accesshub_certificate_pin=certificate_pin,
            allegion_subscription_key=subscription_key,
            integration_id=integration_id,
            origin_key_0_file=key_0,
            origin_key_1_file=key_1,
            source_digest=source_digest,
        )
        _owner_only_directory(self.private_root)
        _atomic_owner_only_json(self.private_root / "resolved-app-config.json", config.private_snapshot())
        return config


def default_resources_root() -> Path:
    packaged = Path(__file__).resolve().parent.parent / "assets"
    if (packaged / _REGION_RESOURCES["us"]).is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "decompiled" / "jadx" / "resources" / "res" / "raw"


def default_allegion_native_library() -> Path:
    packaged = Path(__file__).resolve().parent.parent / "assets" / _NATIVE_ALLEGION_LIBRARY
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "decompiled" / "apktool" / "lib" / "arm64-v8a" / _NATIVE_ALLEGION_LIBRARY
