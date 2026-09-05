from __future__ import annotations

import sys
import types
import unittest
from typing import ClassVar
from unittest import mock

from brivo_poc.session_orchestrator import BridgeEventKind
from unlock import BleakController, BleakTransport


class _FakeDevice:
    address = "AA:BB:CC:DD:EE:FF"
    name = "XE360"


class _FakeAdvertisement:
    local_name = "Front Door"
    rssi = -51
    manufacturer_data: ClassVar[dict[int, bytes]] = {
        0x013B: bytes.fromhex("02002203030003")
    }
    service_data: ClassVar[dict[str, bytes]] = {
        "0000180a-0000-1000-8000-00805f9b34fb": bytes.fromhex("0102030405060708")
    }


class _FakeScanner:
    def __init__(self, callback):
        self.callback = callback

    async def __aenter__(self):
        self.callback(_FakeDevice(), _FakeAdvertisement())
        return self

    async def __aexit__(self, *_args):
        return None


class _FakeCharacteristic:
    properties: ClassVar[list[str]] = ["notify", "write-without-response"]
    max_write_without_response_size = 244


class _FakeServices:
    characteristic = _FakeCharacteristic()

    def get_characteristic(self, uuid):
        return self.characteristic if uuid.lower().endswith("6401") else None


class _FakeClient:
    instances: ClassVar[list["_FakeClient"]] = []

    def __init__(self, device, disconnected_callback, services, timeout):
        self.device = device
        self.disconnected_callback = disconnected_callback
        self.requested_services = services
        self.timeout = timeout
        self.services = _FakeServices()
        self.is_connected = False
        self.notification_callback = None
        self.writes = []
        type(self).instances.append(self)

    async def connect(self):
        self.is_connected = True

    async def start_notify(self, characteristic, callback):
        self.notification_callback = callback

    async def write_gatt_char(self, characteristic, frame, response):
        self.writes.append((characteristic, bytes(frame), response))

    async def disconnect(self):
        was_connected = self.is_connected
        self.is_connected = False
        if was_connected:
            self.disconnected_callback(self)


class BleakTransportTests(unittest.TestCase):
    def setUp(self):
        fake_bleak = types.ModuleType("bleak")
        fake_bleak.BleakClient = _FakeClient
        fake_bleak.BleakScanner = _FakeScanner
        self.module_patch = mock.patch.dict(sys.modules, {"bleak": fake_bleak})
        self.module_patch.start()
        _FakeClient.instances.clear()
        self.controller = BleakController()

    def tearDown(self):
        self.controller.shutdown()
        self.module_patch.stop()

    def test_discovery_decodes_xe360_advertisement(self):
        devices = self.controller.discover(0)

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["name"], "Front Door")
        self.assertEqual(devices[0]["rssi"], -51)
        self.assertEqual(devices[0]["uid"], "0102030405060708")
        self.assertEqual(devices[0]["platinum_version"], 3)

    def test_transport_connects_notifies_and_writes_without_response(self):
        device = self.controller.discover(0)[0]
        transport = BleakTransport(self.controller, device)

        self.assertEqual(
            transport.next_event().kind,
            BridgeEventKind.DESCRIPTOR_ENABLED,
        )
        self.assertEqual(transport.maximum_write_value_length, 244)
        self.assertTrue(transport.can_write_without_response)
        self.assertTrue(transport.write_frame(b"frame", purpose="test"))

        client = _FakeClient.instances[-1]
        self.assertEqual(client.writes[-1][1:], (b"frame", False))
        self.assertEqual(transport.next_event().kind, BridgeEventKind.WRITER_READY)
        client.notification_callback(client.services.characteristic, bytearray(b"reply"))
        event = transport.next_event()
        self.assertEqual(event.kind, BridgeEventKind.INBOUND_FRAME)
        self.assertEqual(event.frame, b"reply")

        transport.close()
        self.assertFalse(transport.can_write_without_response)


if __name__ == "__main__":
    unittest.main()
