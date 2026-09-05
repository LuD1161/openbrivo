"""Offline model of the Allegion Platinum BLE messages used by the XE360.

This module intentionally has no Bluetooth transport.  It reproduces the
message-layer CBOR, transport segmentation, and CRC behavior recovered from
the Brivo APK, and it can exercise the cryptography with synthetic keys and a
synthetic credential blob.  It does not retrieve credentials, access device
keystores, connect to a lock, or write a GATT characteristic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Any


ALLEGION_SERVICE_UUID = "1e345cbb-1103-43f4-8d53-d19cae536400"
ALLEGION_CHARACTERISTIC_UUID = "1e345cbb-1103-43f4-8d53-d19cae536401"
ALLEGION_CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"

DEFAULT_ANDROID_MTU = 247
CBOR_TRANSPORT_OVERHEAD_BUDGET = 20


class ProtocolError(ValueError):
    """Raised when an offline packet does not match the recovered protocol."""


class PlatinumVersion(str, Enum):
    """Protocol selection recovered from the Sapphire security-version field."""

    V1 = "PLATINUM_V1"
    V2 = "PLATINUM_V2"
    V3 = "PLATINUM_V3"


class ReplyResult(str, Enum):
    """Exact lock reply strings accepted by ``AlReplyCred.getResult``."""

    DATA_SUCCESS = "dataSuccess"
    DATA_FAILURE = "dataFailure"
    SUCCESS = "credAccepted"
    FAIL = "credDenied"
    UNKNOWN = "credStatusUnknown"


def reply_requires_session_end(result: ReplyResult) -> bool:
    """Mirror the mediator: data callbacks are nonterminal; cred results end."""

    result = ReplyResult(result)
    return result not in (ReplyResult.DATA_SUCCESS, ReplyResult.DATA_FAILURE)


@dataclass(frozen=True)
class ReaderChallenge:
    """Decrypted and, for V2/V3, authenticated reader challenge."""

    session_nonce: bytes
    device_auth_key: bytes | None
    max_size: int | None
    encrypted_payload: bytes
    device_auth_signature: bytes | None
    pin_was_added: bool


class DevicePinStore:
    """In-memory model of ``AlDeviceStorage``'s serial/device-key TOFU list.

    This is deliberately ephemeral and offline.  The Android implementation
    persists lowercase-hex public keys, rejects first use of one key by a second
    serial, and evicts the oldest entry before adding a 21st pin.
    """

    def __init__(self, entries: Sequence[tuple[str, bytes]] = ()) -> None:
        self._entries = [(serial, bytes(key)) for serial, key in entries]

    @property
    def entries(self) -> tuple[tuple[str, bytes], ...]:
        return tuple(self._entries)

    def validate_or_pin(self, serial_number: str, device_auth_key: bytes) -> bool:
        for stored_serial, stored_key in self._entries:
            if stored_serial == serial_number:
                return stored_key == device_auth_key
        if any(stored_key == device_auth_key for _, stored_key in self._entries):
            return False
        if len(self._entries) >= 20:
            self._entries.pop(0)
        self._entries.append((serial_number, bytes(device_auth_key)))
        return True


@dataclass(frozen=True)
class TransportPacket:
    """Decoded and CRC-validated transport packet."""

    message_type: int
    group_number: int
    packet_number: int | None
    last_packet_number: int | None
    total_cbor_length: int | None
    cbor_data: bytes | None
    crc: int
    raw: bytes


def _encode_head(major: int, value: int) -> bytes:
    if value < 0:
        raise ProtocolError("CBOR length/integer must be non-negative")
    prefix = major << 5
    if value < 24:
        return bytes((prefix | value,))
    if value <= 0xFF:
        return bytes((prefix | 24, value))
    if value <= 0xFFFF:
        return bytes((prefix | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes((prefix | 26,)) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes((prefix | 27,)) + value.to_bytes(8, "big")
    raise ProtocolError("CBOR integer is too large")


def encode_cbor(value: Any) -> bytes:
    """Encode the definite-length CBOR subset emitted by Jackson in this path.

    Python mapping insertion order is retained because the APK writes fields in
    a fixed order.  Canonical key sorting is deliberately not performed.
    """

    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        if value >= 0:
            return _encode_head(0, value)
        return _encode_head(1, -1 - value)
    if isinstance(value, bytes):
        return _encode_head(2, len(value)) + value
    if isinstance(value, bytearray):
        raw = bytes(value)
        return _encode_head(2, len(raw)) + raw
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _encode_head(3, len(raw)) + raw
    if isinstance(value, Mapping):
        encoded = [_encode_head(5, len(value))]
        for key, item in value.items():
            encoded.append(encode_cbor(key))
            encoded.append(encode_cbor(item))
        return b"".join(encoded)
    if isinstance(value, Sequence):
        encoded = [_encode_head(4, len(value))]
        encoded.extend(encode_cbor(item) for item in value)
        return b"".join(encoded)
    raise TypeError(f"unsupported CBOR type: {type(value).__name__}")


def _read_length(raw: bytes, offset: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, offset
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths.get(additional)
    if width is None:
        raise ProtocolError("indefinite/reserved CBOR lengths are unsupported")
    end = offset + width
    if end > len(raw):
        raise ProtocolError("truncated CBOR length")
    return int.from_bytes(raw[offset:end], "big"), end


def _decode_cbor_at(raw: bytes, offset: int) -> tuple[Any, int]:
    if offset >= len(raw):
        raise ProtocolError("truncated CBOR item")
    initial = raw[offset]
    offset += 1
    major = initial >> 5
    additional = initial & 0x1F

    if major in (0, 1):
        number, offset = _read_length(raw, offset, additional)
        return (number if major == 0 else -1 - number), offset
    if major in (2, 3):
        length, offset = _read_length(raw, offset, additional)
        end = offset + length
        if end > len(raw):
            raise ProtocolError("truncated CBOR string")
        data = raw[offset:end]
        if major == 2:
            return data, end
        try:
            return data.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise ProtocolError("invalid CBOR UTF-8") from exc
    if major == 4:
        length, offset = _read_length(raw, offset, additional)
        result = []
        for _ in range(length):
            item, offset = _decode_cbor_at(raw, offset)
            result.append(item)
        return result, offset
    if major == 5:
        length, offset = _read_length(raw, offset, additional)
        result: dict[Any, Any] = {}
        for _ in range(length):
            key, offset = _decode_cbor_at(raw, offset)
            item, offset = _decode_cbor_at(raw, offset)
            result[key] = item
        return result, offset
    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if additional in simple:
            return simple[additional], offset
    raise ProtocolError(f"unsupported CBOR major/additional value {major}/{additional}")


def decode_cbor(raw: bytes) -> Any:
    """Decode one complete item from the protocol's definite-length subset."""

    value, offset = _decode_cbor_at(raw, 0)
    if offset != len(raw):
        raise ProtocolError(f"trailing CBOR bytes at offset {offset}")
    return value


def crc16_xmodem(data: bytes) -> int:
    """APK CRC16 implementation: polynomial 0x1021, initial value 0x0000."""

    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _append_transport_crc(with_placeholder: bytes) -> bytes:
    # Jackson encodes integer 65535 as 19 FF FF.  The APK computes over the
    # array without those final three bytes and deliberately uses 18 XX even
    # when a one-byte CRC could have had a shorter direct CBOR representation.
    if not with_placeholder.endswith(b"\x19\xff\xff"):
        raise ProtocolError("transport CRC placeholder is not 65535")
    body = with_placeholder[:-3]
    crc = crc16_xmodem(body)
    if crc <= 0xFF:
        return body + b"\x18" + bytes((crc,))
    return body + b"\x19" + crc.to_bytes(2, "big")


def _transport_array(values: list[Any]) -> bytes:
    return _append_transport_crc(encode_cbor([*values, 65535]))


def build_flow_control(group_number: int) -> bytes:
    if group_number < 0:
        raise ProtocolError("group number cannot be negative")
    return _transport_array([3, group_number])


def build_transport_error(group_number: int, packet_number: int) -> bytes:
    if group_number < 0 or packet_number < 1:
        raise ProtocolError("invalid transport error group/packet number")
    return _transport_array([2, group_number, packet_number])


def build_transport_packets(
    cbor_data: bytes,
    group_number: int,
    *,
    mtu_size: int = DEFAULT_ANDROID_MTU,
) -> list[bytes]:
    """Segment one message exactly like ``AlCBORWrite``.

    ``mtu_size`` is the Android ATT MTU used by the recovered SDK.  The SDK
    reserves 20 bytes for its CBOR transport envelope and segments the message
    layer into chunks of ``mtu_size - 20``.
    """

    if group_number < 0:
        raise ProtocolError("group number cannot be negative")
    if mtu_size <= CBOR_TRANSPORT_OVERHEAD_BUDGET:
        raise ProtocolError("MTU must be greater than the 20-byte envelope budget")
    if not isinstance(cbor_data, bytes):
        raise TypeError("cbor_data must be bytes")

    block_size = mtu_size - CBOR_TRANSPORT_OVERHEAD_BUDGET
    chunks = [cbor_data[index : index + block_size] for index in range(0, len(cbor_data), block_size)]
    if not chunks:
        chunks = [b""]
    total_packets = len(chunks)
    first_chunk_length = 0 if total_packets == 1 else len(chunks[0])
    packets: list[bytes] = []

    for index, chunk in enumerate(chunks, start=1):
        if index < total_packets:
            packets.append(
                _transport_array([0, group_number, index, total_packets, chunk])
            )
        else:
            packets.append(
                _transport_array(
                    [1, group_number, index, total_packets, first_chunk_length, chunk]
                )
            )
    return packets


def _wire_crc_and_body(raw: bytes, decoded_crc: int) -> tuple[int, bytes]:
    # Both marker bytes can occur immediately before the actual CRC marker as
    # ordinary payload data.  Use the already-decoded final CBOR array item to
    # disambiguate instead of trusting a suffix byte in isolation.
    candidates: list[tuple[int, bytes]] = []
    if len(raw) >= 2 and raw[-2] == 0x18:
        candidates.append((raw[-1], raw[:-2]))
    if len(raw) >= 3 and raw[-3] == 0x19:
        candidates.append((int.from_bytes(raw[-2:], "big"), raw[:-3]))
    matching = [candidate for candidate in candidates if candidate[0] == decoded_crc]
    if len(matching) != 1:
        raise ProtocolError("transport CRC is not encoded as 18 XX or 19 XXXX")
    return matching[0]


def parse_transport_packet(raw: bytes) -> TransportPacket:
    """Decode a transport packet and reject a bad CRC or invalid shape."""

    decoded = decode_cbor(raw)
    if (
        not isinstance(decoded, list)
        or not decoded
        or not isinstance(decoded[-1], int)
        or decoded[-1] < 0
    ):
        raise ProtocolError("transport packet is not a CBOR array ending in a CRC")
    wire_crc, crc_body = _wire_crc_and_body(raw, decoded[-1])
    calculated = crc16_xmodem(crc_body)
    if wire_crc != calculated:
        raise ProtocolError(
            f"transport CRC mismatch: wire=0x{wire_crc:04x}, calculated=0x{calculated:04x}"
        )
    message_type = decoded[0]

    if message_type == 0 and len(decoded) == 6:
        _, group, packet, last, data, _ = decoded
        total_length = None
    elif message_type == 1 and len(decoded) == 7:
        _, group, packet, last, total_length, data, _ = decoded
    elif message_type == 2 and len(decoded) == 4:
        _, group, packet, _ = decoded
        last = None
        total_length = None
        data = None
    elif message_type == 3 and len(decoded) == 3:
        _, group, _ = decoded
        packet = None
        last = None
        total_length = None
        data = None
    else:
        raise ProtocolError("unknown or malformed transport packet")

    if not isinstance(group, int) or group < 0:
        raise ProtocolError("invalid transport group number")
    if packet is not None and (not isinstance(packet, int) or packet < 1):
        raise ProtocolError("invalid transport packet number")
    if data is not None and not isinstance(data, bytes):
        raise ProtocolError("transport CBOR data is not a byte string")

    return TransportPacket(
        message_type=message_type,
        group_number=group,
        packet_number=packet,
        last_packet_number=last,
        total_cbor_length=total_length,
        cbor_data=data,
        crc=wire_crc,
        raw=raw,
    )


def reassemble_transport_packets(raw_packets: Sequence[bytes]) -> bytes:
    """Validate and reassemble one group of intermediate/final packets."""

    if not raw_packets:
        raise ProtocolError("no transport packets supplied")
    packets = [parse_transport_packet(raw) for raw in raw_packets]
    if any(packet.message_type not in (0, 1) for packet in packets):
        raise ProtocolError("flow/error packets cannot be reassembled as message data")
    groups = {packet.group_number for packet in packets}
    if len(groups) != 1:
        raise ProtocolError("transport group numbers do not match")
    expected_last = len(packets)
    for expected_number, packet in enumerate(packets, start=1):
        if packet.packet_number != expected_number:
            raise ProtocolError("transport packet sequence is incomplete or unordered")
        if packet.last_packet_number != expected_last:
            raise ProtocolError("transport last-packet number is inconsistent")
        expected_type = 1 if expected_number == expected_last else 0
        if packet.message_type != expected_type:
            raise ProtocolError("transport final/intermediate type is inconsistent")
    message = b"".join(packet.cbor_data or b"" for packet in packets)
    final = packets[-1]
    if len(packets) == 1:
        if final.total_cbor_length != 0:
            raise ProtocolError("single-packet total length marker must be zero")
    else:
        first_length = len(packets[0].cbor_data or b"")
        if final.total_cbor_length != first_length:
            raise ProtocolError("multi-packet first-chunk length marker is inconsistent")
    return message


def build_session_start(uncompressed_public_key: bytes) -> bytes:
    if len(uncompressed_public_key) != 65 or uncompressed_public_key[0] != 0x04:
        raise ProtocolError("session public key must be 65-byte uncompressed P-256/X9.63")
    return encode_cbor(
        {
            "genMsgType": "sessionStart",
            "tmpKey": uncompressed_public_key,
        }
    )


def build_session_end() -> bytes:
    return encode_cbor({"genMsgType": "sessionEnd"})


def derive_session_aes_key(local_private_key: Any, peer_public_key_x963: bytes) -> bytes:
    """ECDH P-256 followed by SHA-256, matching ``AlEcc``."""

    from cryptography.hazmat.primitives.asymmetric import ec

    if len(peer_public_key_x963) != 65 or peer_public_key_x963[0] != 0x04:
        raise ProtocolError("peer public key must be uncompressed P-256/X9.63")
    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_key_x963
    )
    shared_secret = local_private_key.exchange(ec.ECDH(), peer)
    return sha256(shared_secret).digest()


def public_key_x963(private_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _encrypt_aes256_cbc_pkcs7(plaintext: bytes, session_aes_key: bytes) -> bytes:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(session_aes_key) != 32:
        raise ProtocolError("session AES key must be 32 bytes")
    if not plaintext:
        raise ProtocolError("AES plaintext cannot be empty")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(
        algorithms.AES(session_aes_key), modes.CBC(bytes(16))
    ).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _decrypt_aes256_cbc_pkcs7(ciphertext: bytes, session_aes_key: bytes) -> bytes:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(session_aes_key) != 32:
        raise ProtocolError("session AES key must be 32 bytes")
    if not ciphertext or len(ciphertext) % 16:
        raise ProtocolError("AES ciphertext must be non-empty whole blocks")
    decryptor = Cipher(
        algorithms.AES(session_aes_key), modes.CBC(bytes(16))
    ).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise ProtocolError("invalid AES/PKCS#7 payload") from exc


def build_reader_challenge(
    session_nonce: bytes,
    session_aes_key: bytes,
    version: PlatinumVersion,
    reader_device_auth_private_key: Any | None = None,
) -> tuple[bytes, bytes, bytes | None]:
    """Construct a synthetic reader challenge using the SDK's writer order.

    The V1 inner map is ``sNonce, genMaxSz`` and its outer map is
    ``genMsgType, encPayload``.  V2/V3 insert ``devAuthKey`` after ``sNonce``
    and append ``signatures`` to the outer map.  The signature is DER-encoded
    ECDSA-SHA256 over the ciphertext, not over plaintext CBOR.
    """

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    version = PlatinumVersion(version)
    if len(session_nonce) != 12:
        raise ProtocolError("XE360 challenge nonce must be 12 bytes")

    inner_fields: dict[str, Any] = {"sNonce": session_nonce}
    device_auth_key: bytes | None = None
    if version is not PlatinumVersion.V1:
        if reader_device_auth_private_key is None:
            raise ProtocolError("V2/V3 challenge requires a reader device-auth key")
        device_auth_key = public_key_x963(reader_device_auth_private_key)
        inner_fields["devAuthKey"] = device_auth_key
    inner_fields["genMaxSz"] = 1024
    encrypted = _encrypt_aes256_cbc_pkcs7(
        encode_cbor(inner_fields), session_aes_key
    )

    outer_fields: dict[str, Any] = {
        "genMsgType": "challenge",
        "encPayload": encrypted,
    }
    signature: bytes | None = None
    if version is not PlatinumVersion.V1:
        signature = reader_device_auth_private_key.sign(
            encrypted, ec.ECDSA(hashes.SHA256())
        )
        outer_fields["signatures"] = [
            {"keyId": "devAuthSig", "signature": signature}
        ]
    return encode_cbor(outer_fields), encrypted, signature


def parse_reader_challenge(
    challenge_cbor: bytes,
    session_aes_key: bytes,
    version: PlatinumVersion,
    *,
    serial_number: str,
    pin_store: DevicePinStore,
) -> ReaderChallenge:
    """Apply the APK's challenge decrypt, signature, and TOFU-pin semantics."""

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    version = PlatinumVersion(version)
    outer = decode_cbor(challenge_cbor)
    if not isinstance(outer, dict) or outer.get("genMsgType") != "challenge":
        raise ProtocolError("message is not a reader challenge")
    encrypted = outer.get("encPayload")
    if not isinstance(encrypted, bytes):
        raise ProtocolError("challenge encPayload is missing or not bytes")
    inner = decode_cbor(_decrypt_aes256_cbc_pkcs7(encrypted, session_aes_key))
    if not isinstance(inner, dict):
        raise ProtocolError("decrypted challenge is not a CBOR map")
    nonce = inner.get("sNonce")
    if not isinstance(nonce, bytes):
        raise ProtocolError("decrypted challenge has no byte-string sNonce")
    device_auth_key = inner.get("devAuthKey")
    max_size = inner.get("genMaxSz")

    # AlCredentialChallenge returns true immediately for V1.  In particular,
    # V1 neither requires nor verifies an optional device-auth signature.
    if version is PlatinumVersion.V1:
        return ReaderChallenge(
            nonce,
            device_auth_key if isinstance(device_auth_key, bytes) else None,
            max_size if isinstance(max_size, int) else None,
            encrypted,
            None,
            False,
        )

    if not isinstance(device_auth_key, bytes):
        raise ProtocolError("V2/V3 challenge is missing devAuthKey")
    signatures = outer.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ProtocolError("V2/V3 challenge has no signatures")
    device_auth_signature: bytes | None = None
    for item in signatures:
        if isinstance(item, dict) and item.get("keyId") == "devAuthSig":
            candidate = item.get("signature")
            if isinstance(candidate, bytes):
                # The Kotlin loop keeps the last matching entry.
                device_auth_signature = candidate
    if device_auth_signature is None:
        raise ProtocolError("V2/V3 challenge has no devAuthSig entry")
    try:
        device_auth_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), device_auth_key
        )
        device_auth_public.verify(
            device_auth_signature, encrypted, ec.ECDSA(hashes.SHA256())
        )
    except (ValueError, InvalidSignature) as exc:
        raise ProtocolError("reader device-auth signature validation failed") from exc

    was_pinned = any(serial == serial_number for serial, _ in pin_store.entries)
    if not pin_store.validate_or_pin(serial_number, device_auth_key):
        raise ProtocolError("reader device-auth pin validation failed")
    return ReaderChallenge(
        nonce,
        device_auth_key,
        max_size if isinstance(max_size, int) else None,
        encrypted,
        device_auth_signature,
        not was_pinned,
    )


def build_reader_reply(
    result: ReplyResult, session_aes_key: bytes
) -> tuple[bytes, bytes]:
    """Build a synthetic encrypted reply in the conventional writer order."""

    result = ReplyResult(result)
    encrypted = _encrypt_aes256_cbc_pkcs7(
        encode_cbor({"result": result.value}), session_aes_key
    )
    return encode_cbor(
        {"genMsgType": "reply", "encPayload": encrypted}
    ), encrypted


def parse_reader_reply(reply_cbor: bytes, session_aes_key: bytes) -> ReplyResult:
    """Decrypt a reply and apply the five exact string comparisons in the APK."""

    outer = decode_cbor(reply_cbor)
    if not isinstance(outer, dict) or outer.get("genMsgType") != "reply":
        raise ProtocolError("message is not a reader reply")
    encrypted = outer.get("encPayload")
    if not isinstance(encrypted, bytes):
        raise ProtocolError("reply encPayload is missing or not bytes")
    inner = decode_cbor(_decrypt_aes256_cbc_pkcs7(encrypted, session_aes_key))
    if not isinstance(inner, dict) or not isinstance(inner.get("result"), str):
        raise ProtocolError("decrypted reply has no string result")
    try:
        return ReplyResult(inner["result"])
    except ValueError as exc:
        raise ProtocolError("unknown reply from lock") from exc


def encrypt_platinum_inner(
    credential_blob: bytes, session_nonce: bytes, session_aes_key: bytes
) -> tuple[bytes, bytes]:
    """Return ``(inner_cbor, AES-256-CBC/PKCS7 ciphertext)``.

    Bouncy Castle receives only a KeyParameter in the APK, so CBC starts with
    its reset/default all-zero IV.  This is protocol compatibility, not a
    recommendation for new cryptographic designs.
    """

    if len(session_nonce) != 12:
        raise ProtocolError("XE360 challenge nonce must be 12 bytes")
    inner = encode_cbor(
        {
            "sNonce": session_nonce,
            "credBlob": credential_blob,
        }
    )
    return inner, _encrypt_aes256_cbc_pkcs7(inner, session_aes_key)


def build_platinum_payload(
    credential_blob: bytes,
    session_nonce: bytes,
    session_aes_key: bytes,
    device_private_key: Any,
) -> tuple[bytes, bytes, bytes]:
    """Build a synthetic signed-command message.

    Returns ``(outer_cbor, encrypted_inner, der_signature)``.  Java's
    ``SHA256withECDSA`` output is ASN.1 DER, which ``cryptography`` also emits.
    A real lock will reject synthetic blobs/keys; the function exists for
    offline interoperability tests only.
    """

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    _, encrypted = encrypt_platinum_inner(
        credential_blob, session_nonce, session_aes_key
    )
    signature = device_private_key.sign(encrypted, ec.ECDSA(hashes.SHA256()))
    outer = encode_cbor(
        {
            "genMsgType": "signedCmd",
            "encPayload": encrypted,
            "signatures": [
                {
                    "keyId": "mobileSig",
                    "signature": signature,
                }
            ],
        }
    )
    return outer, encrypted, signature


def verify_platinum_signature(
    device_public_key: Any, encrypted_payload: bytes, signature: bytes
) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    device_public_key.verify(signature, encrypted_payload, ec.ECDSA(hashes.SHA256()))
