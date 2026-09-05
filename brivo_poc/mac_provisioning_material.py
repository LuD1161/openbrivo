"""Local cryptographic material for an authorized Mac XE360 provisioning flow.

This module deliberately performs no HTTP, Bluetooth, Android, or account
operations.  A caller supplies exact serialized request bytes and an already
received AccessHub response.  It can create the device proofs used by the
recovered SDK, verify the response integrity envelope, and persist only the
material consumed by the existing session orchestrator.

No function logs secret material or serializes an HTTP request on a caller's
behalf.  The caller remains responsible for authorization, transport, and
protecting all returned values.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .allegion_xe360 import public_key_x963
from .private_files import posix_mode_is_private, restrict_open_descriptor
from .provisioned_bundle import (
    BUNDLE_FORMAT,
    CREDENTIAL_NAME,
    MANIFEST_NAME,
    PIN_STORE_NAME,
    PRIVATE_KEY_NAME,
    load_provisioned_credential_bundle,
)
from .session_orchestrator import JsonDevicePinStore, SessionError

DEFAULT_MAA_CLOCK_OFFSET_MS = 300_000
_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700


class ProvisioningMaterialError(SessionError):
    """Invalid local key material, server envelope, or bundle input."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _owner_only_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ProvisioningMaterialError("required identity file is missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ProvisioningMaterialError("identity path must be a regular non-symlink file")
    if not posix_mode_is_private(metadata):
        raise ProvisioningMaterialError("identity file must not be group/world accessible")


def _write_owner_only(path: Path, contents: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        restrict_open_descriptor(descriptor, _FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(contents)
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


def _canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _validate_p256_private_key(private_key: Any) -> ec.EllipticCurvePrivateKey:
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise ProvisioningMaterialError("identity key must be P-256")
    return private_key


@dataclass(frozen=True)
class PersistentDeviceIdentity:
    """A software P-256 identity compatible with the recovered SDK contract."""

    private_key: ec.EllipticCurvePrivateKey

    def __post_init__(self) -> None:
        _validate_p256_private_key(self.private_key)

    @classmethod
    def generate(cls) -> "PersistentDeviceIdentity":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def load_der(cls, path: Path) -> "PersistentDeviceIdentity":
        path = Path(path)
        _owner_only_regular_file(path)
        try:
            private_key = serialization.load_der_private_key(
                path.read_bytes(), password=None
            )
        except (OSError, ValueError, TypeError) as exc:
            raise ProvisioningMaterialError("persistent identity cannot be loaded") from exc
        return cls(_validate_p256_private_key(private_key))

    @property
    def public_key_x963(self) -> bytes:
        return public_key_x963(self.private_key)

    @property
    def public_key_x963_lower_hex(self) -> str:
        return self.public_key_x963.hex()

    def sign_exact_bytes_der(self, exact_bytes: bytes) -> bytes:
        if not isinstance(exact_bytes, bytes):
            raise TypeError("exact signed data must be bytes")
        return self.private_key.sign(exact_bytes, ec.ECDSA(hashes.SHA256()))

    def sign_exact_bytes_lower_hex(self, exact_bytes: bytes) -> str:
        return self.sign_exact_bytes_der(exact_bytes).hex()

    def private_key_der(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def write_der(self, path: Path) -> None:
        """Persist this identity at an explicitly named owner-only path."""

        path = Path(path)
        parent = path.parent.resolve(strict=True)
        target = parent / path.name
        if target.exists() or target.is_symlink():
            raise ProvisioningMaterialError("identity destination already exists")
        _write_owner_only(target, self.private_key_der())


@dataclass(frozen=True)
class MaaAuthorizationProof:
    """Exact recovered Maa authorization-header inputs, without logging them."""

    proof_bytes: bytes
    signature_der: bytes
    signature_lower_hex: str
    authorization_header: str
    timestamp_utc: datetime


def _java_utc_timestamp(value: datetime) -> str:
    """Match ``yyyy-MM-d'T'HH:mm:ss.SSS'Z'`` from the static SDK builder."""

    utc_value = value.astimezone(timezone.utc)
    milliseconds = utc_value.microsecond // 1_000
    return (
        f"{utc_value.year:04d}-{utc_value.month:02d}-{utc_value.day}"
        f"T{utc_value.hour:02d}:{utc_value.minute:02d}:{utc_value.second:02d}."
        f"{milliseconds:03d}Z"
    )


def build_maa_authorization_proof(
    identity: PersistentDeviceIdentity,
    server_device_id: uuid.UUID | str,
    *,
    now: datetime | None = None,
    clock_offset_ms: int = DEFAULT_MAA_CLOCK_OFFSET_MS,
) -> MaaAuthorizationProof:
    """Build the recovered ``Authorization: Maa ...`` value.

    The proof is ``deviceUUID + '_' + UTC(now + offset)``.  The supplied
    ``now`` is useful for deterministic authorized integration tests; omitting
    it uses the current UTC instant.  This method does not transmit anything.
    """

    if not isinstance(clock_offset_ms, int):
        raise TypeError("clock offset must be an integer millisecond count")
    try:
        canonical_device_id = str(uuid.UUID(str(server_device_id)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ProvisioningMaterialError("server device ID must be a UUID") from exc
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ProvisioningMaterialError("authorization time must be timezone-aware")
    timestamp_utc = now.astimezone(timezone.utc) + timedelta(milliseconds=clock_offset_ms)
    proof = f"{canonical_device_id}_{_java_utc_timestamp(timestamp_utc)}".encode("utf-8")
    signature_der = identity.sign_exact_bytes_der(proof)
    signature_hex = signature_der.hex()
    authorization_value = "Maa " + base64.b64encode(
        proof + b":" + signature_hex.encode("ascii")
    ).decode("ascii")
    return MaaAuthorizationProof(
        proof_bytes=proof,
        signature_der=signature_der,
        signature_lower_hex=signature_hex,
        authorization_header=authorization_value,
        timestamp_utc=timestamp_utc,
    )


def _decode_x963_public_key(value: bytes | str) -> ec.EllipticCurvePublicKey:
    if isinstance(value, str):
        if value != value.lower() or len(value) != 130:
            raise ProvisioningMaterialError("origin public key hex must be lowercase X9.63")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ProvisioningMaterialError("origin public key is not hexadecimal") from exc
    elif isinstance(value, bytes):
        raw = value
    else:
        raise TypeError("origin public key must be X9.63 bytes or lowercase hex")
    if len(raw) != 65 or raw[0] != 0x04:
        raise ProvisioningMaterialError("origin public key is not uncompressed P-256")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise ProvisioningMaterialError("origin public key is not a valid P-256 point") from exc


def verify_accesshub_response_signatures(
    response_body: bytes,
    alle_signatures_header: str,
    origin_public_keys: Sequence[bytes | str],
) -> int:
    """Verify AccessHub's two-key ``alle-signatures`` response envelope.

    This mirrors the static client: the first comma-separated signature is
    checked with origin key zero and the second with origin key one.  It
    returns the matching origin-key index and rejects any malformed envelope.
    """

    if not isinstance(response_body, bytes) or not response_body:
        raise ProvisioningMaterialError("AccessHub response body must be non-empty bytes")
    if not isinstance(alle_signatures_header, str):
        raise TypeError("alle-signatures header must be a string")
    if len(origin_public_keys) != 2:
        raise ProvisioningMaterialError("exactly two configured origin public keys are required")
    fragments = alle_signatures_header.split(",")
    if len(fragments) != 2 or any(not fragment for fragment in fragments):
        raise ProvisioningMaterialError("alle-signatures must contain exactly two hex values")
    try:
        signatures = [bytes.fromhex(fragment) for fragment in fragments]
    except ValueError as exc:
        raise ProvisioningMaterialError("alle-signatures contains invalid hexadecimal") from exc
    if any(not signature for signature in signatures):
        raise ProvisioningMaterialError("alle-signatures contains an empty signature")
    public_keys = [_decode_x963_public_key(value) for value in origin_public_keys]
    for index, (public_key, signature) in enumerate(zip(public_keys, signatures)):
        try:
            public_key.verify(signature, response_body, ec.ECDSA(hashes.SHA256()))
            return index
        except InvalidSignature:
            continue
    raise ProvisioningMaterialError("AccessHub response signature validation failed")


@dataclass(frozen=True)
class VerifiedBlePlatinumPayload:
    """Opaque credential bytes after origin-envelope and response binding checks."""

    access_right_id: str
    credential_blob: bytes
    response_body_sha256: str
    matched_origin_key_index: int


def verify_and_extract_ble_platinum_payload(
    response_body: bytes,
    alle_signatures_header: str,
    origin_public_keys: Sequence[bytes | str],
    expected_access_right_id: uuid.UUID | str,
) -> VerifiedBlePlatinumPayload:
    """Verify a response envelope and extract exactly one standard Platinum blob."""

    matched_key = verify_accesshub_response_signatures(
        response_body, alle_signatures_header, origin_public_keys
    )
    try:
        expected_right = str(uuid.UUID(str(expected_access_right_id)))
        response = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, AttributeError) as exc:
        raise ProvisioningMaterialError("AccessHub payload response is malformed") from exc
    if not isinstance(response, dict):
        raise ProvisioningMaterialError("AccessHub payload response must be an object")
    response_right = response.get("accessRightId")
    if not isinstance(response_right, str):
        raise ProvisioningMaterialError("AccessHub response has no accessRightId")
    try:
        if str(uuid.UUID(response_right)) != expected_right:
            raise ProvisioningMaterialError("AccessHub response right does not match request")
    except ValueError as exc:
        raise ProvisioningMaterialError("AccessHub response right is not a UUID") from exc
    payloads = response.get("payloads")
    if not isinstance(payloads, list):
        raise ProvisioningMaterialError("AccessHub response has no payload list")
    candidates = [
        item
        for item in payloads
        if isinstance(item, dict) and item.get("payloadType") == "BLE_Platinum"
    ]
    if len(candidates) != 1:
        raise ProvisioningMaterialError("expected exactly one BLE_Platinum response payload")
    encoded_payload = candidates[0].get("payload")
    if not isinstance(encoded_payload, str) or not encoded_payload:
        raise ProvisioningMaterialError("BLE_Platinum response payload is unavailable")
    try:
        credential_blob = bytes.fromhex(encoded_payload)
    except ValueError as exc:
        raise ProvisioningMaterialError("BLE_Platinum response payload is not hexadecimal") from exc
    if not credential_blob:
        raise ProvisioningMaterialError("BLE_Platinum response payload is empty")
    return VerifiedBlePlatinumPayload(
        access_right_id=expected_right,
        credential_blob=credential_blob,
        response_body_sha256=_sha256(response_body),
        matched_origin_key_index=matched_key,
    )


def _validate_lock_ids(lock_ids: Sequence[str]) -> list[str]:
    if isinstance(lock_ids, (str, bytes)):
        raise ProvisioningMaterialError("lock IDs must be an explicit sequence")
    normalized = list(lock_ids)
    if any(not isinstance(item, str) or not item for item in normalized):
        raise ProvisioningMaterialError("lock IDs must be non-empty strings")
    if len(set(normalized)) != len(normalized):
        raise ProvisioningMaterialError("lock IDs must be unique")
    return normalized


def write_verified_provisioned_bundle(
    destination: Path,
    identity: PersistentDeviceIdentity,
    verified_payload: VerifiedBlePlatinumPayload,
    *,
    lock_ids: Sequence[str],
    provisioned_public_key_x963_lower_hex: str,
) -> dict[str, Any]:
    """Atomically write a new V3 bundle consumable by the existing loader.

    The explicit provisioning public-key argument gives callers a fail-closed
    check against the exact public key submitted to AccessHub.  It cannot
    inspect the opaque server payload; binding of that payload to the supplied
    public key remains enforced by the authorized server/reader protocol.
    """

    destination_input = Path(destination)
    destination = destination_input.parent.resolve(strict=True) / destination_input.name
    if destination.exists() or destination.is_symlink():
        raise ProvisioningMaterialError("bundle destination already exists")
    if not isinstance(verified_payload, VerifiedBlePlatinumPayload):
        raise TypeError("verified payload must come from response verification")
    identity_public_hex = identity.public_key_x963_lower_hex
    if not isinstance(provisioned_public_key_x963_lower_hex, str) or not hmac.compare_digest(
        provisioned_public_key_x963_lower_hex, identity_public_hex
    ):
        raise ProvisioningMaterialError("submitted provisioning public key differs from identity")
    selected_lock_ids = _validate_lock_ids(lock_ids)
    binding_record = _canonical_json(
        {
            "access_right_id": verified_payload.access_right_id,
            "credential_sha256": _sha256(verified_payload.credential_blob),
            "lock_ids": selected_lock_ids,
            "provisioned_public_key_x963_hex": identity_public_hex,
            "response_body_sha256": verified_payload.response_body_sha256,
        }
    )
    manifest = {
        "format": BUNDLE_FORMAT,
        "credential_file": CREDENTIAL_NAME,
        "credential_sha256": _sha256(verified_payload.credential_blob),
        "credential_length": len(verified_payload.credential_blob),
        "private_key_file": PRIVATE_KEY_NAME,
        "provisioned_public_key_x963_hex": identity_public_hex,
        "access_right_id": verified_payload.access_right_id,
        "lock_ids": selected_lock_ids,
        # These fields are required by the existing v1 loader.  For a new Mac
        # provisioning flow they retain cryptographic provenance hashes, not
        # Android-state claims: raw verified response and canonical binding.
        "source_cached_state_sha256": verified_payload.response_body_sha256,
        "source_state_sha256": _sha256(binding_record),
    }
    destination.mkdir(mode=_DIRECTORY_MODE)
    os.chmod(destination, _DIRECTORY_MODE)
    try:
        _write_owner_only(destination / CREDENTIAL_NAME, verified_payload.credential_blob)
        _write_owner_only(destination / PRIVATE_KEY_NAME, identity.private_key_der())
        _write_owner_only(
            destination / PIN_STORE_NAME,
            _canonical_json({"format": JsonDevicePinStore.FORMAT, "entries": []}),
        )
        _write_owner_only(destination / MANIFEST_NAME, _canonical_json(manifest))
        # Confirms P-256 pairing, public-key binding, manifest hash, and the
        # persistent V3 pin-store schema without opening any transport.
        bundle, pin_store, _ = load_provisioned_credential_bundle(destination)
        credential, loaded_key = bundle.load_validated()
        if credential != verified_payload.credential_blob or len(pin_store.entries) != 0:
            raise ProvisioningMaterialError("written bundle failed local validation")
        if not hmac.compare_digest(public_key_x963(loaded_key).hex(), identity_public_hex):
            raise ProvisioningMaterialError("written bundle key binding failed")
    except BaseException:
        for child in destination.iterdir() if destination.exists() else []:
            try:
                child.unlink()
            except OSError:
                pass
        try:
            destination.rmdir()
        except OSError:
            pass
        raise
    return {
        "bundle_path": str(destination),
        "bundle_mode": format(destination.stat().st_mode & 0o777, "03o"),
        "credential_length": len(verified_payload.credential_blob),
        "credential_sha256": _sha256(verified_payload.credential_blob),
        "p256_private_public_pairing": "verified",
        "provisioned_public_key_binding": "verified",
        "response_signature_verified": True,
        "access_right_present": True,
        "lock_metadata_present": bool(selected_lock_ids),
        "reader_pin_store_entries": 0,
    }
