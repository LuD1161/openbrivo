"""Restricted file bundle for a provisioned Allegion Platinum credential.

This module only transforms explicitly named, locally captured Android state
into files consumed by :mod:`session_orchestrator`.  It has no Bluetooth,
network, login, or unlock capability.  Its command output intentionally
contains metadata only, never credential/key/right/lock values.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .allegion_xe360 import public_key_x963
from .private_files import posix_mode_is_private, restrict_open_descriptor
from .session_orchestrator import (
    CredentialFileSource,
    DERSigningKeyFileSource,
    JsonDevicePinStore,
    ProvisionedCredentialBundle,
    SessionError,
)

BUNDLE_FORMAT = "xe360-provisioned-credential-bundle-v1"
MANIFEST_NAME = "bundle.json"
CREDENTIAL_NAME = "credential.bin"
PRIVATE_KEY_NAME = "signing-material.bin"
PIN_STORE_NAME = "reader-device-pins.json"
_OWNER_ONLY_FILE_MODE = 0o600
_OWNER_ONLY_DIRECTORY_MODE = 0o700


class ProvisionedBundleError(SessionError):
    """Malformed or insecure credential bundle input."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_owner_only_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ProvisionedBundleError("required bundle file is missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ProvisionedBundleError("bundle input must be a regular non-symlink file")
    if not posix_mode_is_private(metadata):
        raise ProvisionedBundleError("bundle input must not be group/world accessible")


def _require_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ProvisionedBundleError("bundle directory is missing") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ProvisionedBundleError("bundle path must be a directory, not a symlink")
    if not posix_mode_is_private(metadata):
        raise ProvisionedBundleError("bundle directory must not be group/world accessible")


def _write_owner_only(path: Path, contents: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        restrict_open_descriptor(descriptor, _OWNER_ONLY_FILE_MODE)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, _OWNER_ONLY_FILE_MODE)
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


def _single_cached_credential(state: dict[str, Any]) -> tuple[bytes, str, list[str], str]:
    if state.get("schemaVersion") != 1:
        raise ProvisionedBundleError("unsupported Android-state schema")
    cached = state.get("cachedAllegionCredentialsJson")
    if not isinstance(cached, str):
        raise ProvisionedBundleError("cached Allegion credential JSON is unavailable")
    try:
        records = json.loads(cached)
    except json.JSONDecodeError as exc:
        raise ProvisionedBundleError("cached Allegion credential JSON is malformed") from exc
    if not isinstance(records, dict) or len(records) != 1:
        raise ProvisionedBundleError("expected exactly one cached Allegion credential record")
    _, record = next(iter(records.items()))
    if not isinstance(record, dict):
        raise ProvisionedBundleError("cached Allegion credential record is malformed")
    encoded_payload = record.get("accessPayload")
    if not isinstance(encoded_payload, str):
        raise ProvisionedBundleError("cached AccessPayload is unavailable")
    try:
        access_payload = json.loads(encoded_payload)
    except json.JSONDecodeError as exc:
        raise ProvisionedBundleError("cached AccessPayload is malformed") from exc
    if not isinstance(access_payload, dict) or set(access_payload) != {"content", "rightID"}:
        raise ProvisionedBundleError("cached AccessPayload has an unexpected schema")
    encoded_content = access_payload["content"]
    right_id = access_payload["rightID"]
    if not isinstance(encoded_content, str) or not isinstance(right_id, str):
        raise ProvisionedBundleError("cached AccessPayload fields have invalid types")
    try:
        if str(uuid.UUID(right_id)) != right_id.lower():
            raise ValueError("non-canonical UUID")
    except ValueError as exc:
        raise ProvisionedBundleError("cached access-right ID is not a canonical UUID") from exc
    try:
        credential = base64.b64decode(encoded_content, validate=True)
    except binascii.Error as exc:
        raise ProvisionedBundleError("cached credential content is not base64") from exc
    if not credential or base64.b64encode(credential).decode("ascii") != encoded_content:
        raise ProvisionedBundleError("cached credential content is not canonical base64")
    lock_statuses = record.get("locksStatus")
    if not isinstance(lock_statuses, list) or not lock_statuses:
        raise ProvisionedBundleError("cached credential has no lock metadata")
    lock_ids: list[str] = []
    for item in lock_statuses:
        if not isinstance(item, dict) or set(item) != {"lockId"}:
            raise ProvisionedBundleError("cached lock metadata has an unexpected schema")
        lock_id = item["lockId"]
        if not isinstance(lock_id, str) or not lock_id:
            raise ProvisionedBundleError("cached lock ID is invalid")
        lock_ids.append(lock_id)
    if len(set(lock_ids)) != len(lock_ids):
        raise ProvisionedBundleError("cached lock metadata contains duplicate IDs")
    return credential, right_id, lock_ids, _sha256(cached.encode("utf-8"))


def _device_private_key(state: dict[str, Any]) -> tuple[ec.EllipticCurvePrivateKey, str]:
    device_key = state.get("deviceKey")
    if not isinstance(device_key, dict) or set(device_key) != {
        "privateScalarHex",
        "publicX963UncompressedHex",
    }:
        raise ProvisionedBundleError("Android device key has an unexpected schema")
    scalar_hex = device_key["privateScalarHex"]
    public_hex = device_key["publicX963UncompressedHex"]
    if (
        not isinstance(scalar_hex, str)
        or len(scalar_hex) != 64
        or scalar_hex != scalar_hex.lower()
        or not isinstance(public_hex, str)
        or len(public_hex) != 130
        or public_hex != public_hex.lower()
    ):
        raise ProvisionedBundleError("Android device key has invalid P-256 encoding")
    try:
        scalar = int(scalar_hex, 16)
        expected_public = bytes.fromhex(public_hex)
    except ValueError as exc:
        raise ProvisionedBundleError("Android device key is not hexadecimal") from exc
    if expected_public[0] != 0x04:
        raise ProvisionedBundleError("Android device public key is not X9.63 uncompressed")
    try:
        private_key = ec.derive_private_key(scalar, ec.SECP256R1())
    except ValueError as exc:
        raise ProvisionedBundleError("Android device private scalar is not P-256") from exc
    actual_public = public_key_x963(private_key)
    if not hmac.compare_digest(actual_public, expected_public):
        raise ProvisionedBundleError("Android private scalar/public key pairing failed")
    return private_key, public_hex


def export_android_state_bundle(source: Path, destination: Path) -> dict[str, Any]:
    """Write a new owner-only file bundle from one explicit Android-state file.

    The destination must not exist so a prior credential bundle is never
    overwritten.  Return values are deliberately limited to safe metadata.
    """

    source = Path(source).resolve(strict=True)
    destination_input = Path(destination)
    destination = destination_input.parent.resolve(strict=True) / destination_input.name
    _require_owner_only_regular_file(source)
    if destination.exists() or destination.is_symlink():
        raise ProvisionedBundleError("bundle destination already exists")
    try:
        state_bytes = source.read_bytes()
        state = json.loads(state_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisionedBundleError("Android-state input is unreadable") from exc
    if not isinstance(state, dict):
        raise ProvisionedBundleError("Android-state input must be a JSON object")
    credential, right_id, lock_ids, cached_state_sha256 = _single_cached_credential(state)
    private_key, public_hex = _device_private_key(state)

    destination.mkdir(mode=_OWNER_ONLY_DIRECTORY_MODE)
    os.chmod(destination, _OWNER_ONLY_DIRECTORY_MODE)
    try:
        credential_path = destination / CREDENTIAL_NAME
        key_path = destination / PRIVATE_KEY_NAME
        pin_store_path = destination / PIN_STORE_NAME
        manifest_path = destination / MANIFEST_NAME
        private_key_der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        manifest = {
            "format": BUNDLE_FORMAT,
            "credential_file": CREDENTIAL_NAME,
            "credential_sha256": _sha256(credential),
            "credential_length": len(credential),
            "private_key_file": PRIVATE_KEY_NAME,
            "provisioned_public_key_x963_hex": public_hex,
            "access_right_id": right_id,
            "lock_ids": lock_ids,
            "source_cached_state_sha256": cached_state_sha256,
            "source_state_sha256": _sha256(state_bytes),
        }
        _write_owner_only(credential_path, credential)
        _write_owner_only(key_path, private_key_der)
        _write_owner_only(
            pin_store_path,
            _canonical_json({"format": JsonDevicePinStore.FORMAT, "entries": []}),
        )
        _write_owner_only(manifest_path, _canonical_json(manifest))
    except BaseException:
        # The parent directory was created exclusively for this attempt.  Do
        # not leave a partial secret bundle behind when export fails.
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
    return inspect_bundle(destination, expected_source=source)


def export_provisioned_material_bundle(
    *,
    credential: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    access_right_id: str,
    destination: Path,
    lock_ids: list[str] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Export freshly provisioned material using the established bundle format.

    The caller is responsible for authenticating and validating the remote
    response.  This helper only checks that the returned payload is bound to
    the P-256 private key that will be used by the session orchestrator; it
    deliberately does not retain remote tokens or account identities.
    """

    if not credential:
        raise ProvisionedBundleError("provisioned credential is empty")
    try:
        canonical_right = str(uuid.UUID(access_right_id))
    except ValueError as exc:
        raise ProvisionedBundleError("access-right ID is not a canonical UUID") from exc
    if canonical_right != access_right_id.lower():
        raise ProvisionedBundleError("access-right ID is not a canonical UUID")
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise ProvisionedBundleError("provisioned signing key must be P-256")
    destination_input = Path(destination)
    destination = destination_input.parent.resolve(strict=True) / destination_input.name
    if destination.exists() or destination.is_symlink():
        raise ProvisionedBundleError("bundle destination already exists")
    safe_lock_ids = list(lock_ids or [])
    if not all(isinstance(value, str) and value for value in safe_lock_ids):
        raise ProvisionedBundleError("lock IDs must be nonempty strings")
    if len(set(safe_lock_ids)) != len(safe_lock_ids):
        raise ProvisionedBundleError("lock IDs must be unique")
    public_hex = public_key_x963(private_key).hex()
    provenance_hash = _sha256(_canonical_json(provenance or {"source": "mac-provisioning"}))

    destination.mkdir(mode=_OWNER_ONLY_DIRECTORY_MODE)
    os.chmod(destination, _OWNER_ONLY_DIRECTORY_MODE)
    try:
        private_key_der = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        manifest = {
            "format": BUNDLE_FORMAT,
            "credential_file": CREDENTIAL_NAME,
            "credential_sha256": _sha256(credential),
            "credential_length": len(credential),
            "private_key_file": PRIVATE_KEY_NAME,
            "provisioned_public_key_x963_hex": public_hex,
            "access_right_id": canonical_right,
            "lock_ids": safe_lock_ids,
            "source_cached_state_sha256": provenance_hash,
            "source_state_sha256": provenance_hash,
        }
        _write_owner_only(destination / CREDENTIAL_NAME, credential)
        _write_owner_only(destination / PRIVATE_KEY_NAME, private_key_der)
        _write_owner_only(
            destination / PIN_STORE_NAME,
            _canonical_json({"format": JsonDevicePinStore.FORMAT, "entries": []}),
        )
        _write_owner_only(destination / MANIFEST_NAME, _canonical_json(manifest))
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
    return inspect_bundle(destination)


def _read_manifest(bundle_directory: Path) -> dict[str, Any]:
    _require_owner_only_directory(bundle_directory)
    manifest_path = bundle_directory / MANIFEST_NAME
    _require_owner_only_regular_file(manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProvisionedBundleError("bundle manifest is unreadable") from exc
    expected = {
        "format",
        "credential_file",
        "credential_sha256",
        "credential_length",
        "private_key_file",
        "provisioned_public_key_x963_hex",
        "access_right_id",
        "lock_ids",
        "source_cached_state_sha256",
        "source_state_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected:
        raise ProvisionedBundleError("bundle manifest has an unexpected schema")
    if manifest["format"] != BUNDLE_FORMAT:
        raise ProvisionedBundleError("unrecognized bundle format")
    if manifest["credential_file"] != CREDENTIAL_NAME or manifest["private_key_file"] != PRIVATE_KEY_NAME:
        raise ProvisionedBundleError("bundle uses unexpected file names")
    public_hex = manifest["provisioned_public_key_x963_hex"]
    if not isinstance(public_hex, str) or len(public_hex) != 130 or public_hex != public_hex.lower():
        raise ProvisionedBundleError("bundle public key encoding is invalid")
    try:
        public_raw = bytes.fromhex(public_hex)
    except ValueError as exc:
        raise ProvisionedBundleError("bundle public key is not hexadecimal") from exc
    if len(public_raw) != 65 or public_raw[0] != 0x04:
        raise ProvisionedBundleError("bundle public key is not uncompressed P-256")
    if not isinstance(manifest["credential_length"], int) or manifest["credential_length"] <= 0:
        raise ProvisionedBundleError("bundle credential length is invalid")
    lock_ids = manifest["lock_ids"]
    if not isinstance(lock_ids, list) or any(not isinstance(value, str) or not value for value in lock_ids):
        raise ProvisionedBundleError("bundle lock IDs are invalid")
    if len(set(lock_ids)) != len(lock_ids):
        raise ProvisionedBundleError("bundle lock IDs must be unique")
    for key in ("credential_sha256", "source_cached_state_sha256", "source_state_sha256"):
        value = manifest[key]
        if not isinstance(value, str) or len(value) != 64:
            raise ProvisionedBundleError("bundle hash encoding is invalid")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise ProvisionedBundleError("bundle hash is not hexadecimal") from exc
    return manifest


def load_provisioned_credential_bundle(
    bundle_directory: Path, *, allows_live: bool = False
) -> tuple[ProvisionedCredentialBundle, JsonDevicePinStore, dict[str, Any]]:
    """Load and validate a bundle for the existing session orchestrator.

    ``allows_live`` is deliberately opt-in; callers must separately satisfy
    all session and native-bridge live gates before this material can be used.
    """

    bundle_directory = Path(bundle_directory)
    manifest = _read_manifest(bundle_directory)
    credential_path = bundle_directory / CREDENTIAL_NAME
    key_path = bundle_directory / PRIVATE_KEY_NAME
    pin_store_path = bundle_directory / PIN_STORE_NAME
    for path in (credential_path, key_path, pin_store_path):
        _require_owner_only_regular_file(path)
    credential = credential_path.read_bytes()
    if len(credential) != manifest["credential_length"] or not hmac.compare_digest(
        _sha256(credential), manifest["credential_sha256"]
    ):
        raise ProvisionedBundleError("bundle credential does not match manifest")
    bundle = ProvisionedCredentialBundle(
        CredentialFileSource(credential_path, allows_live=allows_live),
        DERSigningKeyFileSource(key_path, allows_live=allows_live),
        manifest["provisioned_public_key_x963_hex"],
    )
    # Verify the PEM scalar/public-point relation before returning a live-capable
    # source object.  This does not create a session or transmit anything.
    bundle.load_validated()
    pin_store = JsonDevicePinStore(pin_store_path)
    return bundle, pin_store, manifest


def inspect_bundle(bundle_directory: Path, *, expected_source: Path | None = None) -> dict[str, Any]:
    """Return metadata-only evidence that a bundle is usable by the PoC."""

    bundle, pin_store, manifest = load_provisioned_credential_bundle(bundle_directory)
    del bundle
    if expected_source is not None:
        source = Path(expected_source)
        _require_owner_only_regular_file(source)
        state_bytes = source.read_bytes()
        state = json.loads(state_bytes)
        credential, right_id, lock_ids, cached_state_sha256 = _single_cached_credential(state)
        if not hmac.compare_digest(_sha256(credential), manifest["credential_sha256"]):
            raise ProvisionedBundleError("bundle credential differs from Android state")
        if (
            manifest["access_right_id"] != right_id
            or manifest["lock_ids"] != lock_ids
            or not hmac.compare_digest(manifest["source_cached_state_sha256"], cached_state_sha256)
            or not hmac.compare_digest(manifest["source_state_sha256"], _sha256(state_bytes))
        ):
            raise ProvisionedBundleError("bundle metadata differs from Android state")
    directory = Path(bundle_directory)
    files = [directory / CREDENTIAL_NAME, directory / PRIVATE_KEY_NAME, directory / PIN_STORE_NAME, directory / MANIFEST_NAME]
    return {
        "bundle_path": str(directory),
        "bundle_mode": format(directory.stat().st_mode & 0o777, "03o"),
        "files": [
            {
                "path": str(path),
                "mode": format(path.stat().st_mode & 0o777, "03o"),
                "length": path.stat().st_size,
                "sha256": _sha256(path.read_bytes()),
            }
            for path in files
        ],
        "credential_length": manifest["credential_length"],
        "credential_sha256": manifest["credential_sha256"],
        "p256_private_public_pairing": "verified",
        "provisioned_public_key_binding": "verified",
        "canonical_base64_payload": "verified",
        "access_payload_equality": "verified" if expected_source is not None else "not-checked",
        "access_right_present": bool(manifest["access_right_id"]),
        "lock_metadata_present": bool(manifest["lock_ids"]),
        "reader_pin_store_entries": len(pin_store.entries),
    }


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Create or inspect a local owner-only XE360 credential bundle."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export-android-state")
    export.add_argument("--source", type=Path, required=True)
    export.add_argument("--destination", type=Path, required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--bundle", type=Path, required=True)
    inspect.add_argument("--expected-source", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "export-android-state":
        report = export_android_state_bundle(arguments.source, arguments.destination)
    else:
        report = inspect_bundle(arguments.bundle, expected_source=arguments.expected_source)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
