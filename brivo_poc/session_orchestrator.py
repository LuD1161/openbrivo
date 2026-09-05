"""Transport-independent Allegion Platinum session orchestrator.

This module is the message/session seam between the recovered XE360 protocol
helpers and a future, separately reviewed transport adapter.  It imports no
Bluetooth API and contains no reader discovery or connection code.  Its
default entry point uses deterministic synthetic credential material.

Raw frames necessarily cross the duplex transport.  Diagnostic events never
contain raw frames, credentials, nonces, public/private keys, signatures,
tokens, serial numbers, paths, or hashes of those values.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol, TextIO, runtime_checkable

from .allegion_xe360 import (
    DevicePinStore,
    PlatinumVersion,
    ProtocolError,
    ReaderChallenge,
    ReplyResult,
    build_flow_control,
    build_platinum_payload,
    build_session_end,
    build_session_start,
    build_transport_error,
    build_transport_packets,
    decode_cbor,
    derive_session_aes_key,
    parse_reader_challenge,
    parse_reader_reply,
    parse_transport_packet,
    public_key_x963,
    reassemble_transport_packets,
    reply_requires_session_end,
)
from .private_files import restrict_open_descriptor

BENCH_CONFIRMATION_PREFIX = "I_CONFIRM_AUTHORIZED_ISOLATED_BENCH:"
MAX_EXPLICIT_CREDENTIAL_BYTES = 1024 * 1024


class SessionError(ProtocolError):
    """Fail-closed orchestrator, bridge, input, or state error."""


class LiveModeDenied(SessionError):
    """A live-declared adapter did not pass every bench-safety gate."""


class FatalSessionError(SessionError):
    """Local configuration/material failure that a reader retry cannot fix."""


class AdapterMode(str, Enum):
    SYNTHETIC = "synthetic"
    LIVE = "live"


class SessionState(str, Enum):
    IDLE = "idle"
    START_SESSION = "start-session"
    PLATINUM_PAYLOAD = "platinum-payload"
    END_SESSION = "end-session"
    FINISHED = "finished"
    FAILED = "failed"


class BridgeEventKind(str, Enum):
    DESCRIPTOR_ENABLED = "descriptor-enabled"
    WRITER_READY = "writer-ready"
    INBOUND_FRAME = "inbound-frame"
    WRITE_QUEUED = "write-queued"
    DISCONNECTED = "disconnected"


@dataclass(frozen=True)
class BridgeEvent:
    kind: BridgeEventKind
    frame: bytes | None = None

    def __post_init__(self) -> None:
        if self.kind is BridgeEventKind.INBOUND_FRAME:
            if not isinstance(self.frame, bytes):
                raise SessionError("inbound-frame event requires bytes")
        elif self.frame is not None:
            raise SessionError(f"{self.kind.value} event cannot carry a frame")


@runtime_checkable
class DuplexTransport(Protocol):
    """Minimal adapter contract; implementations own all I/O and readiness."""

    adapter_mode: AdapterMode
    adapter_identity: str
    bench_reader_serial: str | None
    maximum_write_value_length: int
    observed_platinum_version: PlatinumVersion | None
    notification_bytes_emitted: bool

    @property
    def can_write_without_response(self) -> bool: ...

    def write_frame(self, frame: bytes, *, purpose: str) -> bool:
        """Dispatch a frame and return true only if submission is confirmed."""

    def close(self) -> None:
        """Idempotently request transport disconnect/cleanup."""


class CredentialSource(ABC):
    """Explicit credential input.  There is no environment/keystore fallback."""

    allows_live: bool = False

    @abstractmethod
    def load_credential_blob(self) -> bytes:
        """Return one caller-selected opaque credential blob."""


class SigningKeySource(ABC):
    """Explicit P-256 signing-key input; never discovered implicitly."""

    allows_live: bool = False

    @abstractmethod
    def load_private_key(self) -> Any:
        """Return a cryptography P-256 private key."""


@dataclass(frozen=True)
class ProvisionedCredentialBundle:
    """Credential/key binding exported by an explicit provisioning workflow.

    Brivo provisions the lower-hex 65-byte X9.63 device public key and later
    signs ``signedCmd`` with that same device private key.  A blob plus an
    arbitrary P-256 key is therefore never accepted by the orchestrator.
    """

    credential_source: CredentialSource
    signing_key_source: SigningKeySource
    provisioned_public_key_hex: str

    def __post_init__(self) -> None:
        encoded = self.provisioned_public_key_hex
        if (
            not isinstance(encoded, str)
            or encoded != encoded.lower()
            or len(encoded) != 130
        ):
            raise SessionError(
                "provisioned public key must be 130 lowercase X9.63 hex characters"
            )
        try:
            raw = bytes.fromhex(encoded)
        except ValueError as exc:
            raise SessionError("provisioned public key hex is invalid") from exc
        if len(raw) != 65 or raw[0] != 0x04:
            raise SessionError("provisioned public key is not uncompressed P-256")

    @property
    def allows_live(self) -> bool:
        return (
            self.credential_source.allows_live
            and self.signing_key_source.allows_live
        )

    def load_validated(self) -> tuple[bytes, Any]:
        credential = self.credential_source.load_credential_blob()
        if not isinstance(credential, bytes) or not credential:
            raise SessionError("credential source returned invalid bytes")
        signing_key = self.signing_key_source.load_private_key()
        _validate_p256_private_key(signing_key)
        actual_public_hex = public_key_x963(signing_key).hex()
        if actual_public_hex != self.provisioned_public_key_hex:
            raise SessionError(
                "signing key does not match explicitly provisioned device public key"
            )
        return credential, signing_key


class ExplicitCredentialSource(CredentialSource):
    """Caller-owned bytes, copied on construction."""

    def __init__(self, credential_blob: bytes, *, allows_live: bool = False) -> None:
        if not isinstance(credential_blob, bytes) or not credential_blob:
            raise SessionError("credential blob must be non-empty bytes")
        if len(credential_blob) > MAX_EXPLICIT_CREDENTIAL_BYTES:
            raise SessionError("credential blob exceeds explicit input safety limit")
        self._blob = bytes(credential_blob)
        self.allows_live = bool(allows_live)

    def load_credential_blob(self) -> bytes:
        return bytes(self._blob)


class CredentialFileSource(CredentialSource):
    """Read an explicitly named binary file only when the challenge is valid."""

    def __init__(self, path: Path, *, allows_live: bool = False) -> None:
        self._path = Path(path)
        self.allows_live = bool(allows_live)

    def load_credential_blob(self) -> bytes:
        raw = self._path.read_bytes()
        if not raw:
            raise SessionError("credential file is empty")
        if len(raw) > MAX_EXPLICIT_CREDENTIAL_BYTES:
            raise SessionError("credential file exceeds explicit input safety limit")
        return raw


class ExplicitSigningKeySource(SigningKeySource):
    """Caller-owned cryptography key; validated when requested."""

    def __init__(self, private_key: Any, *, allows_live: bool = False) -> None:
        self._private_key = private_key
        self.allows_live = bool(allows_live)

    def load_private_key(self) -> Any:
        _validate_p256_private_key(self._private_key)
        return self._private_key


class PEMSigningKeyFileSource(SigningKeySource):
    """Load a caller-selected PEM file with an explicit password callback."""

    def __init__(
        self,
        path: Path,
        *,
        password_provider: Callable[[], bytes | None] | None = None,
        allows_live: bool = False,
    ) -> None:
        self._path = Path(path)
        self._password_provider = password_provider
        self.allows_live = bool(allows_live)

    def load_private_key(self) -> Any:
        from cryptography.hazmat.primitives import serialization

        password = self._password_provider() if self._password_provider else None
        key = serialization.load_pem_private_key(self._path.read_bytes(), password=password)
        _validate_p256_private_key(key)
        return key


class DERSigningKeyFileSource(SigningKeySource):
    """Load an explicitly named PKCS#8 DER P-256 signing key file."""

    def __init__(self, path: Path, *, allows_live: bool = False) -> None:
        self._path = Path(path)
        self.allows_live = bool(allows_live)

    def load_private_key(self) -> Any:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_der_private_key(self._path.read_bytes(), password=None)
        _validate_p256_private_key(key)
        return key


def _validate_p256_private_key(private_key: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise SessionError("signing key must be a P-256 private key")


class JsonDevicePinStore(DevicePinStore):
    """Persistent serial/public-key TOFU store matching the SDK's 20-pin model.

    The file contains public reader authentication keys, not credentials or
    private key material.  Existing/corrupt files fail closed.  A successful
    first pin is persisted atomically with owner-only permissions.
    """

    FORMAT = "xe360-device-pins-v1"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        entries: list[tuple[str, bytes]] = []
        if self.path.exists():
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or document.get("format") != self.FORMAT:
                raise SessionError("unrecognized device pin-store format")
            raw_entries = document.get("entries")
            if not isinstance(raw_entries, list) or len(raw_entries) > 20:
                raise SessionError("invalid device pin-store entry list")
            seen_serials: set[str] = set()
            seen_keys: set[bytes] = set()
            for item in raw_entries:
                if not isinstance(item, dict):
                    raise SessionError("invalid device pin-store entry")
                serial = item.get("serial")
                key_hex = item.get("public_key_hex")
                if not isinstance(serial, str) or not serial or not isinstance(key_hex, str):
                    raise SessionError("invalid device pin-store fields")
                try:
                    key = bytes.fromhex(key_hex)
                except ValueError as exc:
                    raise SessionError("invalid device pin-store public key") from exc
                if len(key) != 65 or key[0] != 0x04:
                    raise SessionError("device pin is not an uncompressed P-256 key")
                if serial in seen_serials or key in seen_keys:
                    raise SessionError("duplicate serial or public key in device pin store")
                seen_serials.add(serial)
                seen_keys.add(key)
                entries.append((serial, key))
        super().__init__(entries)

    def validate_or_pin(self, serial_number: str, device_auth_key: bytes) -> bool:
        before = self.entries
        accepted = super().validate_or_pin(serial_number, device_auth_key)
        if accepted and self.entries != before:
            try:
                self._persist()
            except BaseException:
                # A pin that was not durably stored must not remain accepted in
                # memory for the rest of this process.
                self._entries = list(before)
                raise
        return accepted

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "format": self.FORMAT,
            "entries": [
                {"serial": serial, "public_key_hex": key.hex()}
                for serial, key in self.entries
            ],
        }
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=str(self.path.parent)
        )
        try:
            restrict_open_descriptor(descriptor)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
            os.chmod(self.path, 0o600)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise


@dataclass(frozen=True)
class BenchAuthorization:
    """Explicit, serial-bound confirmation required by live adapters."""

    token: str

    @classmethod
    def expected_token(cls, reader_serial: str) -> str:
        return f"{BENCH_CONFIRMATION_PREFIX}{reader_serial}"

    def validates(self, reader_serial: str) -> bool:
        return self.token == self.expected_token(reader_serial)


@dataclass(frozen=True)
class SessionConfiguration:
    version: PlatinumVersion
    reader_serial: str
    bench_authorization: BenchAuthorization | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "version", PlatinumVersion(self.version))
        if not isinstance(self.reader_serial, str) or not self.reader_serial:
            raise SessionError("reader serial must be explicitly supplied")


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event: str
    state: str
    group_number: int
    purpose: str | None = None
    frame_length: int | None = None
    retry_count: int | None = None
    reply_result: str | None = None


class SecretSafeAuditLog:
    """Deterministic metadata-only log with no byte-valued escape hatch."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(
        self,
        event: str,
        state: SessionState,
        group_number: int,
        *,
        purpose: str | None = None,
        frame_length: int | None = None,
        retry_count: int | None = None,
        reply_result: ReplyResult | None = None,
    ) -> None:
        self.events.append(
            AuditEvent(
                sequence=len(self.events),
                event=event,
                state=state.value,
                group_number=group_number,
                purpose=purpose,
                frame_length=frame_length,
                retry_count=retry_count,
                reply_result=reply_result.value if reply_result else None,
            )
        )

    def json_lines(self) -> str:
        return "".join(
            json.dumps(event.__dict__, sort_keys=True, separators=(",", ":")) + "\n"
            for event in self.events
        )


@dataclass(frozen=True)
class _OutboundFrame:
    purpose: str
    raw: bytes


class PlatinumSessionOrchestrator:
    """Event-driven V1/V2/V3 mediator with no transport implementation.

    A new P-256 ECDH key is generated per instance (or explicitly injected by
    deterministic tests).  Credential and signing-key providers are not read
    until the reader session key exists and the challenge has passed the
    version-specific validation, including V2/V3 signature and serial pinning.
    """

    def __init__(
        self,
        transport: DuplexTransport,
        configuration: SessionConfiguration,
        credential_bundle: ProvisionedCredentialBundle,
        *,
        pin_store: DevicePinStore | None = None,
        session_private_key_factory: Callable[[], Any] | None = None,
        audit_log: SecretSafeAuditLog | None = None,
    ) -> None:
        if not isinstance(transport, DuplexTransport):
            raise TypeError("transport does not implement DuplexTransport")
        if transport.maximum_write_value_length <= 20:
            raise SessionError("maximum write value length must exceed 20 bytes")
        try:
            mode = AdapterMode(transport.adapter_mode)
        except ValueError as exc:
            raise SessionError("adapter mode must be synthetic or live") from exc
        if not isinstance(transport.adapter_identity, str) or not transport.adapter_identity:
            raise SessionError("adapter must provide a non-empty identity")
        self.transport = transport
        self.configuration = configuration
        self.credential_bundle = credential_bundle
        self.pin_store = pin_store if pin_store is not None else DevicePinStore()
        self.audit = audit_log if audit_log is not None else SecretSafeAuditLog()
        self.state = SessionState.IDLE
        self.message_count = 0
        self.sent_message_error_count = 0
        self.receive_message_error_count = 0
        self.reader_session_seen = False
        self.last_reply: ReplyResult | None = None
        self.last_challenge: ReaderChallenge | None = None
        self._pending: deque[_OutboundFrame] = deque()
        self._inbound_frames: list[bytes] = []
        self._retry_message: tuple[str, bytes] | None = None
        self._awaiting_submission: _OutboundFrame | None = None
        self._submission_callbacks: dict[str, Callable[[], None]] = {}
        self._transport_closed = False
        self._session_key: bytes | None = None
        if session_private_key_factory is None:
            from cryptography.hazmat.primitives.asymmetric import ec

            def default_session_private_key_factory() -> Any:
                return ec.generate_private_key(ec.SECP256R1())

            session_private_key_factory = default_session_private_key_factory
        self._session_private_key = session_private_key_factory()
        _validate_p256_private_key(self._session_private_key)
        self._adapter_mode = mode

    @classmethod
    def synthetic(
        cls,
        transport: DuplexTransport,
        *,
        version: PlatinumVersion = PlatinumVersion.V3,
        reader_serial: str = "SYNTHETIC-READER",
        pin_store: DevicePinStore | None = None,
        session_private_key_factory: Callable[[], Any] | None = None,
    ) -> "PlatinumSessionOrchestrator":
        """Construct the default dry-run path with obviously invalid material."""

        from cryptography.hazmat.primitives.asymmetric import ec

        signing_key = ec.derive_private_key(0x34567, ec.SECP256R1())
        return cls(
            transport,
            SessionConfiguration(version, reader_serial),
            ProvisionedCredentialBundle(
                ExplicitCredentialSource(b"SYNTHETIC-NOT-A-VALID-CREDENTIAL"),
                ExplicitSigningKeySource(signing_key),
                public_key_x963(signing_key).hex(),
            ),
            pin_store=pin_store,
            session_private_key_factory=session_private_key_factory,
        )

    @property
    def pending_write_count(self) -> int:
        return len(self._pending)

    @property
    def session_key_established(self) -> bool:
        return self._session_key is not None

    def descriptor_enabled(self) -> None:
        self._require_state(SessionState.IDLE)
        if not self.transport.notification_bytes_emitted:
            self._fail("notification-bytes-unavailable")
            raise FatalSessionError(
                "transport cannot run a session without notification bytes"
            )
        try:
            self._enforce_live_gate()
        except LiveModeDenied:
            self._fail("live-mode-gate-denied")
            raise
        message = build_session_start(public_key_x963(self._session_private_key))
        self._set_state(SessionState.START_SESSION)
        self._queue_message("session-start", message, retryable=True)
        self.audit.record("session-started", self.state, self.message_count)

    def writer_ready(self) -> None:
        self._reject_terminal_event("writer-ready")
        if self._awaiting_submission is not None:
            try:
                credit_granted = self.transport.can_write_without_response
            except Exception as exc:
                self._fail("transport-readiness-failed")
                raise FatalSessionError("transport readiness check failed") from exc
            if not credit_granted:
                self._fail("submission-confirmation-without-credit")
                raise FatalSessionError(
                    "transport confirmed submission without restoring write credit"
                )
            submitted = self._awaiting_submission
            self._awaiting_submission = None
            self._on_frame_submitted(submitted)
        self._flush_one()

    def receive_frame(self, raw: bytes) -> None:
        self._reject_terminal_event("inbound-frame")
        if self.state is SessionState.IDLE:
            raise SessionError("inbound frame before descriptor-enabled")
        if not isinstance(raw, bytes) or not raw:
            raise SessionError("inbound frame must be non-empty bytes")
        if len(raw) > self.transport.maximum_write_value_length:
            self._fail("inbound-frame-exceeds-maximum")
            raise SessionError("inbound frame exceeds adapter maximum")
        try:
            packet = parse_transport_packet(raw)
            if packet.message_type == 3:
                if self._inbound_frames:
                    raise SessionError("flow control interrupted fragmented message")
                self._receive_flow_control()
                return
            if packet.message_type == 2:
                if self._inbound_frames:
                    raise SessionError("transport error interrupted fragmented message")
                self._receive_transport_error()
                return
            self._inbound_frames.append(raw)
            if packet.message_type == 0:
                return
            frames = self._inbound_frames
            self._inbound_frames = []
            message_raw = reassemble_transport_packets(frames)
            self._receive_message(message_raw)
        except FatalSessionError:
            self._inbound_frames = []
            raise
        except (ProtocolError, SessionError) as exc:
            self._inbound_frames = []
            if self.state is SessionState.FAILED:
                raise
            self._handle_receive_error(raw, exc)

    def disconnected(self) -> None:
        if self.state not in (SessionState.FINISHED, SessionState.FAILED):
            self._fail("transport-disconnected")

    def abort(self, reason: str = "orchestrator-abort") -> None:
        """Idempotently fail and close an incomplete session."""

        if self.state not in (SessionState.FINISHED, SessionState.FAILED):
            self._fail(reason)
        else:
            self._close_transport()

    def process_bridge_event(self, event: BridgeEvent) -> None:
        if event.kind is BridgeEventKind.DESCRIPTOR_ENABLED:
            self.descriptor_enabled()
        elif event.kind is BridgeEventKind.WRITER_READY:
            self.writer_ready()
        elif event.kind is BridgeEventKind.INBOUND_FRAME:
            assert event.frame is not None
            self.receive_frame(event.frame)
        elif event.kind is BridgeEventKind.WRITE_QUEUED:
            self.audit.record("transport-write-queued", self.state, self.message_count)
        elif event.kind is BridgeEventKind.DISCONNECTED:
            self.disconnected()
        else:  # pragma: no cover - exhaustive enum defense
            raise SessionError(f"unsupported bridge event {event.kind!r}")

    def _enforce_live_gate(self) -> None:
        if self._adapter_mode is not AdapterMode.LIVE:
            return
        authorization = self.configuration.bench_authorization
        if authorization is None or not authorization.validates(
            self.configuration.reader_serial
        ):
            raise LiveModeDenied("live adapter requires exact serial-bound bench token")
        if self.transport.bench_reader_serial != self.configuration.reader_serial:
            raise LiveModeDenied("live adapter bench serial does not match session serial")
        if self.transport.observed_platinum_version != self.configuration.version:
            raise LiveModeDenied(
                "live adapter observed Platinum version does not match session version"
            )
        if not self.transport.notification_bytes_emitted:
            raise LiveModeDenied("live adapter does not expose notification bytes")
        if not self.credential_bundle.allows_live:
            raise LiveModeDenied("credential and key sources require explicit live opt-in")
        if self.configuration.version is not PlatinumVersion.V1 and not isinstance(
            self.pin_store, JsonDevicePinStore
        ):
            raise LiveModeDenied("V2/V3 live sessions require a persistent pin store")

    def _receive_message(self, raw: bytes) -> None:
        message = decode_cbor(raw)
        if not isinstance(message, dict):
            raise SessionError("message layer is not a CBOR map")
        message_type = message.get("genMsgType")
        if message_type == "sessionStart":
            self._require_state(SessionState.START_SESSION)
            if self.reader_session_seen:
                raise SessionError("duplicate reader sessionStart")
            peer_key = message.get("tmpKey")
            if not isinstance(peer_key, bytes):
                raise SessionError("reader sessionStart has no tmpKey")
            self._session_key = derive_session_aes_key(
                self._session_private_key, peer_key
            )
            self.reader_session_seen = True
            self._queue_control("ack-reader-session", build_flow_control(self.message_count))
            self.audit.record("reader-session-established", self.state, self.message_count)
            return
        if message_type == "challenge":
            self._require_state(SessionState.START_SESSION)
            if not self.reader_session_seen or self._session_key is None:
                raise SessionError("challenge arrived before reader sessionStart")
            challenge = parse_reader_challenge(
                raw,
                self._session_key,
                self.configuration.version,
                serial_number=self.configuration.reader_serial,
                pin_store=self.pin_store,
            )
            self.last_challenge = challenge
            # APK ordering is ACK first, then payload construction/send.  The
            # callback fires only after this exact ACK frame is confirmed as
            # submitted by the transport adapter.
            self._submission_callbacks["ack-challenge"] = (
                self._complete_challenge_after_ack
            )
            self._queue_control("ack-challenge", build_flow_control(self.message_count))
            return
        if message_type == "reply":
            self._require_state(SessionState.PLATINUM_PAYLOAD)
            if self._session_key is None:
                raise SessionError("reply arrived before session-key derivation")
            result = parse_reader_reply(raw, self._session_key)
            self.last_reply = result
            self._queue_control("ack-reply", build_flow_control(self.message_count))
            self.audit.record(
                "reply-received", self.state, self.message_count, reply_result=result
            )
            if reply_requires_session_end(result):
                self._set_state(SessionState.END_SESSION)
                self._queue_message("session-end", build_session_end(), retryable=True)
            return
        if message_type == "signedCmd":
            self._fail("reader-sent-signed-command")
            raise SessionError("reader sent invalid signedCmd")
        raise SessionError(f"unexpected reader message type: {message_type!r}")

    def _complete_challenge_after_ack(self) -> None:
        if self.state is SessionState.FAILED:
            return
        challenge = self.last_challenge
        if challenge is None or self._session_key is None:
            self._fail("challenge-continuation-state-invalid")
            raise FatalSessionError("validated challenge/session key is unavailable")
        # Inputs are deliberately accessed only after challenge validation and
        # after its ACK has been submitted.
        try:
            credential, signing_key = self.credential_bundle.load_validated()
            signed_command, _, _ = build_platinum_payload(
                credential,
                challenge.session_nonce,
                self._session_key,
                signing_key,
            )
        except Exception as exc:
            self._fail("credential-bundle-invalid")
            raise FatalSessionError(
                "credential/key bundle validation or signing failed"
            ) from exc
        self._set_state(SessionState.PLATINUM_PAYLOAD)
        self._queue_message("signed-command", signed_command, retryable=True)
        self.audit.record("challenge-accepted", self.state, self.message_count)

    def _receive_flow_control(self) -> None:
        self.message_count += 1
        self.sent_message_error_count = 0
        self.audit.record("flow-control", self.state, self.message_count)
        if self.state is SessionState.IDLE:
            self._fail("ack-in-idle")
            raise SessionError("ACK should not be received in idle")
        if self.state is SessionState.END_SESSION:
            if self._pending or self._awaiting_submission is not None:
                raise SessionError("end-session ACK arrived before writes drained")
            self._set_state(SessionState.FINISHED)
            self.audit.record("session-finished", self.state, self.message_count)
            self._clear_session_references()
            self._close_transport()

    def _receive_transport_error(self) -> None:
        self.sent_message_error_count += 1
        self.audit.record(
            "transport-error",
            self.state,
            self.message_count,
            retry_count=self.sent_message_error_count,
        )
        if self.sent_message_error_count >= 3:
            self._fail("outbound-retry-limit")
            return
        if self._pending:
            raise SessionError("transport error received while writes remain queued")
        if self._retry_message is None:
            raise SessionError("transport error has no retryable message")
        purpose, message = self._retry_message
        self._queue_message(f"{purpose}-retry", message, retryable=False)

    def _handle_receive_error(self, raw: bytes, error: Exception) -> None:
        if self.state is SessionState.FAILED:
            raise SessionError("cannot NAK after terminal failure") from error
        self.receive_message_error_count += 1
        self.audit.record(
            "receive-error",
            self.state,
            self.message_count,
            retry_count=self.receive_message_error_count,
        )
        # APK sends three NAKs, then fails on the fourth malformed receive.
        if self.receive_message_error_count <= 3:
            # Decompiled code uses raw data[2] as the error packet number.  For
            # short/multi-byte CBOR heads that byte is not reliably a parsed
            # packet index; preserve the observed byte when it is valid and
            # otherwise fail closed to packet 1.
            packet_number = raw[2] if len(raw) > 2 and raw[2] >= 1 else 1
            self._queue_control(
                "nak-inbound", build_transport_error(self.message_count, packet_number)
            )
            return
        self._fail("inbound-retry-limit")
        raise SessionError("inbound message retry limit exceeded") from error

    def _queue_control(self, purpose: str, frame: bytes) -> None:
        self._enqueue_frames(purpose, [frame])

    def _queue_message(self, purpose: str, message: bytes, *, retryable: bool) -> None:
        frames = build_transport_frames_for_cap(
            message,
            self.message_count,
            self.transport.maximum_write_value_length,
        )
        if retryable:
            self._retry_message = (purpose, bytes(message))
        self._enqueue_frames(purpose, frames)

    def _enqueue_frames(self, purpose: str, frames: list[bytes]) -> None:
        if self.state is SessionState.FAILED:
            raise SessionError("cannot queue frames after terminal failure")
        if not frames:
            raise SessionError("cannot enqueue an empty frame batch")
        maximum = self.transport.maximum_write_value_length
        for frame in frames:
            if len(frame) > maximum:
                raise SessionError(
                    f"encoded frame length {len(frame)} exceeds adapter maximum {maximum}"
                )
            self._pending.append(_OutboundFrame(purpose, frame))
        self._flush_one()

    def _flush_one(self) -> None:
        if self.state in (SessionState.FINISHED, SessionState.FAILED):
            return
        try:
            can_write = self.transport.can_write_without_response
        except Exception as exc:
            self._fail("transport-readiness-failed")
            raise FatalSessionError("transport readiness check failed") from exc
        if not self._pending or not can_write:
            return
        if self._awaiting_submission is not None:
            return
        # Peek first. A synchronous adapter failure leaves the item logically
        # unsent until fail/cleanup clears the session queue.
        item = self._pending[0]
        maximum = self.transport.maximum_write_value_length
        if len(item.raw) > maximum:
            self._fail("outbound-frame-exceeds-maximum")
            raise SessionError("queued frame exceeds adapter maximum")
        try:
            submission_confirmed = self.transport.write_frame(
                item.raw, purpose=item.purpose
            )
            if type(submission_confirmed) is not bool:
                raise TypeError("transport write_frame must return bool")
        except Exception as exc:
            self._fail("transport-write-failed")
            raise FatalSessionError("transport write failed") from exc
        self._pending.popleft()
        self.audit.record(
            "frame-sent",
            self.state,
            self.message_count,
            purpose=item.purpose,
            frame_length=len(item.raw),
        )
        if submission_confirmed:
            self._on_frame_submitted(item)
        else:
            self._awaiting_submission = item

    def _on_frame_submitted(self, item: _OutboundFrame) -> None:
        self.audit.record(
            "frame-submitted",
            self.state,
            self.message_count,
            purpose=item.purpose,
            frame_length=len(item.raw),
        )
        callback = self._submission_callbacks.pop(item.purpose, None)
        if callback is not None:
            callback()

    def _set_state(self, state: SessionState) -> None:
        self.state = state
        self.audit.record("state-transition", self.state, self.message_count)

    def _fail(self, event: str) -> None:
        if self.state in (SessionState.FINISHED, SessionState.FAILED):
            self._close_transport()
            return
        self._pending.clear()
        self._inbound_frames.clear()
        self.state = SessionState.FAILED
        self.audit.record(event, self.state, self.message_count)
        self._clear_session_references()
        self._close_transport()

    def _clear_session_references(self) -> None:
        # Python immutable bytes cannot be reliably zeroized.  Drop all
        # orchestrator-held session references at terminal state and never log
        # them; callers remain responsible for their provider-owned material.
        self._session_key = None
        self._session_private_key = None
        self._retry_message = None
        self.last_challenge = None
        self._awaiting_submission = None
        self._submission_callbacks.clear()

    def _close_transport(self) -> None:
        if self._transport_closed:
            return
        self._transport_closed = True
        try:
            self.transport.close()
            self.audit.record("transport-close-requested", self.state, self.message_count)
        except Exception:
            # Cleanup is best-effort and idempotent. Preserve the original
            # terminal outcome instead of replacing it with a close exception.
            self.audit.record("transport-close-failed", self.state, self.message_count)

    def _require_state(self, expected: SessionState) -> None:
        if self.state is not expected:
            raise SessionError(
                f"expected state {expected.value}, found {self.state.value}"
            )

    def _reject_terminal_event(self, event: str) -> None:
        if self.state in (SessionState.FINISHED, SessionState.FAILED):
            raise SessionError(f"{event} after terminal state {self.state.value}")


def build_transport_frames_for_cap(
    message: bytes, group_number: int, maximum_write_value_length: int
) -> list[bytes]:
    """Recreate Android segmentation from CoreBluetooth's ATT payload cap.

    Android passes negotiated ATT MTU to ``AlCBORWrite``; CoreBluetooth exposes
    the ATT value cap, which is MTU minus three.  The first attempt therefore
    uses ``cap + 3`` (244 -> 247 -> 227-byte CBOR chunks).  The independent
    encoded-length check is authoritative; a smaller synthetic cap is reduced
    until every frame fits or the transport cannot represent the envelope.
    """

    if maximum_write_value_length <= 20:
        raise SessionError("maximum write value length must exceed 20 bytes")
    candidate_mtu = maximum_write_value_length + 3
    while candidate_mtu > 20:
        frames = build_transport_packets(message, group_number, mtu_size=candidate_mtu)
        if all(len(frame) <= maximum_write_value_length for frame in frames):
            return frames
        candidate_mtu -= 1
    raise SessionError("adapter maximum is too small for transport framing")


class JsonLinesDuplexTransport:
    """JSON-lines bridge protocol for a separately implemented adapter.

    The first input line must be a ``hello`` declaration.  Subsequent input
    events are descriptor/readiness/notification/disconnect events.  Output
    ``write-frame`` lines are transport commands and therefore contain the raw
    frame; they must not be copied into diagnostic logs.
    """

    def __init__(self, source: TextIO, sink: TextIO) -> None:
        self._source = source
        self._sink = sink
        hello = self._read_document()
        if hello.get("event") != "hello":
            raise SessionError("JSON-lines bridge must start with hello")
        try:
            self.adapter_mode = AdapterMode(hello.get("adapter_mode"))
        except ValueError as exc:
            raise SessionError("bridge hello has invalid adapter_mode") from exc
        identity = hello.get("adapter_identity")
        maximum = hello.get("maximum_write_value_length")
        serial = hello.get("bench_reader_serial")
        initially_ready = hello.get("initially_ready", False)
        observed_version = hello.get("platinum_version")
        notification_bytes = hello.get("notification_bytes_emitted")
        if not isinstance(identity, str) or not identity:
            raise SessionError("bridge hello requires adapter_identity")
        if not isinstance(maximum, int) or maximum <= 20:
            raise SessionError("bridge hello has invalid maximum_write_value_length")
        if serial is not None and not isinstance(serial, str):
            raise SessionError("bridge hello has invalid bench_reader_serial")
        if not isinstance(initially_ready, bool):
            raise SessionError("bridge hello initially_ready must be boolean")
        if observed_version is None:
            self.observed_platinum_version = None
        else:
            try:
                self.observed_platinum_version = PlatinumVersion(observed_version)
            except ValueError as exc:
                raise SessionError("bridge hello has invalid platinum_version") from exc
        if not isinstance(notification_bytes, bool):
            raise SessionError("bridge hello notification capability must be boolean")
        self.adapter_identity = identity
        self.maximum_write_value_length = maximum
        self.bench_reader_serial = serial
        self.notification_bytes_emitted = notification_bytes
        self._ready = initially_ready
        self._closed = False
        self._close_requested = False

    @property
    def can_write_without_response(self) -> bool:
        return self._ready

    def write_frame(self, frame: bytes, *, purpose: str) -> bool:
        if self._closed or self._close_requested:
            raise SessionError("bridge write attempted after close")
        if not self._ready:
            raise SessionError("bridge write attempted without readiness")
        if len(frame) > self.maximum_write_value_length:
            raise SessionError("bridge write exceeds maximum_write_value_length")
        self._write_document(
            {
                "event": "write-frame",
                "purpose": purpose,
                "length": len(frame),
                "hex": frame.hex(),
            }
        )
        self._ready = False
        # Generic JSON-lines requires a later writer-ready confirmation.
        return False

    def close(self) -> None:
        if self._closed or self._close_requested:
            return
        self._write_document({"op": "disconnect", "id": "generic-disconnect-1"})
        self._close_requested = True
        self._ready = False

    def next_event(self) -> BridgeEvent:
        document = self._read_document()
        event = document.get("event")
        if event == BridgeEventKind.DESCRIPTOR_ENABLED.value:
            return BridgeEvent(BridgeEventKind.DESCRIPTOR_ENABLED)
        if event == BridgeEventKind.WRITER_READY.value:
            if self._closed or self._close_requested:
                raise SessionError("writer-ready received after bridge close")
            self._ready = True
            return BridgeEvent(BridgeEventKind.WRITER_READY)
        if event == BridgeEventKind.DISCONNECTED.value:
            self._closed = True
            self._ready = False
            return BridgeEvent(BridgeEventKind.DISCONNECTED)
        if event == BridgeEventKind.INBOUND_FRAME.value:
            encoded = document.get("hex")
            if not isinstance(encoded, str):
                raise SessionError("inbound-frame requires hex")
            try:
                frame = bytes.fromhex(encoded)
            except ValueError as exc:
                raise SessionError("inbound-frame hex is invalid") from exc
            return BridgeEvent(BridgeEventKind.INBOUND_FRAME, frame)
        raise SessionError(f"unknown JSON-lines bridge event {event!r}")

    def _read_document(self) -> dict[str, Any]:
        line = self._source.readline()
        if line == "":
            raise EOFError("JSON-lines bridge closed")
        try:
            document = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SessionError("invalid JSON-lines bridge document") from exc
        if not isinstance(document, dict):
            raise SessionError("JSON-lines bridge document must be an object")
        return document

    def _write_document(self, document: dict[str, Any]) -> None:
        self._sink.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
        self._sink.flush()


def _decode_canonical_base64(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise SessionError(f"{field} must be non-empty canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SessionError(f"{field} is not canonical base64") from exc
    if not raw or base64.b64encode(raw).decode("ascii") != value:
        raise SessionError(f"{field} is not canonical base64")
    return raw


def _platinum_version_from_bridge_metadata(value: Any) -> PlatinumVersion:
    mapping = {
        1: PlatinumVersion.V1,
        2: PlatinumVersion.V2,
        3: PlatinumVersion.V3,
        PlatinumVersion.V1.value: PlatinumVersion.V1,
        PlatinumVersion.V2.value: PlatinumVersion.V2,
        PlatinumVersion.V3.value: PlatinumVersion.V3,
    }
    try:
        return mapping[value]
    except (KeyError, TypeError) as exc:
        raise SessionError("Swift bridge platinum_version is invalid") from exc


class SwiftBridgeJsonLinesTransport:
    """Native adapter for ``macos_xe360_bridge.swift``'s JSON-lines schema.

    Construction consumes and validates the ordered ``profile_verified``,
    ``subscribed``, and ``ready`` events. One command credit exists after
    readiness. A write consumes it; only a matching ``write_submitted`` event
    restores exactly one credit. ``write_queued`` never restores credit.
    """

    def __init__(
        self,
        source: TextIO,
        sink: TextIO,
        *,
        bench_reader_serial: str | None = None,
    ) -> None:
        self._source = source
        self._sink = sink
        profile = self._read_lifecycle_event("profile_verified")
        subscribed = self._read_lifecycle_event("subscribed")
        ready = self._read_lifecycle_event("ready")

        mode = profile.get("mode")
        ready_mode = ready.get("mode")
        if mode != ready_mode or mode not in ("dry-run", "live"):
            raise SessionError("Swift bridge mode metadata is missing or inconsistent")
        self.adapter_mode = (
            AdapterMode.SYNTHETIC if mode == "dry-run" else AdapterMode.LIVE
        )
        self.adapter_identity = "macos-xe360-swift-bridge"
        self.bench_reader_serial = bench_reader_serial

        maximum = profile.get("maximum_write_without_response")
        ready_maximum = ready.get("maximum_write_without_response")
        if not isinstance(maximum, int) or maximum <= 20 or ready_maximum != maximum:
            raise SessionError("Swift bridge WNR maximum is missing or inconsistent")
        self.maximum_write_value_length = maximum

        profile_version = profile.get("platinum_version")
        ready_version = ready.get("platinum_version")
        self.observed_platinum_version = _platinum_version_from_bridge_metadata(
            profile_version
        )
        if (
            _platinum_version_from_bridge_metadata(ready_version)
            is not self.observed_platinum_version
        ):
            raise SessionError("Swift bridge platinum_version metadata is inconsistent")

        if subscribed.get("local_cccd_completion") is not True:
            raise SessionError("Swift bridge did not confirm local subscription")
        if subscribed.get("rx_notification") is not False:
            raise SessionError("Swift bridge subscribed event is not local-only")
        if ready.get("stdin_commands_enabled") is not True:
            raise SessionError("Swift bridge did not enable stdin commands")
        profile_notification_bytes = profile.get("notification_bytes_emitted")
        notification_bytes = ready.get("notification_bytes_emitted")
        if not isinstance(profile_notification_bytes, bool) or not isinstance(
            notification_bytes, bool
        ):
            raise SessionError("Swift bridge notification byte capability is missing")
        if notification_bytes is not profile_notification_bytes:
            raise SessionError("Swift bridge notification capability is inconsistent")
        self.notification_bytes_emitted = notification_bytes

        self._ready = True
        self._startup_event_pending = True
        self._closed = False
        self._close_requested = False
        self._next_identifier = 1
        self._awaiting_write_id: str | None = None
        self._awaiting_frame_length: int | None = None
        self._write_was_queued = False
        self._disconnect_id: str | None = None

    @property
    def can_write_without_response(self) -> bool:
        return (
            self._ready
            and not self._closed
            and not self._close_requested
            and self._awaiting_write_id is None
        )

    def write_frame(self, frame: bytes, *, purpose: str) -> bool:
        del purpose  # Purpose belongs in secret-safe Python audit metadata only.
        if not self.can_write_without_response:
            raise SessionError("Swift bridge write attempted without command credit")
        if not isinstance(frame, bytes) or not frame:
            raise SessionError("Swift bridge frame must be non-empty bytes")
        if len(frame) > self.maximum_write_value_length:
            raise SessionError("Swift bridge frame exceeds negotiated WNR maximum")
        identifier = self._new_identifier("w")
        encoded = base64.b64encode(frame).decode("ascii")
        self._write_document(
            {"op": "write", "id": identifier, "frame_b64": encoded}
        )
        self._awaiting_write_id = identifier
        self._awaiting_frame_length = len(frame)
        self._write_was_queued = False
        self._ready = False
        return False

    def close(self) -> None:
        if self._closed or self._close_requested:
            return
        identifier = self._new_identifier("d")
        self._write_document({"op": "disconnect", "id": identifier})
        self._disconnect_id = identifier
        self._close_requested = True
        self._ready = False

    def next_event(self) -> BridgeEvent:
        if self._startup_event_pending:
            self._startup_event_pending = False
            return BridgeEvent(BridgeEventKind.DESCRIPTOR_ENABLED)
        while True:
            document = self._read_document()
            event = document.get("event")
            if event == "write_queued":
                self._validate_current_write_event(document, event)
                if self._write_was_queued:
                    raise SessionError("duplicate Swift bridge write_queued event")
                self._write_was_queued = True
                self._ready = False
                return BridgeEvent(BridgeEventKind.WRITE_QUEUED)
            if event == "write_submitted":
                self._validate_current_write_event(document, event)
                self._awaiting_write_id = None
                self._awaiting_frame_length = None
                self._write_was_queued = False
                self._ready = True
                return BridgeEvent(BridgeEventKind.WRITER_READY)
            if event == "notification":
                if document.get("rx_notification") is not True or document.get(
                    "local_cccd_completion"
                ) is not False:
                    raise SessionError("Swift bridge notification metadata is invalid")
                frame = _decode_canonical_base64(
                    document.get("frame_b64"), field="notification.frame_b64"
                )
                length = document.get("frame_length")
                if length != len(frame):
                    raise SessionError("Swift bridge notification length mismatch")
                if len(frame) > self.maximum_write_value_length:
                    raise SessionError("Swift bridge notification exceeds value cap")
                return BridgeEvent(BridgeEventKind.INBOUND_FRAME, frame)
            if event == "disconnect_requested":
                if self._disconnect_id is None or document.get("id") != self._disconnect_id:
                    raise SessionError("Swift bridge disconnect correlation mismatch")
                continue
            if event == "disconnected":
                self._closed = True
                self._ready = False
                self._awaiting_write_id = None
                self._awaiting_frame_length = None
                return BridgeEvent(BridgeEventKind.DISCONNECTED)
            if event in {
                "command_error",
                "error",
                "notification_error",
                "write_dropped",
                "stdin_closed",
            }:
                raise SessionError(f"Swift bridge transport event {event!r}")
            raise SessionError(f"unexpected Swift bridge event {event!r}")

    def _validate_current_write_event(
        self, document: dict[str, Any], event: str
    ) -> None:
        expected = self._awaiting_write_id
        if expected is None:
            raise SessionError(f"duplicate or unsolicited Swift bridge {event} event")
        if document.get("id") != expected:
            raise SessionError(f"out-of-order Swift bridge {event} id")
        if document.get("frame_length") != self._awaiting_frame_length:
            raise SessionError(f"Swift bridge {event} frame length mismatch")

    def _new_identifier(self, prefix: str) -> str:
        identifier = f"{prefix}-{self._next_identifier:08d}"
        self._next_identifier += 1
        return identifier

    def _read_document(self) -> dict[str, Any]:
        line = self._source.readline()
        if line == "":
            raise EOFError("Swift bridge stdout closed")
        try:
            document = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SessionError("invalid Swift bridge JSON document") from exc
        if not isinstance(document, dict):
            raise SessionError("Swift bridge event must be a JSON object")
        return document

    def _read_lifecycle_event(self, expected: str) -> dict[str, Any]:
        diagnostics = {
            "state",
            "bluetooth_state",
            "scan_observation",
            "target_located",
        }
        while True:
            document = self._read_document()
            event = document.get("event")
            if event == expected:
                return document
            if event in diagnostics:
                continue
            if event in {"error", "disconnected", "stdin_closed"}:
                raise SessionError(
                    f"Swift bridge terminated during initialization: {event!r}"
                )
            raise SessionError(
                f"Swift bridge lifecycle event {expected!r} is missing or out of order"
            )

    def _write_document(self, document: dict[str, Any]) -> None:
        self._sink.write(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self._sink.flush()


def run_json_lines_session(
    transport: Any,
    orchestrator: PlatinumSessionOrchestrator,
    *,
    maximum_events: int = 10_000,
) -> SessionState:
    """Consume bridge events until terminal state, EOF, or a bounded limit."""

    if orchestrator.transport is not transport:
        raise SessionError("orchestrator and JSON-lines transport do not match")
    try:
        for _ in range(maximum_events):
            if orchestrator.state in (SessionState.FINISHED, SessionState.FAILED):
                return orchestrator.state
            orchestrator.process_bridge_event(transport.next_event())
    except EOFError:
        orchestrator.abort("transport-eof")
        raise
    except Exception:
        orchestrator.abort("transport-event-error")
        raise
    orchestrator.abort("transport-event-limit")
    raise SessionError("JSON-lines event limit exceeded")
