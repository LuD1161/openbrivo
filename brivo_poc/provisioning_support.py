"""Fail-closed transport, checkpoint, and audit primitives for provisioning."""
from __future__ import annotations

import http.client
import json
import os
import ssl
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .private_files import restrict_open_descriptor

DEFAULT_PROVISIONING_STAGES: tuple[str, ...] = ()
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class HttpGuardError(RuntimeError):
    pass


def _write_owner_only(path: Path, contents: bytes, *, append: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    descriptor = os.open(path, flags, 0o600)
    try:
        restrict_open_descriptor(descriptor)
        view = memoryview(contents)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def canonical_json_body(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AllowedRoute:
    name: str
    method: str
    host: str
    path: str

    def __post_init__(self) -> None:
        if self.method not in {"GET", "POST"} or not self.host or not self.path.startswith("/") or any(value in self.path for value in ("..", "#")):
            raise HttpGuardError("invalid HTTPS route")


@dataclass(frozen=True)
class FixedRouteTemplate:
    """A code-defined route family; never constructed from operator input."""
    name: str
    method: str
    hosts: frozenset[str]
    path_prefix: str

    def matches(self, route: AllowedRoute) -> bool:
        return route.name == self.name and route.method == self.method and route.host in self.hosts and route.path.startswith(self.path_prefix)


class HttpAllowlist:
    def __init__(self, templates: Iterable[FixedRouteTemplate]):
        self._templates = tuple(templates)
        if not self._templates:
            raise HttpGuardError("an HTTPS client requires fixed route templates")

    def require(self, route: AllowedRoute) -> None:
        if not any(template.matches(route) for template in self._templates):
            raise HttpGuardError("route is not in the fixed allowlist")


@dataclass(frozen=True)
class GuardedHttpRequest:
    route: AllowedRoute
    headers: dict[str, str]
    body: bytes | None = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(frozen=True)
class GuardedHttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    correlation_id: str
    route: AllowedRoute

    def safe_summary(self) -> dict[str, Any]:
        return {"status": self.status, "body_length": len(self.body), "correlation_id": self.correlation_id, "route": self.route.name}


@dataclass(frozen=True)
class RawEvidenceConsent:
    authorized_isolated_bench: bool
    disposable_test_credentials: bool
    acknowledge_secret_bearing_evidence: bool

    def __post_init__(self) -> None:
        if not all((self.authorized_isolated_bench, self.disposable_test_credentials, self.acknowledge_secret_bearing_evidence)):
            raise HttpGuardError("raw capture requires three explicit consent assertions")


class RawHttpEvidenceSink:
    """An opt-in isolated sink; its root must be a new owner-only directory."""
    def __init__(self, root: Path):
        self.path = root / "capture-secrets.jsonl"

    @classmethod
    def open(cls, root: Path, consent: RawEvidenceConsent) -> "RawHttpEvidenceSink":
        del consent
        root = Path(root)
        if root.exists() or root.is_symlink():
            raise HttpGuardError("raw capture root must be a distinct non-existing directory")
        root.mkdir(mode=0o700, parents=False)
        os.chmod(root, 0o700)
        sink = cls(root)
        _write_owner_only(sink.path, b"")
        return sink

    def record(self, value: dict[str, Any]) -> None:
        _write_owner_only(self.path, canonical_json_body(value) + b"\n", append=True)


class ProvisioningRecorder:
    def __init__(self, root: Path, stages: tuple[str, ...]):
        self.root = root
        self.stages = stages
        self.human = root / "provisioning.log"
        self.jsonl = root / "provisioning.jsonl"
        self.checkpoint = root / "checkpoint.json"
        self.completed_stages: set[str] = set()
        if self.checkpoint.exists():
            try:
                saved = json.loads(self.checkpoint.read_text("utf-8"))
                self.completed_stages = set(saved.get("completed", []))
            except (OSError, ValueError, TypeError) as exc:
                raise HttpGuardError("checkpoint is unreadable") from exc

    @classmethod
    def open(cls, root: Path, *, stages: tuple[str, ...] = DEFAULT_PROVISIONING_STAGES) -> "ProvisioningRecorder":
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        recorder = cls(root, stages)
        for stage in stages:
            if stage not in recorder.completed_stages:
                recorder._event(stage, "pending", "queued")
        return recorder

    def __enter__(self) -> "ProvisioningRecorder": return self
    def __exit__(self, *_: Any) -> None: self.close()
    def close(self) -> None: pass

    def _event(self, stage: str, status: str, summary: str) -> None:
        value = {"time": datetime.now(timezone.utc).isoformat(), "stage": stage, "status": status, "summary": summary}
        _write_owner_only(self.jsonl, canonical_json_body(value) + b"\n", append=True)
        _write_owner_only(self.human, f"{value['time']} {stage} {status} {summary}\n".encode(), append=True)

    def _save(self) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".checkpoint.", dir=self.root)
        try:
            restrict_open_descriptor(descriptor)
            os.write(descriptor, canonical_json_body({"completed": sorted(self.completed_stages)}) + b"\n")
            os.fsync(descriptor)
            os.close(descriptor)
            os.replace(temporary, self.checkpoint)
            os.chmod(self.checkpoint, 0o600)
        except BaseException:
            try: os.close(descriptor)
            except OSError: pass
            try: os.unlink(temporary)
            except OSError: pass
            raise

    def start(self, stage: str) -> None: self._event(stage, "in_progress", "started")
    def complete(self, stage: str, summary: str | None = None) -> None:
        self.completed_stages.add(stage); self._save(); self._event(stage, "completed", summary or "completed")
    def fail(self, stage: str, code: str, summary: str | None = None) -> None: self._event(stage, "failed", code + (":" + summary if summary else ""))
    def resume(self, stage: str, recovery_code: str) -> None: self._event(stage, "in_progress", "resume:" + recovery_code)
    def record_http_request(self, stage: str, request: GuardedHttpRequest) -> None: self._event(stage, "in_progress", "request:" + request.route.name)
    def record_http_response(self, stage: str, response: GuardedHttpResponse) -> None: self._event(stage, "in_progress", f"response:{response.status}:{response.route.name}")


class GuardedHttpsClient:
    def __init__(self, allowlist: HttpAllowlist, *, timeout_seconds: int = 20):
        self.allowlist, self.timeout_seconds = allowlist, timeout_seconds

    def send(self, request: GuardedHttpRequest, *, recorder: ProvisioningRecorder | None = None, stage: str = "http", raw_evidence: RawHttpEvidenceSink | None = None) -> GuardedHttpResponse:
        self.allowlist.require(request.route)
        if not isinstance(request.body, (bytes, type(None))): raise HttpGuardError("request body must be bytes")
        if recorder: recorder.record_http_request(stage, request)
        if raw_evidence: raw_evidence.record({"kind": "request", "method": request.route.method, "host": request.route.host, "path": request.route.path, "headers": request.headers, "body_hex": (request.body or b"").hex(), "correlation_id": request.correlation_id})
        try:
            connection = http.client.HTTPSConnection(request.route.host, timeout=self.timeout_seconds, context=ssl.create_default_context())
            connection.request(request.route.method, request.route.path, body=request.body, headers=request.headers)
            raw_response = connection.getresponse()
            body = raw_response.read(MAX_RESPONSE_BYTES + 1)
            headers = {key.lower(): value for key, value in raw_response.getheaders()}
            status = raw_response.status
            connection.close()
        except (OSError, http.client.HTTPException) as exc:
            raise HttpGuardError("verified-TLS HTTPS request failed") from exc
        if len(body) > MAX_RESPONSE_BYTES: raise HttpGuardError("response body exceeds fixed safety limit")
        response = GuardedHttpResponse(status, headers, body, request.correlation_id, request.route)
        if raw_evidence: raw_evidence.record({"kind": "response", "status": status, "headers": headers, "body_hex": body.hex(), "route": request.route.name, "correlation_id": request.correlation_id})
        if recorder: recorder.record_http_response(stage, response)
        return response
