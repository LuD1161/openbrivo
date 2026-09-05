"""Small, authorization-gated Mac-native XE360 provisioning workflow.

The normal live path needs only Brivo/Firebase credentials held in an
owner-only input file (or a password prompt) and an explicit acknowledgement.
It generates a P-256 identity, discovers tenant-scoped IDs through authenticated
APIs, verifies the signed BLE_PLATINUM response, and exports a local bundle.
Advanced overrides never relax fixed-host, TLS, or signature-verification gates.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import http.client
import json
import os
import ssl
import stat
import uuid
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

from .app_config_resolver import (
    AppConfigResolutionError,
    AppConfigResolver,
    ResolvedAppConfig,
    cache_origin_keys_from_bootstrap_response,
    default_resources_root,
    origin_key_bootstrap_request,
)
from .mac_provisioning_material import (
    PersistentDeviceIdentity,
    build_maa_authorization_proof,
    verify_and_extract_ble_platinum_payload,
    write_verified_provisioned_bundle,
)
from .private_files import posix_permissions_are_private
from .provisioning_support import (
    AllowedRoute,
    FixedRouteTemplate,
    GuardedHttpRequest,
    GuardedHttpResponse,
    GuardedHttpsClient,
    HttpAllowlist,
    ProvisioningRecorder,
    RawEvidenceConsent,
    RawHttpEvidenceSink,
    canonical_json_body,
)

STAGES = (
    "firebase_auth",
    "firebase_refresh",
    "brivo_pass_rtdb",
    "brivo_allegion_tokens",
    "device_registration",
    "account_selection",
    "connected_account",
    "rights",
    "access_payload",
    "bundle_export",
)
LIVE_ACK = "I_ACKNOWLEDGE_AUTHORIZED_PROVISIONING"
CAPTURE_ACK = "I_ACKNOWLEDGE_SECRET_BEARING_CAPTURE"
ANDROID_PACKAGE = "com.brivo.pass"
ANDROID_CERT_SHA1 = "755739e38803fb04a8174bc82478b9dcc3176f78"
BRIVO_OAUTH_CLIENT_SECRETS = {
    "1adda5c3-ef20-4af0-b8e6-12ed8c32fa74": "yttSd55maRLOjlEtYYRIIfb4MG3W2uuZ",
    "d510da70-b688-45c6-aade-db2127e05b45": "3twsg4LzZ82msy507CAWqqOsEYgzwZWe",
}
_APPROVED_HOSTS = frozenset(
    {
        "www.googleapis.com",
        "securetoken.googleapis.com",
        "auth.brivo.com",
        "auth.eu.brivo.com",
        "api.allegion.com",
        "us-central1-pass-prod.cloudfunctions.net",
        "europe-west1-pass-prod.cloudfunctions.net",
        "pass-prod.firebaseio.com",
        "pass-prod-eu-default-rtdb.europe-west1.firebasedatabase.app",
    }
)
_ROUTES = {
    "firebase-password": (
        "POST",
        frozenset({"www.googleapis.com"}),
        "/identitytoolkit/v3/relyingparty/verifyPassword?key=",
    ),
    "firebase-refresh": (
        "POST",
        frozenset({"securetoken.googleapis.com"}),
        "/v1/token?key=",
    ),
    "brivo-pass": (
        "GET",
        frozenset(
            {
                "us-central1-pass-prod.cloudfunctions.net",
                "europe-west1-pass-prod.cloudfunctions.net",
            }
        ),
        "/passV2",
    ),
    "rtdb-user": (
        "GET",
        frozenset(
            {
                "pass-prod.firebaseio.com",
                "pass-prod-eu-default-rtdb.europe-west1.firebasedatabase.app",
            }
        ),
        "/users/",
    ),
    "brivo-allegion-token": (
        "POST",
        frozenset({"auth.brivo.com", "auth.eu.brivo.com"}),
        "/allegion/api/token",
    ),
    "brivo-refresh": (
        "POST",
        frozenset({"auth.brivo.com", "auth.eu.brivo.com"}),
        "/oauth/token?",
    ),
    "accesshub-device": (
        "POST",
        frozenset({"api.allegion.com"}),
        "/mobileaccess/app/api/mobiledevices",
    ),
    "accesshub-account": (
        "POST",
        frozenset({"api.allegion.com"}),
        "/mobileaccess/app/api/accounts",
    ),
    "accesshub-connected-read": (
        "GET",
        frozenset({"api.allegion.com"}),
        "/mobileaccess/app/api/accounts/",
    ),
    "accesshub-connected-create": (
        "POST",
        frozenset({"api.allegion.com"}),
        "/mobileaccess/app/api/accounts/",
    ),
    "accesshub-rights": (
        "GET",
        frozenset({"api.allegion.com"}),
        "/mobileaccess/app/api/accounts/",
    ),
    "accesshub-payload": (
        "POST",
        frozenset({"api.allegion.com"}),
        "/mobileaccess/app/api/accounts/",
    ),
    "origin-bootstrap": (
        "GET",
        frozenset({"api.allegion.com"}),
        "/origin/publickeys/",
    ),
}
_HTTP_TEMPLATES = tuple(
    FixedRouteTemplate(name=name, method=method, hosts=hosts, path_prefix=prefix)
    for name, (method, hosts, prefix) in _ROUTES.items()
)


class ProvisioningError(RuntimeError):
    pass


def _owner_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProvisioningError("private input is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not posix_permissions_are_private(metadata)
    ):
        raise ProvisioningError("private input must be an owner-only regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ProvisioningError("private input is unreadable") from exc


def _canonical_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ProvisioningError(f"{field} must be a canonical UUID")
    try:
        normalized = str(uuid.UUID(value))
    except (TypeError, ValueError) as exc:
        raise ProvisioningError(f"{field} must be a canonical UUID") from exc
    if not hmac.compare_digest(value, normalized):
        raise ProvisioningError(f"{field} must be lowercase canonical UUID")
    return normalized


def _load_inputs(args: argparse.Namespace) -> dict[str, Any]:
    values: dict[str, Any] = {}
    if args.input_file is not None:
        try:
            values = json.loads(_owner_file(args.input_file).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProvisioningError("input file must be owner-only JSON") from exc
    if not isinstance(values, dict):
        raise ProvisioningError("input file must contain a JSON object")
    for key, value in tuple(values.items()):
        if isinstance(value, str) and value.startswith("env:"):
            variable = value[4:]
            if not variable or variable not in os.environ:
                raise ProvisioningError("referenced environment input is unavailable")
            values[key] = os.environ[variable]
    return values


def _value(values: dict[str, Any], key: str, *, prompt: bool = False) -> str:
    value = values.get(key)
    if isinstance(value, str) and value:
        return value
    if prompt:
        value = input("Firebase email: ").strip() if key == "firebase_email" else getpass.getpass(f"{key}: ")
        if value:
            return value
    raise ProvisioningError(f"missing required credential or approved configuration: {key}")


def _route(name: str, method: str, host: str, path: str) -> AllowedRoute:
    expected = _ROUTES.get(name)
    if expected is None:
        raise ProvisioningError("unknown fixed HTTPS route")
    expected_method, allowed_hosts, path_prefix = expected
    if (
        method != expected_method
        or host not in _APPROVED_HOSTS
        or host not in allowed_hosts
        or not path.startswith(path_prefix)
        or any(fragment in path for fragment in ("..", "#", "\\"))
    ):
        raise ProvisioningError("unsafe HTTPS route")
    return AllowedRoute(name=name, method=method, host=host, path=path)


def _json(response: Any, stage: str) -> Any:
    try:
        return json.loads(response.body.decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvisioningError(f"{stage} returned non-JSON data") from exc


def _path_value(value: Any, path: tuple[str, ...]) -> Any:
    for item in path:
        if not isinstance(value, dict):
            return None
        value = value.get(item)
    return value


def _discover_brivo_token(value: Any) -> str | None:
    """Accept only explicit Brivo-token fields from authenticated app responses."""

    for path in (
        ("brivo_access_token",),
        ("brivoAccessToken",),
        ("brivo", "access_token"),
        ("brivo", "accessToken"),
        ("tokens", "brivo_access_token"),
        ("tokens", "brivoAccessToken"),
    ):
        candidate = _path_value(value, path)
        if isinstance(candidate, str) and candidate:
            return candidate
    credentials = value.get("credentials") if isinstance(value, dict) else None
    if isinstance(credentials, dict):
        for credential in credentials.values():
            if not isinstance(credential, dict) or credential.get("hasAllegionBleCredentials") is not True:
                continue
            token_credential = credential.get("tokenCredential")
            candidate = (
                token_credential.get("accessToken")
                if isinstance(token_credential, dict)
                else None
            )
            if isinstance(candidate, str) and candidate:
                return candidate
    return None


def _discover_brivo_refresh_token(value: Any) -> str | None:
    credentials = value.get("credentials") if isinstance(value, dict) else None
    if not isinstance(credentials, dict):
        return None
    for credential in credentials.values():
        if not isinstance(credential, dict) or credential.get("hasAllegionBleCredentials") is not True:
            continue
        token_credential = credential.get("tokenCredential")
        candidate = (
            token_credential.get("refreshToken")
            if isinstance(token_credential, dict)
            else None
        )
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _oauth_client_for_refresh_token(token: str) -> tuple[str, str]:
    pieces = token.split(".")
    if len(pieces) != 3:
        raise ProvisioningError("Brivo refresh token is not a supported JWT")
    try:
        payload = pieces[1] + "=" * (-len(pieces[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (UnicodeEncodeError, ValueError, json.JSONDecodeError) as exc:
        raise ProvisioningError("Brivo refresh token claims are invalid") from exc
    client_id = claims.get("client_id") if isinstance(claims, dict) else None
    secret = BRIVO_OAUTH_CLIENT_SECRETS.get(client_id)
    if not isinstance(client_id, str) or secret is None:
        raise ProvisioningError("Brivo refresh token has an unapproved client_id")
    return client_id, secret


def _jwt_claim_uuid(token: Any, names: Iterable[str], field: str) -> str | None:
    """Read a UUID routing hint only from a just-authenticated TLS response."""

    if not isinstance(token, str):
        return None
    pieces = token.split(".")
    if len(pieces) != 3:
        return None
    try:
        encoded = pieces[1] + "=" * (-len(pieces[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")))
    except (UnicodeEncodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    for name in names:
        if name not in claims:
            continue
        try:
            return _canonical_uuid(claims[name], field)
        except ProvisioningError:
            return None
    return None


def _direct_uuid(value: Any, names: Iterable[str], field: str) -> str | None:
    if not isinstance(value, dict):
        return None
    for name in names:
        if name not in value:
            continue
        try:
            return _canonical_uuid(value[name], field)
        except ProvisioningError:
            return None
    return None


def _lock_ids_from_metadata(value: Any) -> list[str]:
    """Extract only documented lock-id shapes from an authorized pass/right."""

    found: list[str] = []
    seen: set[str] = set()

    def add(candidate: Any) -> None:
        if isinstance(candidate, str) and candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)

    def add_list(candidate: Any) -> None:
        if isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, str):
                    add(item)
                elif isinstance(item, dict):
                    add(item.get("lockId"))
                    add(item.get("lock_id"))
                    add(item.get("id"))

    def visit(node: Any, depth: int) -> None:
        if depth > 3:
            return
        if isinstance(node, str) and node[:1] in ("{", "[") and len(node) <= 65536:
            try:
                visit(json.loads(node), depth + 1)
            except json.JSONDecodeError:
                return
        elif isinstance(node, dict):
            add_list(node.get("lockIds"))
            add_list(node.get("lock_ids"))
            add_list(node.get("locks"))
            add_list(node.get("locksStatus"))
            for name in ("attributes", "metadata", "passMetadata", "lockMetadata"):
                if name in node:
                    visit(node[name], depth + 1)

    visit(value, 0)
    return found


def _payload_types(right: dict[str, Any]) -> set[str]:
    values = right.get("payloadTypes")
    if not isinstance(values, list):
        return set()
    types: set[str] = set()
    for value in values:
        if isinstance(value, str):
            types.add(value)
        elif isinstance(value, dict) and isinstance(value.get("payloadType"), str):
            types.add(value["payloadType"])
    return types


def _compatible_right(right: Any, connected_account_id: str) -> bool:
    return (
        isinstance(right, dict)
        and "BLE_Platinum" in _payload_types(right)
        and right.get("connectedAccountId") in (None, connected_account_id)
        and isinstance(right.get("id"), str)
    )


def _opaque_choice(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _merge_config(args: argparse.Namespace, values: dict[str, Any], config: ResolvedAppConfig) -> None:
    """Apply non-printed local configuration and optional advanced overrides."""

    for name, value in {
        "firebase_web_api_key": config.firebase_web_api_key,
        "allegion_subscription_key": config.allegion_subscription_key,
        "integration_id": config.integration_id,
    }.items():
        if value and not values.get(name):
            values[name] = value
    for field in ("device_id", "account_id", "connected_account_id"):
        override = getattr(args, field)
        if override is not None:
            values[field] = override
    if args.integration_id is not None:
        values["integration_id"] = args.integration_id
    if args.access_right_id is not None:
        values["access_right_id"] = args.access_right_id
    if args.lock_id:
        values["lock_ids"] = list(args.lock_id)
    if args.origin_key_0_file is None:
        args.origin_key_0_file = config.origin_key_0_file
    if args.origin_key_1_file is None:
        args.origin_key_1_file = config.origin_key_1_file
    if args.bundle_destination is None:
        args.bundle_destination = args.run_dir / "xe360-provisioned-bundle"


class Workflow:
    def __init__(
        self,
        args: argparse.Namespace,
        values: dict[str, Any],
        config: ResolvedAppConfig,
        recorder: ProvisioningRecorder,
        raw: RawHttpEvidenceSink | None,
        rights_choice_callback: Any = None,
    ):
        self.args = args
        self.values = values
        self.config = config
        self.recorder = recorder
        self.raw = raw
        self.rights_choice_callback = rights_choice_callback
        self.state: dict[str, Any] = {}
        self.identity: PersistentDeviceIdentity | None = None
        self.client = GuardedHttpsClient(
            HttpAllowlist(_HTTP_TEMPLATES), timeout_seconds=args.timeout
        )

    @property
    def accesshub_host(self) -> str:
        if self.config.accesshub_host != "api.allegion.com":
            raise ProvisioningError("approved native configuration has an unexpected AccessHub host")
        return self.config.accesshub_host

    def _request(
        self,
        stage: str,
        name: str,
        method: str,
        host: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> Any:
        response = self.client.send(
            GuardedHttpRequest(
                route=_route(name, method, host, path),
                headers=headers or {},
                body=body,
            ),
            recorder=self.recorder,
            stage=stage,
            raw_evidence=self.raw,
        )
        if not 200 <= response.status < 300:
            detail = ""
            try:
                error = json.loads(response.body.decode("utf-8"))
                title = error.get("title") if isinstance(error, dict) else None
                if isinstance(title, str) and title:
                    detail = ": " + title[:200]
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            raise ProvisioningError(f"{stage} received HTTP {response.status}{detail}")
        return response

    def run(self) -> None:
        # Authenticated state is intentionally never resumed or skipped.
        for stage in STAGES:
            self.recorder.start(stage)
            try:
                if self.args.dry_run:
                    self.recorder.complete(stage, "dry-run: no network or device operation")
                    continue
                getattr(self, stage)()
                self.recorder.complete(stage, "completed")
            except Exception as exc:
                self.recorder.fail(stage, "workflow-error", type(exc).__name__)
                raise

    def firebase_auth(self) -> None:
        supplied = self.values.get("firebase_id_token")
        if isinstance(supplied, str) and supplied:
            self.state["firebase_id_token"] = supplied
            if isinstance(self.values.get("firebase_uid"), str):
                self.state["firebase_uid"] = self.values["firebase_uid"]
            return
        body = canonical_json_body(
            {
                "email": _value(self.values, "firebase_email", prompt=self.args.prompt_credentials),
                "password": _value(self.values, "firebase_password", prompt=self.args.prompt_credentials),
                "returnSecureToken": True,
                "clientType": "CLIENT_TYPE_ANDROID",
            }
        )
        response = self._request(
            "firebase_auth",
            "firebase-password",
            "POST",
            self.config.firebase_host,
            "/identitytoolkit/v3/relyingparty/verifyPassword?key="
            + quote(_value(self.values, "firebase_web_api_key"), safe=""),
            {
                "content-type": "application/json",
                "x-android-package": ANDROID_PACKAGE,
                "x-android-cert": ANDROID_CERT_SHA1,
            },
            body,
        )
        data = _json(response, "firebase_auth")
        if not isinstance(data, dict):
            raise ProvisioningError("Firebase authentication response must be an object")
        self.state.update(
            firebase_id_token=data.get("idToken"),
            firebase_refresh_token=data.get("refreshToken"),
            firebase_uid=data.get("localId"),
        )
        if not all(
            isinstance(self.state[name], str) and self.state[name]
            for name in ("firebase_id_token", "firebase_refresh_token", "firebase_uid")
        ):
            raise ProvisioningError("Firebase authentication response omitted a token or user ID")

    def firebase_refresh(self) -> None:
        token = self.state.get("firebase_refresh_token") or self.values.get("firebase_refresh_token")
        if not isinstance(token, str) or not token:
            if isinstance(self.state.get("firebase_id_token"), str):
                return  # Deliberate short-lived ID-token override.
            raise ProvisioningError("Firebase refresh token is unavailable")
        response = self._request(
            "firebase_refresh",
            "firebase-refresh",
            "POST",
            self.config.refresh_host,
            "/v1/token?key=" + quote(_value(self.values, "firebase_web_api_key"), safe=""),
            {
                "content-type": "application/x-www-form-urlencoded",
                "x-android-package": ANDROID_PACKAGE,
                "x-android-cert": ANDROID_CERT_SHA1,
            },
            ("grant_type=refresh_token&refresh_token=" + quote(token, safe="")).encode("ascii"),
        )
        data = _json(response, "Firebase refresh")
        if not isinstance(data, dict) or not isinstance(data.get("id_token"), str):
            raise ProvisioningError("Firebase refresh response omitted id_token")
        self.state["firebase_id_token"] = data["id_token"]
        self.state["firebase_refresh_token"] = data.get("refresh_token", token)

    def brivo_pass_rtdb(self) -> None:
        if all(
            isinstance(self.values.get(name), str) and self.values[name]
            for name in ("allegion_id_token", "allegion_access_token")
        ):
            return
        firebase_token = self.state.get("firebase_id_token")
        if not isinstance(firebase_token, str) or not firebase_token:
            raise ProvisioningError("Firebase token is unavailable for authorized Brivo discovery")
        pass_response = self._request(
            "brivo_pass_rtdb",
            "brivo-pass",
            "GET",
            self.config.brivo_pass_host,
            "/passV2",
            {"id_token": firebase_token},
        )
        try:
            pass_result = pass_response.body.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ProvisioningError("Brivo pass refresh returned invalid text") from exc
        if pass_result != "Updated pass":
            raise ProvisioningError("Brivo pass refresh returned an unexpected response")
        explicit = self.values.get("brivo_access_token")
        if isinstance(explicit, str) and explicit:
            self.state["brivo_access_token"] = explicit
            return
        uid = self.state.get("firebase_uid") or self.values.get("firebase_uid")
        if not isinstance(uid, str) or not uid:
            raise ProvisioningError("authorized Firebase response did not supply a user ID for Brivo discovery")
        rtdb_metadata = _json(
            self._request(
                "brivo_pass_rtdb",
                "rtdb-user",
                "GET",
                self.config.rtdb_host,
                "/users/" + quote(uid, safe="") + ".json?auth=" + quote(firebase_token, safe=""),
            ),
            "Brivo RTDB",
        )
        self.state["pass_metadata"] = rtdb_metadata
        self.state["rtdb_metadata"] = rtdb_metadata
        token = _discover_brivo_token(rtdb_metadata)
        if not token:
            refresh_token = _discover_brivo_refresh_token(rtdb_metadata)
            if not refresh_token:
                raise ProvisioningError(
                    "the authenticated Brivo pass/RTDB response did not expose a Brivo refresh token under the approved app schema"
                )
            client_id, client_secret = _oauth_client_for_refresh_token(refresh_token)
            basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            refreshed = _json(
                self._request(
                    "brivo_pass_rtdb",
                    "brivo-refresh",
                    "POST",
                    self.config.brivo_auth_host,
                    "/oauth/token?grant_type=refresh_token&refresh_token="
                    + quote(refresh_token, safe=""),
                    {"authorization": "Basic " + basic},
                ),
                "Brivo OAuth refresh",
            )
            token = refreshed.get("access_token") if isinstance(refreshed, dict) else None
            if not isinstance(token, str) or not token:
                raise ProvisioningError("Brivo OAuth refresh omitted access_token")
            self.state["brivo_refresh_token"] = refreshed.get("refresh_token", refresh_token)
        self.state["brivo_access_token"] = token

    def brivo_allegion_tokens(self) -> None:
        if all(
            isinstance(self.values.get(name), str) and self.values[name]
            for name in ("allegion_id_token", "allegion_access_token")
        ):
            self.state["allegion_id_token"] = self.values["allegion_id_token"]
            self.state["allegion_access_token"] = self.values["allegion_access_token"]
            return
        data = _json(
            self._request(
                "brivo_allegion_tokens",
                "brivo-allegion-token",
                "POST",
                self.config.brivo_auth_host,
                "/allegion/api/token",
                {"authorization": "Bearer " + self.state["brivo_access_token"]},
                b"",
            ),
            "Brivo Allegion token",
        )
        if not isinstance(data, dict):
            raise ProvisioningError("Brivo Allegion response must be an object")
        self.state["allegion_id_token"] = data.get("idToken")
        self.state["allegion_access_token"] = data.get("accessToken")
        if not all(
            isinstance(self.state[name], str) and self.state[name]
            for name in ("allegion_id_token", "allegion_access_token")
        ):
            raise ProvisioningError("Brivo Allegion response omitted required tokens")
        integration = _direct_uuid(data, ("integrationId", "integration_id"), "Brivo integration ID")
        integration = integration or _jwt_claim_uuid(
            self.state["allegion_id_token"],
            ("integrationId", "integration_id"),
            "Brivo integration ID",
        )
        if integration:
            self.state["integration_id"] = integration

    def _identity(self) -> PersistentDeviceIdentity:
        if self.identity is not None:
            return self.identity
        if self.args.enrollment_mode == "existing":
            if self.args.device_identity_file is None:
                raise ProvisioningError("existing device requires --device-identity-file")
            self.identity = PersistentDeviceIdentity.load_der(self.args.device_identity_file)
            return self.identity
        path = self.args.run_dir / "device-identity.der"
        self.identity = (
            PersistentDeviceIdentity.load_der(path)
            if path.exists()
            else PersistentDeviceIdentity.generate()
        )
        if not path.exists():
            self.identity.write_der(path)
        return self.identity

    def _ah_headers(self, body: bytes | None = None, auth: bool = False) -> dict[str, str]:
        identity = self._identity()
        headers = {"alle-subscription-key": _value(self.values, "allegion_subscription_key")}
        if body is not None:
            headers.update(
                {
                    "content-type": "application/json",
                    "device-signature": identity.sign_exact_bytes_lower_hex(body),
                }
            )
        if auth:
            headers["authorization"] = build_maa_authorization_proof(
                identity, self.state["device_id"]
            ).authorization_header
        return headers

    def device_registration(self) -> None:
        if self.values.get("device_id"):
            self.state["device_id"] = _canonical_uuid(self.values["device_id"], "device_id")
            return
        if self.args.enrollment_mode != "create":
            raise ProvisioningError("existing device requires --device-id")
        body = canonical_json_body({"devicePublicKey": self._identity().public_key_x963_lower_hex})
        data = _json(
            self._request(
                "device_registration", "accesshub-device", "POST", self.accesshub_host,
                "/mobileaccess/app/api/mobiledevices", self._ah_headers(body), body,
            ),
            "device registration",
        )
        self.state["device_id"] = _canonical_uuid(
            data.get("id") if isinstance(data, dict) else None,
            "device registration response ID",
        )

    def account_selection(self) -> None:
        if self.values.get("account_id"):
            self.state["account_id"] = _canonical_uuid(self.values["account_id"], "account_id")
            return
        if self.args.enrollment_mode != "create":
            raise ProvisioningError("existing device requires --account-id")
        data = _json(
            self._request(
                "account_selection", "accesshub-account", "POST", self.accesshub_host,
                "/mobileaccess/app/api/accounts", self._ah_headers(auth=True),
            ),
            "account creation",
        )
        self.state["account_id"] = _canonical_uuid(
            data.get("id") if isinstance(data, dict) else None,
            "account creation response ID",
        )

    def connected_account(self) -> None:
        if self.values.get("connected_account_id"):
            self.state["connected_account_id"] = _canonical_uuid(
                self.values["connected_account_id"], "connected_account_id"
            )
            self._request(
                "connected_account", "accesshub-connected-read", "GET", self.accesshub_host,
                "/mobileaccess/app/api/accounts/" + self.state["account_id"]
                + "/connectedaccounts/" + self.state["connected_account_id"],
                self._ah_headers(auth=True),
            )
            return
        if self.args.enrollment_mode != "create":
            raise ProvisioningError("existing device requires --connected-account-id")
        integration = self.state.get("integration_id") or self.values.get("integration_id")
        if integration is None:
            raise ProvisioningError("authenticated response omitted integration ID")
        integration = _canonical_uuid(integration, "integration_id")
        body = canonical_json_body({"idToken": self.state["allegion_id_token"]})
        data = _json(
            self._request(
                "connected_account", "accesshub-connected-create", "POST", self.accesshub_host,
                "/mobileaccess/app/api/accounts/" + self.state["account_id"]
                + "/connectedaccounts/" + integration,
                self._ah_headers(body, True), body,
            ),
            "connected-account creation",
        )
        self.state["connected_account_id"] = _canonical_uuid(
            data.get("id") if isinstance(data, dict) else None,
            "connected-account response ID",
        )

    def rights(self) -> None:
        data = _json(
            self._request(
                "rights", "accesshub-rights", "GET", self.accesshub_host,
                "/mobileaccess/app/api/accounts/" + self.state["account_id"] + "/accessrights",
                self._ah_headers(auth=True),
            ),
            "access-right discovery",
        )
        rights = data if isinstance(data, list) else data.get("rights") if isinstance(data, dict) else None
        if not isinstance(rights, list):
            raise ProvisioningError("access-right response did not contain a rights list")
        compatible = [item for item in rights if _compatible_right(item, self.state["connected_account_id"])]
        requested = self.values.get("access_right_id")
        if requested is not None:
            requested = _canonical_uuid(requested, "access_right_id")
            chosen = next(
                (item for item in compatible if isinstance(item, dict) and item.get("id") == requested),
                None,
            )
            if chosen is None:
                raise ProvisioningError("advanced access-right override is not a compatible BLE_Platinum right")
        elif len(compatible) == 1:
            chosen = compatible[0]
        elif not compatible:
            raise ProvisioningError("authenticated account has no compatible BLE_Platinum access right")
        elif self.rights_choice_callback is not None:
            chosen = self.rights_choice_callback(
                [item for item in compatible if isinstance(item, dict) and isinstance(item.get("id"), str)]
            )
            if not _compatible_right(chosen, self.state["connected_account_id"]):
                raise ProvisioningError("rights choice callback returned an incompatible access right")
        else:
            choices = ",".join(
                _opaque_choice(item["id"])
                for item in compatible
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            )
            raise ProvisioningError(
                "multiple compatible BLE_Platinum rights; select one with --access-right-id "
                "(opaque choices: " + choices + ")"
            )
        self.state["right_metadata"] = chosen
        self.state["access_right_id"] = _canonical_uuid(
            chosen.get("id") if isinstance(chosen, dict) else None,
            "selected access-right ID",
        )

    def _origin_keys(self) -> tuple[Path, Path]:
        if self.args.origin_key_0_file is not None and self.args.origin_key_1_file is not None:
            _owner_file(self.args.origin_key_0_file)
            _owner_file(self.args.origin_key_1_file)
            return self.args.origin_key_0_file, self.args.origin_key_1_file
        request_definition = origin_key_bootstrap_request()
        if request_definition.host != self.accesshub_host or request_definition.path != "/origin/publickeys/":
            raise ProvisioningError("origin-key bootstrap route differs from fixed native configuration")
        request = GuardedHttpRequest(
            route=_route("origin-bootstrap", "GET", request_definition.host, request_definition.path),
            headers={"accept": "application/json"},
        )
        self.recorder.record_http_request("access_payload", request)
        connection = http.client.HTTPSConnection(
            request_definition.host, timeout=self.args.timeout, context=ssl.create_default_context()
        )
        try:
            connection.connect()
            if connection.sock is None:
                raise ProvisioningError("TLS connection did not expose a peer certificate")
            certificate = connection.sock.getpeercert(binary_form=True)
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives.serialization import (
                    Encoding,
                    PublicFormat,
                )

                public_bytes = x509.load_der_x509_certificate(certificate).public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )
            except Exception as exc:
                raise ProvisioningError("cannot validate the configured AccessHub certificate pin") from exc
            actual_pin = "sha256/" + base64.b64encode(hashlib.sha256(public_bytes).digest()).decode("ascii")
            if not hmac.compare_digest(actual_pin, self.config.accesshub_certificate_pin):
                raise ProvisioningError("AccessHub certificate pin differs from approved native configuration")
            connection.request("GET", request_definition.path, headers=request.headers)
            raw_response = connection.getresponse()
            body = raw_response.read(65537)
            if len(body) > 65536:
                raise ProvisioningError("origin-key bootstrap response exceeds fixed limit")
            headers = {name.lower(): value for name, value in raw_response.getheaders()}
            response = GuardedHttpResponse(
                raw_response.status, headers, body, request.correlation_id, request.route
            )
        except (OSError, http.client.HTTPException) as exc:
            raise ProvisioningError("TLS-pinned origin-key bootstrap request failed") from exc
        finally:
            connection.close()
        self.recorder.record_http_response("access_payload", response)
        if not 200 <= response.status < 300:
            raise ProvisioningError(f"origin-key bootstrap received HTTP {response.status}")
        try:
            return cache_origin_keys_from_bootstrap_response(response.body, self.args.run_dir)
        except AppConfigResolutionError as exc:
            raise ProvisioningError("origin-key bootstrap response failed validation") from exc

    def access_payload(self) -> None:
        body = canonical_json_body(
            {
                "accessToken": self.state["allegion_access_token"],
                "payloadRequests": [{
                    "payloadType": "BLE_PLATINUM",
                    "mobileDevicePropertyBag": "",
                    "payloadArgs": {"MobileDevicePublicKey": self._identity().public_key_x963_lower_hex},
                }],
            }
        )
        origin_0, origin_1 = self._origin_keys()
        response = self._request(
            "access_payload", "accesshub-payload", "POST", self.accesshub_host,
            "/mobileaccess/app/api/accounts/" + self.state["account_id"] + "/accessrights/"
            + self.state["access_right_id"] + "/accessPayloads",
            self._ah_headers(body, True), body,
        )
        self.state["verified_payload"] = verify_and_extract_ble_platinum_payload(
            response.body,
            response.headers.get("alle-signatures", ""),
            (_owner_file(origin_0).decode("utf-8").strip(), _owner_file(origin_1).decode("utf-8").strip()),
            self.state["access_right_id"],
        )

    def bundle_export(self) -> None:
        advanced = self.values.get("lock_ids")
        if advanced is not None:
            if not isinstance(advanced, list) or not all(isinstance(value, str) and value for value in advanced):
                raise ProvisioningError("advanced lock override must be a nonempty string list")
            lock_ids = list(dict.fromkeys(advanced))
        else:
            lock_ids = _lock_ids_from_metadata(self.state.get("right_metadata"))
            if not lock_ids:
                lock_ids = _lock_ids_from_metadata(self.state.get("pass_metadata"))
        write_verified_provisioned_bundle(
            self.args.bundle_destination,
            self._identity(),
            self.state["verified_payload"],
            lock_ids=lock_ids,
            provisioned_public_key_x963_lower_hex=self._identity().public_key_x963_lower_hex,
        )


def parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authorized XE360 credential retrieval (dry-run by default; no BLE)")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--input-file", type=Path, help="owner-only JSON with credentials or an authorized token override")
    parser.add_argument("--prompt-credentials", action="store_true", help="prompt for missing Firebase email/password")
    parser.add_argument("--region", choices=("auto", "us", "eu"), default="auto")
    parser.add_argument("--app-config-file", type=Path, help="optional owner-only approved app configuration")
    parser.add_argument("--bundle-destination", type=Path)
    parser.add_argument("--origin-key-0-file", type=Path, help="advanced owner-only trust-key override")
    parser.add_argument("--origin-key-1-file", type=Path, help="advanced owner-only trust-key override")
    parser.add_argument("--enrollment-mode", choices=("create", "existing"), default="create")
    parser.add_argument("--device-identity-file", type=Path, help="owner-only existing device identity")
    parser.add_argument("--device-id", help="existing device ID")
    parser.add_argument("--account-id", help="existing account ID")
    parser.add_argument("--connected-account-id", help="existing connected-account ID")
    parser.add_argument("--integration-id", help="advanced configuration override")
    parser.add_argument("--access-right-id", help="select one when multiple compatible rights exist")
    parser.add_argument("--lock-id", action="append", help="advanced exported-lock override; repeatable")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--authorization-ack")
    parser.add_argument("--capture-secrets", action="store_true")
    parser.add_argument("--capture-secrets-ack")
    parser.add_argument("--capture-secrets-dir", type=Path)
    parser.add_argument("--timeout", type=int, default=20)
    return parser


def _preflight_live(args: argparse.Namespace, values: dict[str, Any]) -> None:
    errors: list[str] = []
    if not values.get("firebase_id_token"):
        for name in ("firebase_email", "firebase_password", "firebase_web_api_key"):
            if name in {"firebase_email", "firebase_password"} and args.prompt_credentials:
                continue
            if not values.get(name):
                errors.append(name)
    if not values.get("allegion_subscription_key"):
        errors.append("Allegion subscription key from approved native configuration")
    if args.enrollment_mode == "existing":
        for name in ("device_id", "account_id", "connected_account_id"):
            if not values.get(name):
                errors.append("--" + name.replace("_", "-"))
        if args.device_identity_file is None:
            errors.append("--device-identity-file")
        else:
            _owner_file(args.device_identity_file)
    if args.bundle_destination is None or not args.bundle_destination.parent.is_dir():
        errors.append("writable bundle destination parent")
    if errors:
        raise ProvisioningError("live preflight missing: " + "; ".join(dict.fromkeys(errors)))


def _open_raw_capture(args: argparse.Namespace) -> RawHttpEvidenceSink | None:
    if not args.capture_secrets:
        return None
    if args.capture_secrets_dir is None or not hmac.compare_digest(args.capture_secrets_ack or "", CAPTURE_ACK):
        raise ProvisioningError("secret capture requires --capture-secrets-dir and " + CAPTURE_ACK)
    root = args.capture_secrets_dir.resolve()
    try:
        root.relative_to(args.run_dir.resolve())
    except ValueError:
        pass
    else:
        raise ProvisioningError("secret capture directory must be outside --run-dir")
    if not root.parent.is_dir() or not posix_permissions_are_private(root.parent.stat()):
        raise ProvisioningError("secret capture parent must be an existing owner-only directory")
    return RawHttpEvidenceSink.open(args.capture_secrets_dir, RawEvidenceConsent(True, True, True))


def main() -> int:
    args = parser().parse_args()
    args.dry_run = not args.live
    if not 1 <= args.timeout <= 120:
        raise SystemExit("timeout must be 1..120 seconds")
    if args.live and not hmac.compare_digest(args.authorization_ack or "", LIVE_ACK):
        raise SystemExit("live mode requires --authorization-ack " + LIVE_ACK)
    run_preexisted = args.run_dir.exists()
    args.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.run_dir, 0o700)
    if args.live and run_preexisted and any(args.run_dir.iterdir()):
        raise SystemExit("live runs require a fresh run directory; authenticated work is not resumed")
    try:
        config = AppConfigResolver(default_resources_root(), args.run_dir, args.app_config_file).resolve(args.region)
        values = _load_inputs(args)
        _merge_config(args, values, config)
        if args.live:
            _preflight_live(args, values)
        if args.capture_secrets and args.dry_run:
            raise ProvisioningError("secret capture requires --live")
        raw = _open_raw_capture(args)
        with ProvisioningRecorder.open(args.run_dir, stages=STAGES) as recorder:
            Workflow(args, values, config, recorder, raw).run()
    except (AppConfigResolutionError, ProvisioningError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
