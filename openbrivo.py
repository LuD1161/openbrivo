#!/usr/bin/env python3
"""OpenBrivo CLI — Brivo Mobile Pass login research tool.

Runs entirely on YOUR machine. Credentials you pass go directly from this
process to Google's Firebase auth and Brivo's servers over TLS. Nothing is
sent to, stored by, or proxied through any OpenBrivo infrastructure (there is
none). Tokens are written to disk only via --out (default openbrivo_tokens.json).

Recovered from Brivo Mobile Pass 4.32.0 (see ../analysis/API_AUTH_CALL_MAP.md):
    POST identitytoolkit .../verifyPassword?key=<web api key>   · email/password login
    GET  {api}/pass          · Bearer <idToken>

Examples:
    python3 openbrivo.py exchange --region US --username you@example.com --password SECRET
    python3 openbrivo.py validate --region US --token TOKEN
    python3 openbrivo.py refresh  --token REFRESH_TOKEN --region EU --firebase
"""
import argparse
import base64
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler

try:
    from .terminal_ui import BOLD, CYAN, DIM, banner, paint, prompt
except ImportError:  # pragma: no cover - exercised by the script entrypoint
    from terminal_ui import BOLD, CYAN, DIM, banner, paint, prompt

DEFAULT_TOKEN_FILE = "openbrivo_tokens.json"

CLIENTS = {
    "US": {
        "auth": "https://auth.brivo.com",
        "api": "https://pi.brivo.com/api",
        "id": "1adda5c3-ef20-4af0-b8e6-12ed8c32fa74",
        "secret": "yttSd55maRLOjlEtYYRIIfb4MG3W2uuZ",
    },
    "EU": {
        "auth": "https://auth.eu.brivo.com",
        "api": "https://pi.eu.brivo.com/api",
        "id": "d510da70-b688-45c6-aade-db2127e05b45",
        "secret": "3twsg4LzZ82msy507CAWqqOsEYgzwZWe",
    },
}

# Firebase Web API keys extracted from the APK (res/raw/{us,eu}_google_services.json)
FIREBASE_KEYS = {
    "US": "AIzaSyCnOoSRkfsWoIRQfdARd2LmTXO-WyOo-fI",
    "EU": "AIzaSyDZycLr7MnBcVI2HpltJyWXsTqvM9tSP5w",
}
FIREBASE_VERIFY_URL = (
    "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key="
)
FIREBASE_REFRESH_URL = "https://securetoken.googleapis.com/v1/token?key="
# App identity the API key is restricted to (from the APK's signing cert)
ANDROID_PACKAGE = "com.brivo.pass"
ANDROID_CERT_SHA1 = "755739e38803fb04a8174bc82478b9dcc3176f78"


def android_headers() -> dict:
    return {"X-Android-Package": ANDROID_PACKAGE, "X-Android-Cert": ANDROID_CERT_SHA1}


def mask(token: str) -> str:
    if not token:
        return "-"
    return f"{token[:8]}...{token[-4:]}" if len(token) > 18 else "*" * len(token)


def jwt_claims(token: str) -> dict | None:
    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def basic_header(region: str) -> str:
    client = CLIENTS[region]
    raw = f"{client['id']}:{client['secret']}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def http(req: urllib.request.Request) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def save_tokens(path: str, payload: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle, indent=2)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def print_token_summary(data: dict, region: str) -> None:
    access = data.get("access_token") or data.get("accessToken") or ""
    refresh = data.get("refresh_token") or data.get("refreshToken") or ""
    print(f"region         : {region}")
    print(f"access_token   : {mask(access)}")
    if refresh:
        print(f"refresh_token  : {mask(refresh)}")
    claims = jwt_claims(access)
    if claims:
        import datetime

        if claims.get("exp"):
            exp = datetime.datetime.fromtimestamp(claims["exp"])
            state = "EXPIRED" if exp < datetime.datetime.now() else "valid"
            print(f"jwt expiry     : {exp} ({state})")
        if claims.get("sub"):
            print(f"jwt subject    : {claims['sub']}")
    else:
        print("jwt            : opaque token (no decodable claims)")


def cmd_exchange(args) -> int:
    username = args.username or ask("Username")
    password = args.password or ask("Password", secret=True)
    payload = json.dumps(
        {
            "email": username,
            "password": password,
            "returnSecureToken": True,
            "clientType": "CLIENT_TYPE_ANDROID",
        }
    ).encode()
    url = FIREBASE_VERIFY_URL + FIREBASE_KEYS[args.region]
    headers = {"Content-Type": "application/json", **android_headers()}
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    status, body = http(req)
    print(f"POST {FIREBASE_VERIFY_URL}<key> -> HTTP {status}")
    if status != 200:
        print(body.decode(errors="replace"), file=sys.stderr)
        return 1
    raw = json.loads(body)
    data = {
        "access_token": raw.get("idToken", ""),
        "refresh_token": raw.get("refreshToken", ""),
        "expires_in": raw.get("expiresIn", ""),
        "_provider": "firebase-email-password",
    }
    print(f"account        : {raw.get('email', username)} (localId {raw.get('localId', '?')})")
    print_token_summary(data, args.region)
    out = getattr(args, "out", None)
    if out:
        save_tokens(out, {**data, "_region": args.region})
        print(f"saved          : {out} (chmod 600)")
    if getattr(args, "reveal", False):
        print(f"\naccess_token   : {data['access_token']}")
    return 0


def cmd_refresh(args) -> int:
    if getattr(args, "firebase", False):
        url = FIREBASE_REFRESH_URL + FIREBASE_KEYS[args.region]
        body = json.dumps({"grantType": "refresh_token", "refreshToken": args.token}).encode()
        headers = {"Content-Type": "application/json", **android_headers()}
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    else:
        query = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": args.token})
        url = CLIENTS[args.region]["auth"] + "/oauth/token?" + query
        req = urllib.request.Request(url, headers={"Authorization": basic_header(args.region)}, method="POST")
    status, body = http(req)
    print(f"POST refresh -> HTTP {status}")
    if status != 200:
        print(body.decode(errors="replace"), file=sys.stderr)
        return 1
    raw = json.loads(body)
    data = {
        "access_token": raw.get("access_token") or raw.get("id_token") or raw.get("idToken") or "",
        "refresh_token": raw.get("refresh_token") or args.token,
        "_provider": "firebase" if getattr(args, "firebase", False) else "brivo-oauth",
    }
    print_token_summary(data, args.region)
    if args.out:
        save_tokens(args.out, {**data, "_region": args.region})
        print(f"saved          : {args.out} (chmod 600)")
    return 0


def cmd_validate(args) -> int:
    api = CLIENTS[args.region]["api"]
    url = api + "/pass"
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + args.token})
    status, body = http(req)
    print(f"GET {url} -> HTTP {status}")
    if status != 200:
        hint = "token rejected, expired, or wrong region" if status == 401 else "server error"
        print(f"({hint})", file=sys.stderr)
        print(body.decode(errors="replace"), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(json.loads(body), indent=2))
    else:
        print(f"key accepted; response is {len(body)} bytes (pass JSON). Re-run with --json to print it.")
    return 0


def cmd_scan(args) -> int:
    import unlock

    return unlock.scan_all_devices(args.scan_seconds)


def cmd_unlock(args) -> int:
    import unlock

    return unlock.run_unlock(args.region, args.scan_seconds, args.username, args.password)


HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "content-encoding",
               "content-length", "host", "origin", "referer", "accept-encoding"}


class UiHandler(SimpleHTTPRequestHandler):
    """Serves index.html statically and forwards API traffic to Brivo locally.

    The /forward endpoint exists only on this loopback server. It lets the page
    perform OAuth calls without CORS friction while every byte still originates
    from and terminates on your machine.
    """

    def _forward(self):  # noqa: C901
        target = self.headers.get("X-OpenBrivo-Target")
        if not target:
            self.send_error(400, "Missing X-OpenBrivo-Target header")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(target, data=body, method=self.command)
        for key, value in self.headers.items():
            if key.lower() not in HOP_HEADERS:
                req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read()
                self.send_response(resp.status)
                for key, value in resp.getheaders():
                    if key.lower() not in HOP_HEADERS:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as err:
            payload = err.read()
            self.send_response(err.code)
            self.send_header("Content-Type", err.headers.get("Content-Type", "text/plain"))
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except Exception as err:  # noqa: BLE001
            msg = f"{type(err).__name__}: {err}".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def route(self):
        if self.path == "/forward":
            self._forward()
        elif self.command == "GET":
            super().do_GET()
        else:
            self.send_error(404)

    do_GET = route
    do_POST = route

    def log_message(self, fmt, *args):
        print("[openbrivo-ui]", fmt % args)


def serve_ui(port: int) -> int:
    from http.server import ThreadingHTTPServer

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = ThreadingHTTPServer(("127.0.0.1", port), UiHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"OpenBrivo UI  ->  {url}   (Ctrl-C to stop)")
    print("Loopback only: the page's API calls are forwarded by this process;")
    print("credentials go from your machine straight to Brivo over TLS.")
    import threading
    import webbrowser

    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


def launch_ui(args) -> int:
    return serve_ui(getattr(args, "port", 8787))


def ask(prompt: str, secret: bool = False, default: str = "") -> str:
    import getpass

    suffix = f" [{default}]: " if default else ": "
    value = getpass.getpass(prompt + suffix) if secret else input(prompt + suffix)
    value = value.strip() or default
    if not value:
        print("(required)", file=sys.stderr)
        sys.exit(2)
    return value


def ask_region() -> str:
    choice = input(prompt("Region  1) US  2) EU  [1]: ")).strip()
    return "EU" if choice == "2" else "US"


def interactive() -> int:
    banner()
    print(paint("  Everything runs locally; credentials go directly to Brivo over TLS.\n", DIM))
    print(f"  {paint('1', BOLD, CYAN)}  🔑  Log in for an access key")
    print(f"  {paint('2', BOLD, CYAN)}  ✓   Validate an access token")
    print(f"  {paint('3', BOLD, CYAN)}  ↻   Refresh an access token")
    print(f"  {paint('4', BOLD, CYAN)}  🔓  Unlock an authorized XE360 lock")
    print(f"  {paint('5', BOLD, CYAN)}  ◌   Scan nearby BLE devices")
    print(f"  {paint('6', BOLD, CYAN)}  ◫   Launch the local web UI")
    action = input(prompt("\n  Choose [1-6, default 1]: ")).strip() or "1"

    if action == "6":
        return launch_ui(argparse.Namespace(port=8787))
    if action == "5":
        import unlock

        return unlock.scan_all_devices(12)
    if action == "4":
        import unlock

        region = ask_region()
        return unlock.run_unlock(region, 12)

    region = ask_region()
    if action == "1":
        username = ask("Username")
        password = ask("Password", secret=True)
        out = input(f"Save access key to file? path [{DEFAULT_TOKEN_FILE}]: ").strip()
        ns = argparse.Namespace(region=region, username=username, password=password,
                                out=out or DEFAULT_TOKEN_FILE, reveal=False)
        print()
        return cmd_exchange(ns)
    if action == "2":
        token = ask("Access token", secret=True)
        show = input("Print full pass JSON? [y/N]: ").strip().lower() == "y"
        print()
        return cmd_validate(argparse.Namespace(region=region, token=token, json=show))
    if action == "3":
        token = ask("Refresh token", secret=True)
        firebase = input("Firebase refresh token? [y/N]: ").strip().lower() == "y"
        out = input(f"Save new tokens to file? path [{DEFAULT_TOKEN_FILE}]: ").strip()
        print()
        return cmd_refresh(argparse.Namespace(region=region, token=token, firebase=firebase,
                                              out=out or None))
    print("Unknown choice.", file=sys.stderr)
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="openbrivo.py",
        description=__doc__,
        epilog="Running without a subcommand starts the XE360 unlock flow.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--ui", action="store_true",
                        help="serve the web UI on loopback with credential forwarding (no CORS)")
    parser.add_argument("--port", type=int, default=8787, help="port for --ui (default 8787)")
    sub = parser.add_subparsers(dest="command")

    ex = sub.add_parser("exchange", aliases=["login"],
                        help="log in with username/password (Firebase) and get an access key")
    ex.add_argument("--region", choices=["US", "EU"], default="US")
    ex.add_argument("--username", help="username / email / pass ID (prompted if omitted)")
    ex.add_argument("--password", help="password (prompted if omitted)")
    ex.add_argument("--out", default=DEFAULT_TOKEN_FILE,
                    help=f"save access key to a chmod-600 JSON file (default {DEFAULT_TOKEN_FILE})")
    ex.add_argument("--reveal", action="store_true", help="print the full access token")

    rf = sub.add_parser("refresh", help="refresh an access token")
    rf.add_argument("--token", required=True, help="refresh token")
    rf.add_argument("--region", choices=["US", "EU"], default="US")
    rf.add_argument("--firebase", action="store_true",
                    help="refresh a Firebase login token instead of a Brivo OAuth token")
    rf.add_argument("--out", help="save full response to a chmod-600 JSON file")

    va = sub.add_parser("validate", help="check an access key against GET /pass")
    va.add_argument("--region", choices=["US", "EU"], default="US")
    va.add_argument("--token", required=True, help="access token")
    va.add_argument("--json", action="store_true", help="print the full pass JSON")

    scan = sub.add_parser("scan", help="list all nearby BLE devices; never connect or write")
    scan.add_argument("--scan-seconds", type=int, default=12, help="BLE scan duration (default 12)")

    un = sub.add_parser(
        "unlock",
        help="fetch credential and discover BLE in parallel, then unlock the selected XE360 lock",
    )
    un.add_argument("--region", choices=["US", "EU"], default="US")
    un.add_argument("--scan-seconds", type=int, default=12, help="BLE scan duration (default 12)")
    un.add_argument("--username", help="prompted if omitted")
    un.add_argument("--password", help="prompted if omitted")

    args = parser.parse_args()
    if args.ui:
        return launch_ui(args)
    if not args.command:
        return cmd_unlock(
            argparse.Namespace(region="US", scan_seconds=12, username=None, password=None)
        )
    return {"exchange": cmd_exchange, "login": cmd_exchange, "refresh": cmd_refresh,
            "validate": cmd_validate, "scan": cmd_scan, "unlock": cmd_unlock}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
