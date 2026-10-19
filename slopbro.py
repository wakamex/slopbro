#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SlopBro
# by throwaway96
# https://github.com/throwaway96/slopbro
# Copyright 2026. Licensed under AGPL v3 or later. No warranties.

"""
slopbro.py - Connect to an LG webOS TV over SSAP, pair, and
launch various apps with a self-hosted payload page.

Single file, standard library only. Requires Python 3 and should be run on
a PC on the same LAN as the TV.

Example:
    python3 slopbro.py 192.168.1.50
    python3 slopbro.py --debug 192.168.1.50
    python3 slopbro.py --local-ip 1.2.3.4 192.168.1.50
"""

import argparse
import base64
import io
import json
import os
import posixpath
import socket
import ssl
import struct
import sys
import threading
import time
from hashlib import sha1
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import quote, unquote, urlsplit

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

PORT_TLS = 3001
PORT_PLAIN = 3000

# TODO: Support complete webOS version numbers (or firmware versions?).
# TODO: Figure out actual webOS version ranges for each app.
TARGET_APPS = [
    ("com.webos.app.voiceweb", "URL", [11]),
    (
        "com.webos.app.adoverlayex",
        "interactiveUrl",
        [3, 4, 5, 6, 7, 8, 9, 10],
    ),
    # TODO: Figure out why this doesn't always work on webOS 6.5.3.
    ("com.webos.app.adoverlay", "interactiveUrl", [3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.acroverlay", "contentTarget", [3, 4, 5, 6, 7, 8, 9, 10]),
    ("com.webos.app.tinybrowser", "contentTarget", [3, 4, 5, 6, 7, 8, 9, 10]),
    # May not work on certain webOS versions (e.g., 6.5.x) even if present
    # because of region restrictions.
    ("com.webos.app.dangbei-overlay", "target", [3, 4, 6, 7, 8, 9, 10]),
]

ENTRY_PAGE = "index.html"
SHELL_SCRIPT = "autoroot.sh"
SERVICE_FILES = [
    "package.json",
    "main.js",
]

ASSET_SOURCE_AUTO = "auto"
ASSET_SOURCE_DIR = "dir"
ASSET_SOURCE_EMBEDDED = "embedded"
ASSET_SOURCES = (ASSET_SOURCE_AUTO, ASSET_SOURCE_DIR, ASSET_SOURCE_EMBEDDED)

TEST_SERVER_SIMPLE = "simple"
TEST_SERVER_PAYLOAD = "payload"
TEST_SERVER_MODES = (TEST_SERVER_SIMPLE, TEST_SERVER_PAYLOAD)

# Should exist on all targeted webOS versions.
DEFAULT_FAKE_SERVICE_PATH = "/usr/palm/services/com.palm.service.devmode"

# Tried in order by the payload. /media/internal/downloads is rejected as an
# untrusted location on some newer firmware; /tmp is a broad fallback.
DEFAULT_DOWNLOAD_DIRS = [
    "/media/internal/downloads",
    "/tmp",
]

# --- BEGIN EMBEDDED WWWROOT ---
EMBEDDED_WWWROOT = {}
# --- END EMBEDDED WWWROOT ---

# seconds
CONNECT_TIMEOUT = 10.0
PAIR_TIMEOUT = 60.0
FILE_WAIT_TIMEOUT = 180.0

# Manifest distilled from the reference clients. Broad permission set so the
# launcher works across firmware versions; the TV grants what it recognizes.
DEFAULT_MANIFEST = {
    "manifestVersion": 1,
    "appVersion": "1.0",
    "appId": "lol.slopbro",
    "vendorId": "throwaway96",
    "localizedAppNames": {"": "SlopBro"},
    "localizedVendorNames": {"": "throwaway96"},
    "permissions": [
        "LAUNCH",
        "CLOSE",
        "READ_APP_STATUS",
        "READ_INSTALLED_APPS",
        "READ_RUNNING_APPS",
    ],
}


def log(msg):
    """Print a timestamped status line to stderr so stdout stays parse-friendly."""
    sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


def die(msg, code=1):
    log("error: " + msg)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Minimal RFC 6455 WebSocket client (text frames only, client-side masking).
# ---------------------------------------------------------------------------


class WebSocketError(Exception):
    pass


class WebSocket:
    """A tiny blocking WebSocket client over a raw (optionally TLS) socket.

    Only what SSAP needs: a client handshake with no Origin header, masked text
    frames, ping/pong handling, and a clean close. Not a general-purpose library.
    """

    OP_CONT = 0x0
    OP_TEXT = 0x1
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, sock):
        self._sock = sock
        self._recv_buf = b""
        self.closed = False

    @classmethod
    def connect(cls, host, port, secure=True, timeout=CONNECT_TIMEOUT):
        raw = socket.create_connection((host, port), timeout)
        if secure:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Intentional: the TV uses a self-signed certificate.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        ws = cls(sock)
        ws._handshake(host, port, secure)
        return ws

    def _handshake(self, host, port, secure):
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        # Deliberately no Origin header: that is what lets a native client past
        # the SSAP server's web-origin filter.
        lines = [
            "GET / HTTP/1.1",
            "Host: %s:%d" % (host, port),
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: %s" % key,
            "Sec-WebSocket-Version: 13",
            "",
            "",
        ]
        self._sock.sendall("\r\n".join(lines).encode("ascii"))

        header = self._read_http_headers()
        status_line = header.split("\r\n", 1)[0]
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or parts[1] != "101":
            raise WebSocketError("unexpected handshake response: %s" % status_line)

        expected = base64.b64encode(
            sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        accept = None
        for line in header.split("\r\n")[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                if name.strip().lower() == "sec-websocket-accept":
                    accept = value.strip()
                    break
        if accept != expected:
            raise WebSocketError("invalid Sec-WebSocket-Accept value")

    def _read_http_headers(self):
        while b"\r\n\r\n" not in self._recv_buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise WebSocketError("connection closed during handshake")
            self._recv_buf += chunk
        header_bytes, self._recv_buf = self._recv_buf.split(b"\r\n\r\n", 1)
        return header_bytes.decode("latin-1")

    def _recv_exact(self, n):
        while len(self._recv_buf) < n:
            chunk = self._sock.recv(max(4096, n - len(self._recv_buf)))
            if not chunk:
                raise WebSocketError("connection closed")
            self._recv_buf += chunk
        data, self._recv_buf = self._recv_buf[:n], self._recv_buf[n:]
        return data

    def send_text(self, text):
        self._send_frame(self.OP_TEXT, text.encode("utf-8"))

    def _send_frame(self, opcode, payload):
        if self.closed:
            raise WebSocketError("socket is closed")
        header = bytearray()
        header.append(0x80 | opcode)  # FIN + opcode
        length = len(payload)
        mask_bit = 0x80  # client frames must be masked
        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header += struct.pack("!H", length)
        else:
            header.append(mask_bit | 127)
            header += struct.pack("!Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytearray(payload)
        for i in range(len(masked)):
            masked[i] ^= mask[i % 4]
        self._sock.sendall(bytes(header) + bytes(masked))

    def recv_text(self, timeout=None):
        """Return the next complete text message as a unicode string.

        Handles fragmented messages and transparently answers pings. Returns
        None if the peer sends a close frame.
        """
        if timeout is not None:
            self._sock.settimeout(timeout)
        fragments = []
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == self.OP_TEXT:
                # Start of a new message; discard any incomplete fragment.
                fragments = [payload]
            elif opcode == self.OP_CONT:
                if not fragments:
                    # Continuation without a start frame; ignore it.
                    continue
                fragments.append(payload)
            elif opcode == self.OP_PING:
                self._send_frame(self.OP_PONG, payload)
                continue
            elif opcode == self.OP_PONG:
                continue
            elif opcode == self.OP_CLOSE:
                self._send_close()
                self.closed = True
                return None
            else:
                # Ignore unexpected data frames.
                continue
            if fin:
                return b"".join(fragments).decode("utf-8")

    def _read_frame(self):
        b0, b1 = struct.unpack("!BB", self._recv_exact(2))
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length) if length else b""
        if mask:
            payload = bytearray(payload)
            for i in range(len(payload)):
                payload[i] ^= mask[i % 4]
            payload = bytes(payload)
        return fin, opcode, payload

    def _send_close(self):
        try:
            self._send_frame(self.OP_CLOSE, b"")
        except (WebSocketError, OSError):
            pass

    def close(self):
        if not self.closed:
            self._send_close()
            self.closed = True
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# SSAP client layer
# ---------------------------------------------------------------------------


class SSAPError(Exception):
    pass


class SSAPClient:
    def __init__(self, ws):
        self._ws = ws
        self._counter = 0

    def _next_id(self, prefix):
        self._counter += 1
        return "%s_%d" % (prefix, self._counter)

    def _send(self, message):
        self._ws.send_text(json.dumps(message))

    def register(self, client_key, manifest, timeout=PAIR_TIMEOUT):
        """Perform the SSAP register handshake.

        Returns the client-key string from the 'registered' reply. If no key was
        stored, the TV shows a pairing prompt and this blocks (up to timeout)
        until the user accepts.
        """
        payload = {
            "forcePairing": False,
            "pairingType": "PROMPT",
            "manifest": manifest,
        }
        if client_key:
            payload["client-key"] = client_key
        msg_id = self._next_id("register")
        self._send({"id": msg_id, "type": "register", "payload": payload})

        prompted = False
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise SSAPError("timed out waiting for registration")
            try:
                raw = self._ws.recv_text(timeout=remaining)
            except socket.timeout:
                raise SSAPError("timed out waiting for registration")
            if raw is None:
                raise SSAPError("connection closed during registration")
            try:
                msg = json.loads(raw)
            except ValueError:
                raise SSAPError("invalid JSON during registration")
            mtype = msg.get("type")
            if mtype == "registered":
                return (msg.get("payload") or {}).get("client-key", client_key)
            if mtype == "response" and (msg.get("payload") or {}).get("pairingType"):
                if not prompted:
                    prompted = True
                    log("accept the pairing prompt on the TV screen ...")
                continue
            if mtype == "error":
                raise SSAPError(msg.get("error") or "registration rejected")
            # Ignore anything else (e.g. stray notifications) and keep waiting.

    def request(self, uri, payload=None, timeout=15.0):
        """Send an SSAP request and return the matching response message."""
        msg_id = self._next_id("req")
        self._send(
            {
                "id": msg_id,
                "type": "request",
                "uri": uri,
                "payload": payload or {},
            }
        )
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise SSAPError("timed out waiting for response to %s" % uri)
            try:
                raw = self._ws.recv_text(timeout=remaining)
            except socket.timeout:
                raise SSAPError("timed out waiting for response to %s" % uri)
            if raw is None:
                raise SSAPError("connection closed while awaiting %s" % uri)
            try:
                msg = json.loads(raw)
            except ValueError:
                raise SSAPError("invalid JSON while awaiting %s" % uri)
            if msg.get("id") == msg_id:
                return msg
            # Different id: not ours, keep reading.

    def close(self):
        self._ws.close()


def register_with_fallback(client, stored_key):
    """Register with the TV, retrying without a rejected stored key."""
    try:
        return client.register(stored_key, DEFAULT_MANIFEST)
    except SSAPError as exc:
        if not stored_key or "timed out" in str(exc).lower():
            raise
        log("stored client key was rejected (%s); pairing again" % exc)
        return client.register("", DEFAULT_MANIFEST)


# ---------------------------------------------------------------------------
# Client-key persistence
# ---------------------------------------------------------------------------


def key_path(ip):
    safe_ip = os.path.basename(str(ip).replace("\\", "/")) or "tv"
    return os.path.join(os.getcwd(), "%s.key" % safe_ip)


def load_client_key(ip):
    path = key_path(ip)
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def save_client_key(ip, client_key):
    path = key_path(ip)
    directory = os.path.dirname(path)
    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            pass
    try:
        with open(path, "w") as fh:
            fh.write(client_key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        log("warning: could not save client key to %s (%s)" % (path, exc))


# ---------------------------------------------------------------------------
# High-level flow
# ---------------------------------------------------------------------------


def target_apps_for_webos_version(candidates, webos_version):
    """Return launcher candidates compatible with the given webOS version."""
    if webos_version is None:
        return [(app_id, url_param_name) for app_id, url_param_name, _ in candidates]

    try:
        major_version = int(str(webos_version).split(".", 1)[0])
    except (TypeError, ValueError):
        raise ValueError("invalid webOS version: %s" % webos_version)

    return [
        (app_id, url_param_name)
        for app_id, url_param_name, major_versions in candidates
        if major_version in major_versions
    ]


def verify_app_present(client, candidates):
    """Check installed apps and return the first matching (app_id, url_param_name).

    Falls back to the first candidate if the check fails or no match is found.
    """
    fallback = candidates[0]
    try:
        resp = client.request(
            "ssap://com.webos.applicationManager/listApps", {}, timeout=8.0
        )
    except (SSAPError, WebSocketError, OSError) as exc:
        log("warning: could not verify app presence (%s)" % exc)
        return fallback
    if resp.get("type") == "error":
        log(
            "warning: listApps denied (%s); skipping app check"
            % resp.get("error", "unknown")
        )
        return fallback
    apps = (resp.get("payload") or {}).get("apps") or []
    installed_ids = set(
        a.get("id") for a in apps if isinstance(a, dict) and a.get("id")
    )
    for app_id, url_param_name in candidates:
        if app_id in installed_ids:
            log("confirmed app is installed: %s" % app_id)
            return app_id, url_param_name
    log(
        "warning: none of [%s] found in listApps; launch may do nothing"
        % ", ".join(a for a, _ in candidates)
    )
    return fallback


def launch_app(client, app_id, params):
    resp = client.request(
        "ssap://system.launcher/launch", {"id": app_id, "params": params}
    )
    if resp.get("type") == "error":
        raise SSAPError("launch failed: %s" % resp.get("error", "unknown"))
    return resp.get("payload") or {}


def local_ip_for_remote(remote_host, remote_port=80):
    """Choose a LAN-reachable local IPv4 for a given remote host."""
    remote_ip = socket.gethostbyname(remote_host)
    route_ip = _route_selected_local_ip(remote_ip, remote_port)

    # LunaDownloadMgr seems to choke on 127.0.0.1
    if route_ip and route_ip.startswith("127."):
        # Arbitrary external address; doesn't have to be reachable
        lan_ip = _route_selected_local_ip("8.8.8.8", 80)
        if lan_ip and not lan_ip.startswith("127."):
            log("detected loopback route; using LAN IP %s instead" % lan_ip)
            return lan_ip
        raise RuntimeError("could not determine a non-loopback local IPv4 address")

    if route_ip:
        return route_ip
    raise RuntimeError("could not determine local IPv4 address")


def resolve_client_ip(host):
    """Resolve the expected TV address, or None if it cannot be resolved."""
    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except (OSError, UnicodeError):
        return None


def guess_local_ip(target_host=None, local_ip_override=None):
    """Resolve the local IPv4 to advertise, without necessarily knowing a target.

    Prefers an explicit override, then a route lookup toward target_host (if
    given), then falls back to the route toward an arbitrary external address.
    """
    if local_ip_override:
        return local_ip_override
    if target_host:
        return local_ip_for_remote(target_host)
    # Arbitrary external address; doesn't have to be reachable
    route_ip = _route_selected_local_ip("8.8.8.8", 80)
    if route_ip:
        return route_ip
    raise RuntimeError("could not determine local IPv4 address")


def _route_selected_local_ip(remote_ip, remote_port):
    """Ask the kernel route table which source IP it would pick."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect((remote_ip, remote_port))
            return sock.getsockname()[0]
        except OSError:
            return None


def required_files():
    return [ENTRY_PAGE, SHELL_SCRIPT] + list(SERVICE_FILES)


def resolve_wwwroot_path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.join(script_dir, "wwwroot")
    return root_dir


def _embedded_meta_for(rel_path):
    if not isinstance(EMBEDDED_WWWROOT, dict):
        return None
    meta = EMBEDDED_WWWROOT.get(rel_path)
    if not isinstance(meta, dict):
        return None
    return meta


def _read_embedded_file(rel_path):
    meta = _embedded_meta_for(rel_path)
    if meta is None:
        return None
    encoding = meta.get("encoding", "base64")
    if encoding != "base64":
        raise RuntimeError(
            "unsupported embedded encoding for %s: %s" % (rel_path, encoding)
        )
    payload = meta.get("data", "")
    return base64.b64decode(payload)


def _read_filesystem_file(root_dir, rel_path):
    if not root_dir:
        return None
    abs_path = os.path.join(root_dir, rel_path.replace("/", os.sep))
    if not os.path.isfile(abs_path):
        return None
    with open(abs_path, "rb") as fh:
        return fh.read()


def _missing_required_files(
    tracked_files,
    root_dir,
    allow_embedded_assets,
    allow_filesystem_fallback,
):
    missing = []
    for rel_path in tracked_files:
        if allow_embedded_assets and _embedded_meta_for(rel_path) is not None:
            continue
        if (
            allow_filesystem_fallback
            and _read_filesystem_file(root_dir, rel_path) is not None
        ):
            continue
        missing.append(rel_path)
    return missing


def resolve_asset_root(asset_source, tracked_files):
    dir_root = resolve_wwwroot_path()
    if asset_source not in ASSET_SOURCES:
        raise RuntimeError(
            "invalid --asset-source '%s' (expected one of: %s)"
            % (asset_source, ", ".join(ASSET_SOURCES))
        )

    allow_embedded_assets = asset_source != ASSET_SOURCE_DIR
    allow_filesystem_fallback = asset_source != ASSET_SOURCE_EMBEDDED
    if allow_filesystem_fallback and not os.path.isdir(dir_root):
        dir_root = None

    missing = _missing_required_files(
        tracked_files,
        dir_root,
        allow_embedded_assets,
        allow_filesystem_fallback,
    )
    if missing:
        raise RuntimeError(
            "required files not found in %s: %s"
            % (
                (
                    "wwwroot"
                    if asset_source == ASSET_SOURCE_DIR
                    else (
                        "embedded data"
                        if asset_source == ASSET_SOURCE_EMBEDDED
                        else "embedded data or wwwroot"
                    )
                ),
                ", ".join(missing),
            )
        )

    if asset_source == ASSET_SOURCE_DIR:
        source_desc = ASSET_SOURCE_DIR
    elif allow_filesystem_fallback and dir_root is not None:
        source_desc = "embedded+dir"
    elif allow_filesystem_fallback:
        source_desc = "embedded"
    else:
        source_desc = ASSET_SOURCE_EMBEDDED
    return dir_root, source_desc, allow_embedded_assets, allow_filesystem_fallback


class RequestedFilesTracker:
    def __init__(self, tracked_files):
        self._tracked = set(tracked_files)
        self._seen = set()
        self._lock = threading.Lock()
        self._complete = threading.Event()
        if not self._tracked:
            self._complete.set()

    def mark_seen(self, rel_path):
        with self._lock:
            if rel_path not in self._tracked or rel_path in self._seen:
                return False, len(self._seen), len(self._tracked)
            self._seen.add(rel_path)
            if self._seen == self._tracked:
                self._complete.set()
            return True, len(self._seen), len(self._tracked)

    def wait_for_all(self, timeout):
        return self._complete.wait(timeout)

    def missing_files(self):
        with self._lock:
            return sorted(self._tracked - self._seen)


def make_tracking_handler(
    root_dir,
    tracker,
    served_files,
    allow_embedded_assets,
    allow_filesystem_fallback,
    expected_client=None,
):
    served = set(served_files)

    class TrackingHTTPRequestHandler(SimpleHTTPRequestHandler):
        def _requested_rel_path(self):
            raw_path = urlsplit(self.path).path
            try:
                raw_path = unquote(raw_path, errors="surrogatepass")
            except UnicodeDecodeError:
                return None
            raw_path = posixpath.normpath(raw_path)
            if raw_path in ("", "/", "."):
                return ENTRY_PAGE
            rel_path = raw_path.lstrip("/")
            if rel_path.startswith("../") or rel_path == "..":
                return None
            return rel_path.replace("\\", "/")

        def _send_bytes(self, rel_path, data):
            ctype = self.guess_type(rel_path)
            self.send_response(200)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            return io.BytesIO(data)

        def _mark_served_file(self, rel_path):
            if expected_client is not None and self.client_address[0] != expected_client:
                log(
                    "ignoring request for %s from unexpected client %s"
                    % (rel_path, self.client_address[0])
                )
                return
            marked, seen_count, total_count = tracker.mark_seen(rel_path)
            if marked:
                log(
                    "served required file: %s (%d/%d)"
                    % (
                        rel_path,
                        seen_count,
                        total_count,
                    )
                )

        def send_head(self):
            rel_path = self._requested_rel_path()
            if rel_path is None or rel_path not in served:
                self.send_error(404, "File not found")
                return None

            data = None
            if allow_embedded_assets:
                data = _read_embedded_file(rel_path)
            if data is None and allow_filesystem_fallback:
                data = _read_filesystem_file(root_dir, rel_path)
            if data is None:
                self.send_error(404, "File not found")
                return None

            self._mark_served_file(rel_path)
            return self._send_bytes(rel_path, data)

    return TrackingHTTPRequestHandler


def start_http_server(
    root_dir,
    tracker,
    served_files,
    allow_embedded_assets,
    allow_filesystem_fallback,
    bind_host="0.0.0.0",
    preferred_port=8080,
    expected_client=None,
):
    """Start a tiny static file server rooted at root_dir."""
    handler = make_tracking_handler(
        root_dir,
        tracker,
        served_files,
        allow_embedded_assets,
        allow_filesystem_fallback,
        expected_client=expected_client,
    )
    return _start_http_server(handler, bind_host, preferred_port)


def _start_http_server(handler, bind_host, preferred_port):
    server = None
    for port in (preferred_port, 0):
        try:
            server = HTTPServer((bind_host, port), handler)
            break
        except OSError:
            server = None
    if server is None:
        raise RuntimeError("could not start local HTTP server")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def build_self_hosted_url(
    tv_host,
    server_port,
    debug=False,
    local_ip_override=None,
    curl_insecure=False,
    fake_service_path=DEFAULT_FAKE_SERVICE_PATH,
    telnet=False,
    leave_script=False,
    download_dirs=(),
):
    local_ip = local_ip_override or local_ip_for_remote(tv_host)
    params = [
        "script=" + quote(SHELL_SCRIPT, safe=""),
        "files=" + quote(";".join(SERVICE_FILES), safe=";"),
    ]
    if debug:
        params.append("debug")
    if telnet:
        params.append("telnet")
    if curl_insecure:
        params.append("curl-insecure")
    if leave_script:
        params.append("leave-script")
    if fake_service_path:
        params.append("fake-service-path=" + quote(fake_service_path, safe="/"))
    if download_dirs:
        params.append("download-dirs=" + quote(";".join(download_dirs), safe=";"))
    return "http://%s:%d/%s?%s" % (
        local_ip,
        server_port,
        quote(ENTRY_PAGE, safe=""),
        "&".join(params),
    )


def _validate_ipv4_address(ip_text):
    try:
        socket.inet_aton(ip_text)
    except OSError:
        return False
    return ip_text.count(".") == 3


TEST_CONNECTION_MESSAGE = "Here's your slop, bro!\n"


def make_test_connection_handler():
    """Build a minimal request handler that answers every request the same way.

    Used only to prove that the TV (or any browser on the LAN) can reach this
    host over HTTP; it doesn't serve any real payload/exploit files.
    """
    body = TEST_CONNECTION_MESSAGE.encode("utf-8")

    class TestConnectionHandler(BaseHTTPRequestHandler):
        def _send_headers(self, include_body):
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def do_GET(self):
            self._send_headers(True)

        def do_HEAD(self):
            self._send_headers(False)

        def log_message(self, format, *args):
            log("request from %s: %s" % (self.client_address[0], format % args))

    return TestConnectionHandler


def start_test_connection_server(bind_host="0.0.0.0", preferred_port=8080):
    handler = make_test_connection_handler()
    return _start_http_server(handler, bind_host, preferred_port)


def run_test_connection(host=None, local_ip_override=None):
    """Serve a fixed plain-text response to test basic HTTP connectivity only.

    Doesn't serve the real payload/exploit files and doesn't perform any SSAP
    pairing; just prints the URL to open manually in the TV's (or any) web
    browser to confirm that the TV can reach this host over HTTP. host is
    optional here since no SSAP connection or route-to-TV lookup is required.
    """
    if not host:
        log(
            "warning: no <tv-ip-or-host> given; the guessed local IP may be "
            "wrong (recommended: pass the TV's IP address)"
        )

    http_server = None
    url = None
    try:
        http_server = start_test_connection_server()
        local_ip = guess_local_ip(
            target_host=host, local_ip_override=local_ip_override
        )
        url = "http://%s:%d/" % (local_ip, http_server.server_port)
    except Exception as exc:
        die("could not start test HTTP server: %s" % exc)

    log("test mode: minimal HTTP connectivity check (no payload served)")
    log("open this URL in the TV's web browser to test HTTP connectivity:")
    log("    %s" % url)
    log("press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("stopping test server")
    finally:
        if http_server is not None:
            try:
                http_server.shutdown()
            except Exception:
                pass
            try:
                http_server.server_close()
            except Exception:
                pass


def run_test_payload(
    host=None,
    debug=False,
    asset_source=ASSET_SOURCE_AUTO,
    local_ip_override=None,
    curl_insecure=False,
    fake_service_path=DEFAULT_FAKE_SERVICE_PATH,
    telnet=False,
    leave_script=False,
    download_dir=None,
    no_client_check=False,
):
    """Serve the payload page and print its URL without pairing/launching.

    Lets the user manually open the URL in the TV's web browser (or any
    browser on the LAN) to confirm that the payload/exploit files are served
    correctly, without needing a working SSAP connection first. host is
    recommended, since it's used to guess the local IP to listen on.
    """
    if not host:
        log(
            "warning: no <tv-ip-or-host> given; the guessed local IP may be "
            "wrong (recommended: pass the TV's IP address)"
        )

    all_files = required_files()
    tracked_files = [name for name in all_files if name != ENTRY_PAGE]
    wwwroot_dir = None
    asset_source_used = None
    allow_embedded_assets = True
    allow_filesystem_fallback = True
    http_server = None
    page_url = None
    try:
        (
            wwwroot_dir,
            asset_source_used,
            allow_embedded_assets,
            allow_filesystem_fallback,
        ) = resolve_asset_root(asset_source, all_files)
    except RuntimeError as exc:
        die("%s" % exc)

    tracker = RequestedFilesTracker(tracked_files)
    try:
        http_server = start_http_server(
            wwwroot_dir,
            tracker,
            all_files,
            allow_embedded_assets,
            allow_filesystem_fallback,
            expected_client=None if no_client_check else resolve_client_ip(host),
        )
        local_ip = guess_local_ip(
            target_host=host, local_ip_override=local_ip_override
        )
        page_url = build_self_hosted_url(
            host,
            http_server.server_port,
            debug=debug,
            curl_insecure=curl_insecure,
            local_ip_override=local_ip,
            fake_service_path=fake_service_path,
            telnet=telnet,
            leave_script=leave_script,
            download_dirs=[download_dir] if download_dir else DEFAULT_DOWNLOAD_DIRS,
        )
    except Exception as exc:
        die("could not start self-hosted page server: %s" % exc)

    log(
        "test mode: serving files from %s (source=%s)"
        % (wwwroot_dir, asset_source_used)
    )
    log("open this URL in the TV's web browser to test the payload:")
    log("    %s" % page_url)
    log("press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("stopping test server")
    finally:
        if http_server is not None:
            try:
                http_server.shutdown()
            except Exception:
                pass
            try:
                http_server.server_close()
            except Exception:
                pass


def run(
    host,
    debug=False,
    asset_source=ASSET_SOURCE_AUTO,
    local_ip_override=None,
    webos_version_override=None,
    curl_insecure=False,
    fake_service_path=DEFAULT_FAKE_SERVICE_PATH,
    telnet=False,
    leave_script=False,
    app_override=None,
    download_dir=None,
    no_client_check=False,
):
    secure = True
    port = PORT_TLS if secure else PORT_PLAIN
    scheme = "wss" if secure else "ws"
    log("connecting to %s://%s:%d" % (scheme, host, port))

    all_files = required_files()
    tracked_files = [name for name in all_files if name != ENTRY_PAGE]
    wwwroot_dir = None
    asset_source_used = None
    allow_embedded_assets = True
    allow_filesystem_fallback = True
    http_server = None
    page_url = None
    ws = None
    new_key = ""
    result = {}
    try:
        (
            wwwroot_dir,
            asset_source_used,
            allow_embedded_assets,
            allow_filesystem_fallback,
        ) = resolve_asset_root(
            asset_source,
            all_files,
        )
    except RuntimeError as exc:
        die("%s" % exc)

    tracker = RequestedFilesTracker(tracked_files)
    if tracked_files:
        log(
            "tracking %d files in %s (source=%s)"
            % (len(tracked_files), wwwroot_dir, asset_source_used)
        )
    else:
        log("warning: no files found in %s" % wwwroot_dir)
    try:
        http_server = start_http_server(
            wwwroot_dir,
            tracker,
            all_files,
            allow_embedded_assets,
            allow_filesystem_fallback,
            expected_client=None if no_client_check else resolve_client_ip(host),
        )
        page_url = build_self_hosted_url(
            host,
            http_server.server_port,
            debug=debug,
            curl_insecure=curl_insecure,
            local_ip_override=local_ip_override,
            fake_service_path=fake_service_path,
            telnet=telnet,
            leave_script=leave_script,
            download_dirs=[download_dir] if download_dir else DEFAULT_DOWNLOAD_DIRS,
        )
    except Exception as exc:
        die("could not start self-hosted page server: %s" % exc)
    log("serving files from %s at %s" % (wwwroot_dir, page_url))

    try:
        ws = WebSocket.connect(
            host,
            port,
            secure=secure,
        )
    except (OSError, WebSocketError) as exc:
        die("could not connect to TV: %s" % exc)

    client = SSAPClient(ws)
    try:
        stored_key = load_client_key(host)
        if stored_key:
            log("using stored client key")
        else:
            log("no stored client key; pairing will be requested")

        try:
            new_key = register_with_fallback(client, stored_key)
        except (SSAPError, WebSocketError, OSError) as exc:
            die("registration failed: %s" % exc)

        if new_key and new_key != stored_key:
            save_client_key(host, new_key)
            log("registered; client key saved")
        else:
            log("registered")

        webos_version = None
        if webos_version_override:
            webos_version = webos_version_override
            log("using forced webOS version: %s" % webos_version)
        # Version auto-detection is disabled; pass --webos-version if the
        # default candidate list does not work on your TV.

        target_apps = []
        try:
            target_apps = target_apps_for_webos_version(TARGET_APPS, webos_version)
        except ValueError as exc:
            die("%s" % exc)
        if not target_apps:
            die("no target apps configured for webOS %s" % webos_version)
        if app_override:
            matches = [(app, param) for app, param in target_apps if app == app_override]
            if not matches:
                die(
                    "app '%s' is not a valid target for webOS %s (choose from: %s)"
                    % (
                        app_override,
                        webos_version or "any",
                        ", ".join(app for app, _ in target_apps),
                    )
                )
            app_id, url_param_name = matches[0]
            log("using app override: %s" % app_id)
        else:
            app_id, url_param_name = verify_app_present(client, target_apps)

        log("launching %s -> %s" % (app_id, page_url))
        try:
            result = launch_app(client, app_id, {url_param_name: page_url})
        except (SSAPError, WebSocketError, OSError) as exc:
            die("%s" % exc)

        print(json.dumps(result, sort_keys=True))

        log("waiting for all tracked files to be requested")
        if not tracker.wait_for_all(FILE_WAIT_TIMEOUT):
            missing = tracker.missing_files()
            die(
                "timed out waiting for file(s): %s"
                % (", ".join(missing) if missing else "unknown")
            )
        log("done; all tracked files were requested (❛ ᴗ ❛)")
    finally:
        client.close()
        if http_server is not None:
            try:
                http_server.shutdown()
            except Exception:
                pass
            try:
                http_server.server_close()
            except Exception:
                pass


def _require_path_arg(value):
    if not value.strip():
        raise argparse.ArgumentTypeError("value must not be empty")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in value):
        raise argparse.ArgumentTypeError("value must not contain whitespace or control characters")
    return value


def _fake_service_path_arg(value):
    return _require_path_arg(value)


def _download_dir_arg(value):
    value = _require_path_arg(value)
    if ";" in value:
        raise argparse.ArgumentTypeError("value must not contain ';'")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Pair with an LG webOS TV and launch a self-hosted payload page.",
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", "-?", action="help",
        help="show this help message and exit",
    )
    parser.add_argument(
        "--debug", action="store_true", help="enable payload debug output",
    )
    parser.add_argument(
        "--curl-insecure", action="store_true",
        help="disable curl TLS certificate verification for payload downloads",
    )
    parser.add_argument(
        "--fake-service-path", metavar="<path>",
        default=DEFAULT_FAKE_SERVICE_PATH, type=_fake_service_path_arg,
        help="fake service path used to bypass the service launch patch",
    )
    parser.add_argument(
        "--no-fake-service-path", dest="fake_service_path",
        action="store_const", const="",
        help="disable the fake service path bypass",
    )
    parser.add_argument(
        "--asset-source", choices=ASSET_SOURCES, default=ASSET_SOURCE_AUTO,
        help="asset location (default: %(default)s)",
    )
    parser.add_argument(
        "--local-ip", metavar="<ipv4>",
        help="override the advertised local IPv4 address",
    )
    parser.add_argument(
        "--webos-version", metavar="<version>",
        help="limit target apps by internal webOS major version (e.g. 10 for webOS 25)",
    )
    parser.add_argument(
        "--app", metavar="<app-id>",
        help="override target app selection (must be valid for the webOS version)",
    )
    parser.add_argument(
        "--telnet", action="store_true",
        help="start telnetd in the payload",
    )
    parser.add_argument(
        "--leave-script", action="store_true",
        help="do not rename an invalid start-devmode.sh",
    )
    parser.add_argument(
        "--download-dir", metavar="<path>", type=_download_dir_arg,
        help="directory on the TV for payload downloads (default: try /media/internal/downloads, then /tmp)",
    )
    parser.add_argument(
        "--no-client-check", action="store_true",
        help="credit payload file requests from any client, not just the TV address",
    )
    parser.add_argument(
        "--test-server", choices=TEST_SERVER_MODES,
        help="serve a connectivity response (simple) or payload without pairing",
    )
    parser.add_argument(
        "host", nargs="?", metavar="<tv-ip-or-host>",
        help="TV address (required except in test-server modes; recommended there)",
    )
    args = parser.parse_args(argv)
    if args.local_ip is not None and not _validate_ipv4_address(args.local_ip):
        parser.error("invalid --local-ip value '%s'" % args.local_ip)
    if args.webos_version is not None and not args.webos_version.strip():
        parser.error("--webos-version value must not be empty")
    if args.test_server is None and args.host is None:
        parser.error("<tv-ip-or-host> is required unless --test-server is used")

    try:
        if args.test_server == TEST_SERVER_SIMPLE:
            run_test_connection(
                args.host,
                local_ip_override=args.local_ip,
            )
        elif args.test_server == TEST_SERVER_PAYLOAD:
            run_test_payload(
                args.host,
                debug=args.debug,
                asset_source=args.asset_source,
                local_ip_override=args.local_ip,
                curl_insecure=args.curl_insecure,
                fake_service_path=args.fake_service_path,
                telnet=args.telnet,
                leave_script=args.leave_script,
                download_dir=args.download_dir,
                no_client_check=args.no_client_check,
            )
        else:
            run(
                args.host,
                debug=args.debug,
                asset_source=args.asset_source,
                local_ip_override=args.local_ip,
                webos_version_override=args.webos_version,
                curl_insecure=args.curl_insecure,
                fake_service_path=args.fake_service_path,
                telnet=args.telnet,
                leave_script=args.leave_script,
                app_override=args.app,
                download_dir=args.download_dir,
                no_client_check=args.no_client_check,
            )
    except KeyboardInterrupt:
        sys.stderr.write("\n")
        log("interrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
