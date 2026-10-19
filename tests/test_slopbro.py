import io
import os
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch
from urllib.parse import parse_qs, urlsplit

import slopbro


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.runners = {}
        for name in ("run", "run_test_connection", "run_test_payload"):
            patcher = patch.object(slopbro, name)
            self.runners[name] = patcher.start()
            self.addCleanup(patcher.stop)

    def test_normal_defaults(self):
        self.assertEqual(slopbro.main(["tv.local"]), 0)
        self.runners["run"].assert_called_once_with(
            "tv.local", debug=False, asset_source="auto",
            local_ip_override=None, webos_version_override=None,
            curl_insecure=False, fake_service_path=slopbro.DEFAULT_FAKE_SERVICE_PATH,
            telnet=False, leave_script=False, app_override=None,
            download_dir=None, no_client_check=False, no_ipk_checksum=False,
        )
        self.runners["run_test_connection"].assert_not_called()
        self.runners["run_test_payload"].assert_not_called()

    def test_option_value_forms(self):
        for equals in (False, True):
            argv = ["--debug", "tv.local", "--curl-insecure"]
            for option, value in (
                ("--local-ip", "192.168.1.2"),
                ("--asset-source", "dir"),
                ("--webos-version", "6.5"),
            ):
                argv.extend([option + "=" + value] if equals else [option, value])
            self.assertEqual(slopbro.main(argv), 0)
            self.runners["run"].assert_called_with(
                "tv.local", debug=True, asset_source="dir",
                local_ip_override="192.168.1.2", webos_version_override="6.5",
                curl_insecure=True, fake_service_path=slopbro.DEFAULT_FAKE_SERVICE_PATH,
                telnet=False, leave_script=False, app_override=None,
                download_dir=None, no_client_check=False, no_ipk_checksum=False,
            )

    def test_fake_service_path_options(self):
        for argv, expected in (
            (["--fake-service-path", "/custom/service"], "/custom/service"),
            (["--fake-service-path=/custom/service"], "/custom/service"),
            (["--no-fake-service-path"], ""),
            (["--fake-service-path=/custom/service", "--no-fake-service-path"], ""),
            (["--no-fake-service-path", "--fake-service-path=/custom/service"], "/custom/service"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(slopbro.main(argv + ["tv.local"]), 0)
                self.assertEqual(self.runners["run"].call_args.kwargs["fake_service_path"], expected)

        self.assertEqual(slopbro.main([
            "--test-server=payload", "--no-fake-service-path",
        ]), 0)
        self.assertEqual(self.runners["run_test_payload"].call_args.kwargs["fake_service_path"], "")

    def test_payload_and_app_options(self):
        self.assertEqual(slopbro.main([
            "--telnet", "--leave-script", "--app=com.webos.app.tinybrowser",
            "tv.local",
        ]), 0)
        self.runners["run"].assert_called_with(
            "tv.local", debug=False, asset_source="auto",
            local_ip_override=None, webos_version_override=None,
            curl_insecure=False, fake_service_path=slopbro.DEFAULT_FAKE_SERVICE_PATH,
            telnet=True, leave_script=True,
            app_override="com.webos.app.tinybrowser", download_dir=None,
            no_client_check=False, no_ipk_checksum=False,
        )

    def test_download_dir_option(self):
        self.assertEqual(slopbro.main([
            "--download-dir=/tmp/payload", "tv.local",
        ]), 0)
        self.assertEqual(
            self.runners["run"].call_args.kwargs["download_dir"], "/tmp/payload",
        )
        self.assertEqual(slopbro.main([
            "--test-server=payload", "--download-dir=/tmp/payload",
        ]), 0)
        self.assertEqual(
            self.runners["run_test_payload"].call_args.kwargs["download_dir"],
            "/tmp/payload",
        )

    def test_no_client_check_option(self):
        self.assertEqual(slopbro.main([
            "--no-client-check", "tv.local",
        ]), 0)
        self.assertTrue(self.runners["run"].call_args.kwargs["no_client_check"])
        self.assertEqual(slopbro.main([
            "--test-server=payload", "--no-client-check",
        ]), 0)
        self.assertTrue(
            self.runners["run_test_payload"].call_args.kwargs["no_client_check"],
        )

    def test_no_ipk_checksum_option(self):
        self.assertEqual(slopbro.main([
            "--no-ipk-checksum", "tv.local",
        ]), 0)
        self.assertTrue(
            self.runners["run"].call_args.kwargs["no_ipk_checksum"],
        )
        self.assertEqual(slopbro.main([
            "--test-server=payload", "--no-ipk-checksum",
        ]), 0)
        self.assertTrue(
            self.runners["run_test_payload"].call_args.kwargs["no_ipk_checksum"],
        )

    def test_test_server_modes(self):
        for host in (None, "tv.local"):
            positional = [host] if host else []
            self.assertEqual(slopbro.main(["--test-server", "simple"] + positional), 0)
            self.runners["run_test_connection"].assert_called_with(
                host, local_ip_override=None,
            )
            self.assertEqual(slopbro.main([
                "--test-server=payload", "--debug", "--curl-insecure",
                "--asset-source=embedded", "--local-ip=192.168.1.2",
            ] + positional), 0)
            self.runners["run_test_payload"].assert_called_with(
                host, debug=True, asset_source="embedded",
                local_ip_override="192.168.1.2", curl_insecure=True,
                fake_service_path=slopbro.DEFAULT_FAKE_SERVICE_PATH,
                telnet=False, leave_script=False, download_dir=None,
                no_client_check=False, no_ipk_checksum=False,
            )
        self.runners["run"].assert_not_called()

    def test_help_aliases(self):
        for option in ("--help", "-h", "-?"):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                with self.assertRaises(SystemExit) as caught:
                    slopbro.main([option])
            self.assertEqual(caught.exception.code, 0)
            self.assertIn("--test-server", output.getvalue())
            self.assertIn("--no-fake-service-path", output.getvalue())
        for runner in self.runners.values():
            runner.assert_not_called()

    def test_invalid_arguments(self):
        invalid = [
            [], ["tv", "extra"], ["--unknown"],
            ["--asset-source=bad", "tv"], ["--test-server=bad"],
            ["--local-ip=bad", "tv"], ["--local-ip=", "tv"],
            ["--webos-version=", "tv"], ["--webos-version", " ", "tv"],
            ["--fake-service-path=", "tv"],
            ["--fake-service-path", " ", "tv"],
            ["--fake-service-path", "a b", "tv"],
            ["--fake-service-path", "a\tb", "tv"],
            ["--download-dir=", "tv"],
            ["--download-dir", " ", "tv"],
            ["--download-dir", "a b", "tv"],
            ["--download-dir", "/tmp/a;b", "tv"],
        ]
        invalid.extend([[option] for option in (
            "--local-ip", "--webos-version", "--asset-source", "--test-server",
            "--fake-service-path", "--app", "--download-dir",
        )])
        for argv in invalid:
            with patch("sys.stderr", new_callable=io.StringIO) as output:
                with self.assertRaises(SystemExit) as caught:
                    slopbro.main(argv)
            self.assertEqual(caught.exception.code, 2, argv)
            self.assertIn("error:", output.getvalue())
        for runner in self.runners.values():
            runner.assert_not_called()

    def test_keyboard_interrupt(self):
        self.runners["run"].side_effect = KeyboardInterrupt
        with patch.object(slopbro, "log"):
            self.assertEqual(slopbro.main(["tv.local"]), 130)

    def test_default_argv(self):
        with patch("sys.argv", ["slopbro.py", "tv.local"]):
            self.assertEqual(slopbro.main(), 0)
        self.runners["run"].assert_called_once()


class HandlerTests(unittest.TestCase):
    def test_server_startup(self):
        for mode in ("payload", "simple"):
            for failed_attempts in (0, 1, 2):
                with self.subTest(mode=mode, failed_attempts=failed_attempts):
                    server = Mock()
                    outcomes = [OSError("port unavailable")] * failed_attempts
                    if failed_attempts < 2:
                        outcomes.append(server)
                    with patch.object(slopbro, "HTTPServer", side_effect=outcomes) as factory:
                        with patch.object(slopbro.threading, "Thread") as thread:
                            if mode == "simple":
                                starter = slopbro.start_test_connection_server
                                args = ()
                            else:
                                starter = slopbro.start_http_server
                                args = (None, None, [], True, False)
                            if failed_attempts == 2:
                                with self.assertRaisesRegex(RuntimeError, "could not start"):
                                    starter(*args, bind_host="127.0.0.1", preferred_port=9000)
                                thread.assert_not_called()
                            else:
                                self.assertIs(
                                    starter(*args, bind_host="127.0.0.1", preferred_port=9000),
                                    server,
                                )
                                thread.assert_called_once_with(
                                    target=server.serve_forever, daemon=True,
                                )
                                thread.return_value.start.assert_called_once_with()
                    handler = factory.call_args_list[0][0][1]
                    ports = [9000] if failed_attempts == 0 else [9000, 0]
                    self.assertEqual(factory.call_args_list, [
                        call(("127.0.0.1", port), handler) for port in ports
                    ])

    def test_requested_paths(self):
        handler_class = slopbro.make_tracking_handler(
            None, slopbro.RequestedFilesTracker(slopbro.required_files()),
            slopbro.required_files(), True, False,
        )
        handler = object.__new__(handler_class)
        for path, expected in (
            ("/", "index.html"),
            ("/index%2Ehtml?debug", "index.html"),
            ("/caf%C3%A9", "caf\u00e9"),
            ("/%ED%A0%80", "\ud800"),
            ("/%FF", None),
            ("/%C3", None),
            ("../missing", None),
        ):
            handler.path = path
            self.assertEqual(handler._requested_rel_path(), expected)

    def test_payload_headers_disable_caching(self):
        handler_class = slopbro.make_tracking_handler(
            None, slopbro.RequestedFilesTracker(slopbro.required_files()),
            slopbro.required_files(), True, False,
        )
        handler = object.__new__(handler_class)
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.guess_type = Mock(return_value="text/html")
        result = handler._send_bytes("index.html", b"data")
        headers = {c.args[0]: c.args[1] for c in handler.send_header.call_args_list}
        self.assertEqual(
            headers["Cache-Control"], "no-store, no-cache, must-revalidate",
        )
        self.assertEqual(headers["Pragma"], "no-cache")
        self.assertEqual(result.read(), b"data")

    def test_tracker_ignores_unexpected_client(self):
        tracker = slopbro.RequestedFilesTracker(["package.json"])
        handler_class = slopbro.make_tracking_handler(
            None, tracker, ["index.html", "package.json"], True, False,
            expected_client="192.168.1.50",
        )
        handler = object.__new__(handler_class)
        with patch.object(slopbro, "log"):
            handler.client_address = ("10.0.0.9", 1234)
            handler._mark_served_file("package.json")
            self.assertFalse(tracker.wait_for_all(0.01))
            handler.client_address = ("192.168.1.50", 1234)
            handler._mark_served_file("package.json")
        self.assertTrue(tracker.wait_for_all(0.01))

    def test_status_tracker(self):
        tracker = slopbro.RequestedFilesTracker([])
        self.assertFalse(tracker.wait_for_status(0.01))
        self.assertIsNone(tracker.get_status())
        tracker.set_status("ok")
        self.assertTrue(tracker.wait_for_status(0.01))
        self.assertEqual(tracker.get_status(), "ok")

    def _status_handler(self, tracker, client="192.168.1.50"):
        handler_class = slopbro.make_tracking_handler(
            None, tracker, [], True, False, expected_client="192.168.1.50",
        )
        handler = object.__new__(handler_class)
        handler.client_address = (client, 1234)
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.send_error = Mock()
        return handler

    def test_status_endpoint(self):
        tracker = slopbro.RequestedFilesTracker([])
        handler = self._status_handler(tracker)
        handler.path = slopbro.STATUS_PATH + "?result=ok"
        with patch.object(slopbro, "log"):
            handler._handle_status()
        self.assertEqual(tracker.get_status(), "ok")
        handler.send_response.assert_called_once_with(204)
        handler.send_error.assert_not_called()

    def test_status_endpoint_rejects_unexpected_client(self):
        tracker = slopbro.RequestedFilesTracker([])
        handler = self._status_handler(tracker, client="10.0.0.9")
        handler.path = slopbro.STATUS_PATH + "?result=failed"
        with patch.object(slopbro, "log"):
            handler._handle_status()
        self.assertIsNone(tracker.get_status())
        handler.send_error.assert_called_once_with(403, "Forbidden")

    def test_status_endpoint_rejects_bad_result(self):
        tracker = slopbro.RequestedFilesTracker([])
        handler = self._status_handler(tracker)
        handler.path = slopbro.STATUS_PATH + "?result=maybe"
        handler._handle_status()
        self.assertIsNone(tracker.get_status())
        handler.send_error.assert_called_once_with(400, "Bad Request")

    def test_head_does_not_mark_file(self):
        for command, expected in (("HEAD", False), ("GET", True)):
            with self.subTest(command=command):
                tracker = slopbro.RequestedFilesTracker(["a"])
                handler_class = slopbro.make_tracking_handler(
                    None, tracker, ["a"], True, False,
                )
                handler = object.__new__(handler_class)
                handler.command = command
                handler.path = "/a"
                handler._send_bytes = Mock(return_value=object())
                with patch.object(slopbro, "_read_embedded_file", return_value=b"x"):
                    handler.send_head()
                self.assertEqual(tracker.wait_for_all(0.01), expected)

    def test_connection_logging(self):
        handler = object.__new__(slopbro.make_test_connection_handler())
        handler.client_address = ("127.0.0.1", 12345)
        with patch.object(slopbro, "log") as logger:
            handler.log_message("status %s", 200)
        logger.assert_called_once_with("request from 127.0.0.1: status 200")


class Python3CleanupTests(unittest.TestCase):
    def test_websocket_frame_masking(self):
        sock = Mock()
        client = slopbro.WebSocket(sock)
        with patch.object(slopbro.os, "urandom", return_value=b"\x01\x02\x03\x04") as random:
            client._send_frame(client.OP_TEXT, b"abc")
        random.assert_called_once_with(4)
        sock.sendall.assert_called_once_with(b"\x81\x83\x01\x02\x03\x04" + b"\x60" * 3)

    def test_websocket_close_ignores_connection_errors(self):
        for error_type in (OSError, ssl.SSLError, slopbro.WebSocketError):
            with self.subTest(error_type=error_type):
                sock = Mock()
                sock.sendall.side_effect = error_type("disconnected")
                sock.close.side_effect = OSError("already closed")
                client = slopbro.WebSocket(sock)
                client.close()
                self.assertTrue(client.closed)
                sock.close.assert_called_once_with()

    def test_route_lookup_closes_socket(self):
        for failure in (None, "connect", "getsockname"):
            with self.subTest(failure=failure):
                with patch.object(slopbro.socket, "socket") as factory:
                    sock = factory.return_value.__enter__.return_value
                    sock.getsockname.return_value = ("192.168.1.2", 12345)
                    if failure:
                        getattr(sock, failure).side_effect = OSError("no route")
                    result = slopbro._route_selected_local_ip("192.168.1.50", 80)
                self.assertEqual(result, None if failure else "192.168.1.2")
                factory.assert_called_once_with(
                    slopbro.socket.AF_INET, slopbro.socket.SOCK_DGRAM,
                )
                sock.connect.assert_called_once_with(("192.168.1.50", 80))
                factory.return_value.__exit__.assert_called_once_with(None, None, None)

    def test_tls_client_context(self):
        with patch.object(slopbro.socket, "create_connection") as connect:
            with patch.object(ssl.SSLContext, "wrap_socket", autospec=True) as wrap:
                with patch.object(slopbro.WebSocket, "_handshake") as handshake:
                    client = slopbro.WebSocket.connect("tv.local", 3001)
        context = wrap.call_args[0][0]
        self.assertEqual(context.protocol, ssl.PROTOCOL_TLS_CLIENT)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        wrap.assert_called_once_with(
            context, connect.return_value, server_hostname="tv.local",
        )
        self.assertIs(client._sock, wrap.return_value)
        handshake.assert_called_once_with("tv.local", 3001, True)

    def test_embedded_base64(self):
        for encoded in ("AP9hc3NldA==", b"AP9hc3NldA=="):
            with self.subTest(encoded=encoded):
                with patch.object(slopbro, "EMBEDDED_WWWROOT", {
                    "index.html": {"data": encoded},
                }):
                    self.assertEqual(
                        slopbro._read_embedded_file("index.html"), b"\x00\xffasset",
                    )

    def test_key_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "keys", "tv.key")
            with patch.object(slopbro, "key_path", return_value=path):
                self.assertEqual(slopbro.load_client_key("tv"), "")
                for key in ("first-key", "replacement-key"):
                    slopbro.save_client_key("tv", key)
                    self.assertEqual(slopbro.load_client_key("tv"), key)
                with patch("builtins.open", side_effect=OSError("denied")):
                    with patch.object(slopbro, "log") as logger:
                        slopbro.save_client_key("tv", "unsaved-key")
                    logger.assert_called_once()
                    self.assertIn("could not save client key", logger.call_args[0][0])

    def test_key_path_sanitizes_host(self):
        with patch.object(slopbro.os, "getcwd", return_value="/keys"):
            self.assertEqual(slopbro.key_path("tv.local"), "/keys/tv.local.key")
            self.assertEqual(slopbro.key_path("../evil"), "/keys/evil.key")
            self.assertEqual(slopbro.key_path("..\\evil"), "/keys/evil.key")

    def test_self_hosted_url_encoding(self):
        url = slopbro.build_self_hosted_url(
            "192.168.1.50", 8080,
            local_ip_override="192.168.1.10",
            fake_service_path="/x&debug#f y",
            telnet=True, leave_script=True,
            download_dirs=["/media/internal/downloads", "/tmp"],
            no_ipk_checksum=True,
        )
        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        self.assertEqual(query["script"], ["autoroot.sh"])
        self.assertEqual(query["files"], ["package.json;main.js"])
        self.assertEqual(query["fake-service-path"], ["/x&debug#f y"])
        self.assertEqual(
            query["download-dirs"], ["/media/internal/downloads;/tmp"],
        )
        self.assertIn("telnet", query)
        self.assertIn("leave-script", query)
        self.assertIn("no-ipk-checksum", query)

    def test_local_ip_rejects_loopback_only(self):
        with patch.object(slopbro.socket, "gethostbyname", return_value="192.168.1.50"):
            with patch.object(slopbro, "_route_selected_local_ip", return_value="127.0.0.1"):
                with self.assertRaises(RuntimeError):
                    slopbro.local_ip_for_remote("tv.local")

    def test_resolve_client_ip(self):
        with patch.object(slopbro.socket, "gethostbyname", return_value="192.168.1.50"):
            self.assertEqual(slopbro.resolve_client_ip("tv.local"), "192.168.1.50")
        with patch.object(slopbro.socket, "gethostbyname", side_effect=OSError("no")):
            self.assertIsNone(slopbro.resolve_client_ip("tv.local"))
        self.assertIsNone(slopbro.resolve_client_ip(None))

    def test_register_falls_back_without_stale_key(self):
        client = Mock()
        client.register.side_effect = [
            slopbro.SSAPError("registration rejected"), "new-key",
        ]
        with patch.object(slopbro, "log"):
            key = slopbro.register_with_fallback(client, "old-key")
        self.assertEqual(key, "new-key")
        self.assertEqual(client.register.call_args_list, [
            call("old-key", slopbro.DEFAULT_MANIFEST),
            call("", slopbro.DEFAULT_MANIFEST),
        ])

    def test_register_does_not_retry_on_timeout_or_missing_key(self):
        for stored_key, message in (
            ("old-key", "timed out waiting for registration"),
            ("", "registration rejected"),
        ):
            with self.subTest(stored_key=stored_key):
                client = Mock()
                client.register.side_effect = slopbro.SSAPError(message)
                with self.assertRaises(slopbro.SSAPError):
                    slopbro.register_with_fallback(client, stored_key)
                self.assertEqual(client.register.call_count, 1)

    def test_websocket_reassembles_text_fragments(self):
        def server_frame(opcode, payload, fin=True):
            header = bytearray([(0x80 if fin else 0) | opcode])
            length = len(payload)
            if length < 126:
                header.append(length)
            elif length < 65536:
                header.append(126)
                header += struct.pack("!H", length)
            else:
                header.append(127)
                header += struct.pack("!Q", length)
            return bytes(header) + payload

        data = (
            server_frame(0x1, b"hello", fin=False)
            + server_frame(0x9, b"ping")
            + server_frame(0x0, b" world")
        )
        sock = Mock()
        sock.recv.side_effect = [data]
        client = slopbro.WebSocket(sock)
        with patch.object(client, "_send_frame") as send:
            self.assertEqual(client.recv_text(), "hello world")
        send.assert_called_once_with(client.OP_PONG, b"ping")

    def test_websocket_ignores_orphan_continuation(self):
        def server_frame(opcode, payload, fin=True):
            header = bytearray([(0x80 if fin else 0) | opcode, len(payload)])
            return bytes(header) + payload

        data = server_frame(0x0, b"orphan") + server_frame(0x1, b"real")
        sock = Mock()
        sock.recv.side_effect = [data]
        client = slopbro.WebSocket(sock)
        self.assertEqual(client.recv_text(), "real")

    def test_websocket_rejects_oversized_frame(self):
        header = (
            struct.pack("!BB", 0x81, 127)
            + struct.pack("!Q", slopbro.MAX_FRAME_BYTES + 1)
        )
        sock = Mock()
        sock.recv.side_effect = [header]
        client = slopbro.WebSocket(sock)
        with self.assertRaises(slopbro.WebSocketError):
            client._read_frame()

    def test_websocket_rejects_oversized_headers(self):
        sock = Mock()
        sock.recv.return_value = b"A" * (slopbro.MAX_HTTP_HEADER_BYTES + 1)
        client = slopbro.WebSocket(sock)
        with self.assertRaises(slopbro.WebSocketError):
            client._read_http_headers()


@unittest.skipIf(sys.version_info < (3, 12), "packaging tool requires Python 3.12+")
class PackageToolTests(unittest.TestCase):
    def setUp(self):
        self.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.tool = os.path.join(self.repo_root, "tools", "package_single_file.py")

    def _run(self, files, out):
        return subprocess.run(
            [
                sys.executable, self.tool,
                "--source", "slopbro.py",
                "--wwwroot", "wwwroot",
                "--out", out,
                "--files", *files,
            ],
            cwd=self.repo_root, capture_output=True, text=True,
        )

    def test_rejects_assets_outside_wwwroot(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.py")
            for files in (
                ["../slopbro.py"],
                [os.path.join(self.repo_root, "slopbro.py")],
            ):
                with self.subTest(files=files):
                    result = self._run(files, out)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("asset path", result.stderr)
                    self.assertFalse(os.path.exists(out))

    def test_embeds_valid_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.py")
            result = self._run(["index.html"], out)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(os.path.isfile(out))

    def test_normalizes_dot_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.py")
            result = self._run(["./index.html"], out)
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(out, "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn('"index.html"', text)
            self.assertNotIn('"./index.html"', text)

    def test_out_and_in_place_are_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable, self.tool,
                    "--source", "slopbro.py",
                    "--wwwroot", "wwwroot",
                    "--out", os.path.join(tmp, "out.py"),
                    "--in-place",
                    "--files", "index.html",
                ],
                cwd=self.repo_root, capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not allowed with argument", result.stderr)


class JavascriptTests(unittest.TestCase):
    def test_download_dir_retry_logic(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("node is not available")
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = os.path.join(repo_root, "tests", "js_retry_test.js")
        result = subprocess.run(
            [node, script], cwd=repo_root, capture_output=True, text=True,
        )
        self.assertEqual(
            result.returncode, 0, result.stderr + result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
