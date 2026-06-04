"""Tests for the libreg Python client.

These run against an in process mock agent: a stdlib ``http.server`` that
implements just enough of the CONTRACTS.md envelope to exercise the client end
to end (request method, path, body, the GET with body transport, envelope
parsing, error mapping, and value encoding). No real agent binary, no network,
no external dependencies. Run with::

    python3 -m unittest discover -s clients/python/tests
"""

import base64
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from libreg import (  # noqa: E402
    Agent,
    ErrorCode,
    RegError,
    RegType,
    TransportError,
    decode_data,
    encode_data,
)


class _MockAgent(BaseHTTPRequestHandler):
    """A tiny stand in for the libreg agent.

    Records the last request (method, path, parsed body) on the server so a
    test can assert what the client sent, and returns canned envelopes keyed by
    path. A path may be registered to return a logical error envelope instead.
    """

    def log_message(self, *args):
        pass  # keep test output quiet

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _respond(self, envelope):
        payload = json.dumps(envelope).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self, method):
        body = self._read_body()
        self.server.last = (method, self.path, body)
        err = self.server.errors.get(self.path)
        if err is not None:
            code, message = err
            self._respond({"ok": False, "error": message, "code": code, "data": None})
            return
        data = self.server.responses.get(self.path, {})
        if callable(data):
            data = data(body)
        self._respond({"ok": True, "error": None, "data": data})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockAgent)
        self.server.responses = {}
        self.server.errors = {}
        self.server.last = None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.agent = Agent(host=host, port=port, timeout=5.0)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5.0)

    # --- handshake ---

    def test_version(self):
        self.server.responses["/version"] = {
            "agent": "linux",
            "protocol": "0.1.0",
            "backend": "libreg-0.1.0",
        }
        hs = self.agent.version()
        self.assertEqual(hs.agent, "linux")
        self.assertEqual(hs.backend, "libreg-0.1.0")
        # Reads are GET and still carry a JSON body (CONTRACTS.md / ADR 0001).
        method, path, _ = self.server.last
        self.assertEqual((method, path), ("GET", "/version"))

    # --- hive lifecycle ---

    def test_create_save_close(self):
        self.server.responses["/hive/create"] = {"handle": "h_1"}
        self.server.responses["/hive/save"] = {"bytes_written": 8192}
        self.server.responses["/hive/close"] = {}
        hive = self.agent.create("/tmp/x.hiv")
        self.assertEqual(hive.handle, "h_1")
        _, path, body = self.server.last
        self.assertEqual((path, body), ("/hive/create", {"path": "/tmp/x.hiv"}))
        self.assertEqual(hive.save(), 8192)
        hive.close()
        self.assertTrue(hive.closed)
        # close is idempotent and a closed handle refuses further work.
        hive.close()
        with self.assertRaises(ValueError):
            hive.create_key("Software")

    def test_context_manager_closes(self):
        self.server.responses["/hive/create"] = {"handle": "h_ctx"}
        self.server.responses["/hive/close"] = {}
        with self.agent.create("/tmp/x.hiv") as hive:
            self.assertFalse(hive.closed)
        self.assertTrue(hive.closed)
        self.assertEqual(self.server.last[1], "/hive/close")

    # --- keys ---

    def test_key_ops(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        self.server.responses["/key/create"] = {}
        self.server.responses["/key/delete"] = {}
        self.server.responses["/key/rename"] = {}
        self.server.responses["/key/list"] = {
            "subkeys": ["Foo", "Bar"],
            "values": ["", "Greeting"],
        }
        self.server.responses["/key/info"] = {
            "last_write": "2026-01-01T00:00:00Z",
            "class_name": None,
            "subkey_count": 2,
            "value_count": 2,
        }
        hive = self.agent.create("/tmp/x.hiv")

        hive.create_key("Software\\Foo")
        _, path, body = self.server.last
        self.assertEqual(path, "/key/create")
        self.assertEqual(body, {"handle": "h", "path": "Software\\Foo"})

        hive.delete_key("Software\\Foo", recursive=True)
        self.assertEqual(self.server.last[2]["recursive"], True)

        hive.rename_key("Software\\Foo", "Baz")
        self.assertEqual(self.server.last[2]["new_name"], "Baz")

        listing = hive.list_key("Software")
        self.assertEqual(listing.subkeys, ["Foo", "Bar"])
        self.assertEqual(listing.values, ["", "Greeting"])

        info = hive.key_info("Software")
        self.assertEqual(info.subkey_count, 2)
        self.assertIsNone(info.class_name)

        # An empty path means the hive root and must be sent as "".
        hive.list_key()
        self.assertEqual(self.server.last[2]["path"], "")

    # --- values: encoding round trips through the wire shapes ---

    def test_value_set_encoding(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        self.server.responses["/value/set"] = {}
        hive = self.agent.create("/tmp/x.hiv")

        cases = [
            (RegType.SZ, "hello", "hello"),
            (RegType.EXPAND_SZ, "%PATH%", "%PATH%"),
            (RegType.LINK, "\\Registry\\X", "\\Registry\\X"),
            (RegType.DWORD, 4096, 4096),
            (RegType.DWORD_BE, 1, 1),
            (RegType.MULTI_SZ, ["a", "b"], ["a", "b"]),
            (RegType.NONE, None, None),
            (RegType.BINARY, b"\x00\x01\x02", base64.b64encode(b"\x00\x01\x02").decode()),
            (RegType.QWORD, 42, 42),
            (RegType.QWORD, 2 ** 60, str(2 ** 60)),  # > 2^53 sent as a string
        ]
        for reg_type, value, wire in cases:
            hive.set_value("Software", "V", reg_type, value)
            body = self.server.last[2]
            self.assertEqual(body["type"], reg_type.value, reg_type)
            self.assertEqual(body["data"], wire, reg_type)

    def test_value_get_decoding(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        hive = self.agent.create("/tmp/x.hiv")

        self.server.responses["/value/get"] = {
            "type": "REG_BINARY",
            "data": base64.b64encode(b"\xde\xad").decode(),
        }
        v = hive.get_value("Software", "Blob")
        self.assertEqual(v.type, RegType.BINARY)
        self.assertEqual(v.data, b"\xde\xad")

        self.server.responses["/value/get"] = {"type": "REG_QWORD", "data": str(2 ** 60)}
        v = hive.get_value("Software", "Big")
        self.assertEqual(v.data, 2 ** 60)

        self.server.responses["/value/get"] = {
            "type": "REG_MULTI_SZ",
            "data": ["x", "y"],
        }
        v = hive.get_value("Software", "List")
        self.assertEqual(v.data, ["x", "y"])

    def test_default_value_name_is_empty_string(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        self.server.responses["/value/set"] = {}
        hive = self.agent.create("/tmp/x.hiv")
        hive.set_value("", "", RegType.SZ, "default")
        body = self.server.last[2]
        self.assertEqual(body["key"], "")
        self.assertEqual(body["name"], "")

    # --- security ---

    def test_security(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        sddl = "O:BAG:BAD:(A;CI;KA;;;SY)"
        self.server.responses["/key/security"] = lambda body: (
            {"sddl": sddl} if "sddl" not in body else {}
        )
        hive = self.agent.create("/tmp/x.hiv")

        self.assertEqual(hive.get_security("Software"), sddl)
        self.assertEqual(self.server.last[0], "GET")  # read is GET

        hive.set_security("Software", sddl)
        self.assertEqual(self.server.last[0], "POST")  # write is POST
        self.assertEqual(self.server.last[2]["sddl"], sddl)

    # --- diagnostics ---

    def test_diagnostics(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        self.server.responses["/hive/dump"] = {"canonical_json": {"root": {"name": ""}}}
        self.server.responses["/hive/checksum"] = {
            "sha256_file": "aa",
            "sha256_canonical": "bb",
        }
        self.server.responses["/hive/validate"] = {
            "valid": True,
            "errors": [],
            "warnings": ["w"],
        }
        hive = self.agent.create("/tmp/x.hiv")
        self.assertEqual(hive.dump(), {"root": {"name": ""}})
        cs = hive.checksum()
        self.assertEqual((cs.sha256_file, cs.sha256_canonical), ("aa", "bb"))
        val = hive.validate()
        self.assertTrue(val.valid)
        self.assertEqual(val.warnings, ["w"])

    def test_crash_save_targets_test_endpoint(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        self.server.responses["/test/crash_save"] = {
            "bytes_written": 10,
            "crashed_at": "after_first_log",
        }
        hive = self.agent.create("/tmp/x.hiv")
        out = hive.crash_save("after_first_log")
        self.assertEqual(out["crashed_at"], "after_first_log")
        self.assertEqual(self.server.last[1], "/test/crash_save")

    # --- error handling ---

    def test_logical_error_raises_regerror(self):
        self.server.responses["/hive/create"] = {"handle": "h"}
        self.server.errors["/key/create"] = (ErrorCode.KEY_EXISTS, "key already exists: X")
        hive = self.agent.create("/tmp/x.hiv")
        with self.assertRaises(RegError) as ctx:
            hive.create_key("X")
        self.assertEqual(ctx.exception.code, ErrorCode.KEY_EXISTS)
        self.assertIn("already exists", ctx.exception.message)

    def test_transport_error_on_refused_connection(self):
        # Point at a port nothing is listening on.
        agent = Agent(host="127.0.0.1", port=1, timeout=1.0)
        with self.assertRaises(TransportError):
            agent.version()


class CodecTest(unittest.TestCase):
    """Direct unit tests for the value codec, independent of the wire."""

    def test_binary_round_trip(self):
        raw = bytes(range(256))
        wire = encode_data(RegType.BINARY, raw)
        self.assertIsInstance(wire, str)
        self.assertEqual(decode_data(RegType.BINARY, wire), raw)

    def test_dword_range_validation(self):
        with self.assertRaises(ValueError):
            encode_data(RegType.DWORD, 2 ** 32)
        with self.assertRaises(TypeError):
            encode_data(RegType.DWORD, "7")
        # bool is not an int here, even though Python says it is.
        with self.assertRaises(TypeError):
            encode_data(RegType.DWORD, True)

    def test_qword_threshold(self):
        self.assertEqual(encode_data(RegType.QWORD, 2 ** 53), 2 ** 53)
        self.assertEqual(encode_data(RegType.QWORD, 2 ** 53 + 1), str(2 ** 53 + 1))

    def test_multi_sz_rejects_bare_string(self):
        with self.assertRaises(TypeError):
            encode_data(RegType.MULTI_SZ, "not a list")

    def test_none_must_be_none(self):
        self.assertIsNone(encode_data(RegType.NONE, None))
        with self.assertRaises(TypeError):
            encode_data(RegType.NONE, "x")

    def test_from_wire_and_code(self):
        self.assertIs(RegType.from_wire("REG_SZ"), RegType.SZ)
        self.assertEqual(RegType.DWORD.code, 4)
        self.assertEqual(RegType.QWORD.code, 11)
        with self.assertRaises(ValueError):
            RegType.from_wire("REG_NOPE")


if __name__ == "__main__":
    unittest.main()
