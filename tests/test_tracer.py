import contextlib
import io
import subprocess
import threading
import time
import unittest

import frida

from frida_tools.reactor import Reactor
from frida_tools.tracer import (
    UI,
    MemoryRepository,
    Tracer,
    TracerProfileBuilder,
    TraceTarget,
    compute_allowed_ui_origins,
)

from .data import target_program


class TestTracer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.target = subprocess.Popen([target_program], stdin=subprocess.PIPE)
        # TODO: improve injectors to handle injection into a process that hasn't yet finished initializing
        time.sleep(0.05)
        cls.session = frida.attach(cls.target.pid)

    @classmethod
    def tearDownClass(cls):
        cls.session.detach()
        cls.target.terminate()
        cls.target.stdin.close()
        cls.target.wait()

    def test_basics(self):
        thread_errors = []
        previous_excepthook = threading.excepthook
        threading.excepthook = lambda args: thread_errors.append(args.exc_value)
        try:
            done = threading.Event()
            reactor = Reactor(lambda reactor: done.wait())

            def start():
                tp = TracerProfileBuilder().include("open*")
                t = Tracer(reactor, MemoryRepository(), tp.build())
                t.start_trace(self.session, "late", {}, "qjs", UI())
                t.stop()
                reactor.stop()
                done.set()

            reactor.schedule(start)
            reactor.run()
        finally:
            threading.excepthook = previous_excepthook

        self.assertEqual(thread_errors, [])


class TestTracerStopped(unittest.TestCase):
    def test_message_after_stop_is_ignored(self):
        tracer = Tracer(Reactor(lambda reactor: None), MemoryRepository(), TracerProfileBuilder().build())
        tracer.stop()

        message = {
            "type": "send",
            "payload": {
                "type": "handlers:get",
                "flavor": "c",
                "baseId": 1,
                "scopes": [{"name": "libc.so.6", "members": ["open"]}],
            },
        }
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            tracer._on_message(message, None, UI())

        self.assertEqual(output.getvalue(), "")


class TestMemoryRepository(unittest.TestCase):
    def test_ensure_handler_reuses_handler_for_same_target(self):
        repo = MemoryRepository()
        created = []
        loaded = []
        repo.on_create(lambda target, handler, source: created.append(target.identifier))
        repo.on_load(lambda target, handler, source: loaded.append(target.identifier))
        target = TraceTarget(1, "c", "libc.so.6", "open", "open", None)

        first = repo.ensure_handler(target)
        second = repo.ensure_handler(target)

        self.assertEqual(first, second)
        self.assertEqual(created, [1])
        self.assertEqual(loaded, [1])


class TestTracerUiOrigins(unittest.TestCase):
    def test_localhost_ui_origin_is_allowed(self):
        origins = compute_allowed_ui_origins("localhost", 2999)
        self.assertEqual(origins, ["http://localhost:2999", "http://localhost:3000"])

    def test_bind_allows_common_local_origins(self):
        origins = compute_allowed_ui_origins("0.0.0.0", 2999)
        self.assertIn("http://0.0.0.0:2999", origins)
        self.assertIn("http://localhost:2999", origins)
        self.assertIn("http://127.0.0.1:2999", origins)
        self.assertIn("http://localhost:3000", origins)
        self.assertIn("http://127.0.0.1:3000", origins)

    def test_ipv6_ui_origin_is_bracketed(self):
        origins = compute_allowed_ui_origins("::1", 2999)
        self.assertEqual(origins, ["http://[::1]:2999", "http://[::1]:3000"])

    def test_ipv6_bind_origin_is_bracketed(self):
        origins = compute_allowed_ui_origins("::", 2999)
        self.assertIn("http://[::]:2999", origins)
        self.assertNotIn("http://:::2999", origins)

    def test_extra_origin_is_allowed(self):
        origins = compute_allowed_ui_origins("localhost", 2999, ["http://example.test:8080"])
        self.assertIn("http://example.test:8080", origins)

    def test_duplicate_origins_are_removed(self):
        origins = compute_allowed_ui_origins("localhost", 2999, ["http://localhost:2999"])
        self.assertEqual(origins.count("http://localhost:2999"), 1)


if __name__ == "__main__":
    unittest.main()
