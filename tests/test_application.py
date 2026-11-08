import os
import sys
import threading
import unittest
from unittest import mock

import frida

from frida_tools.application import input_with_cancellable


@unittest.skipIf(sys.platform == "win32", "stdin is not polled on Windows")
class InputWithCancellableTestCase(unittest.TestCase):
    def test_returns_line(self):
        self.assertEqual(self._read_from_pipe(b"hello\n"), "hello\n")

    def test_waits_for_cancellation_at_eof(self):
        with self.assertRaises(frida.OperationCancelledError):
            self._read_from_pipe(b"")

    def test_returns_at_eof_on_terminal(self):
        import pty

        master, slave = pty.openpty()
        try:
            os.write(master, b"\x04")
            cancellable = frida.Cancellable()
            timer = threading.Timer(0.2, cancellable.cancel)
            timer.start()
            try:
                with os.fdopen(slave, closefd=False) as stdin, mock.patch.object(sys, "stdin", stdin):
                    self.assertEqual(input_with_cancellable(cancellable), "")
            finally:
                timer.cancel()
        finally:
            os.close(master)
            os.close(slave)

    def _read_from_pipe(self, data):
        rfd, wfd = os.pipe()
        os.write(wfd, data)
        os.close(wfd)
        cancellable = frida.Cancellable()
        timer = threading.Timer(0.2, cancellable.cancel)
        timer.start()
        try:
            with os.fdopen(rfd) as stdin, mock.patch.object(sys, "stdin", stdin):
                return input_with_cancellable(cancellable)
        finally:
            timer.cancel()
