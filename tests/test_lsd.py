import contextlib
import io
import sys
import unittest
from unittest import mock

import frida

from frida_tools import lsd


class FakeDevice:
    def __init__(self, id, type, name, os):
        self.id = id
        self.type = type
        self.name = name
        self._os = os

    def query_system_parameters(self):
        if self._os is None:
            raise frida.ServerNotRunningError("unable to connect to remote frida-server")
        return {"os": self._os}


class TestLSD(unittest.TestCase):
    @mock.patch("signal.signal")
    @mock.patch("frida.shutdown")
    @mock.patch("frida.enumerate_devices")
    @mock.patch.object(sys, "stdin", io.StringIO())
    @mock.patch.object(sys, "argv", ["frida-ls-devices"])
    def test_list_without_terminal(self, enumerate_devices, shutdown, signal_):
        enumerate_devices.return_value = [
            FakeDevice("socket", "remote", "Local Socket", None),
            FakeDevice("local", "local", "Local System", {"id": "ubuntu", "name": "Ubuntu", "version": "24.04"}),
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as cm:
            lsd.main()
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(
            output.getvalue(),
            "Id      Type    Name          OS\n"
            "------  ------  ------------  ------------\n"
            "local   local   Local System  Ubuntu 24.04\n"
            "socket  remote  Local Socket\n",
        )
