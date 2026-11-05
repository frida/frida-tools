import unittest

from frida_tools.ps import _enumerate_with_icon_fallback


class TestPSEnumerationFallback(unittest.TestCase):
    def test_full_scope_failure_is_retried_without_icons(self):
        device = FakeDevice(fail_scopes={"full"})
        warnings = []
        processes = _enumerate_with_icon_fallback(device.enumerate_processes, "full", warnings.append)
        self.assertEqual(processes, ["init"])
        self.assertEqual(device.calls, ["full", "minimal"])
        self.assertEqual(len(warnings), 1)
        self.assertIn("could not load icons", str(warnings[0]))

    def test_full_scope_success_is_returned_as_is(self):
        device = FakeDevice(fail_scopes=set())
        warnings = []
        processes = _enumerate_with_icon_fallback(device.enumerate_processes, "full", warnings.append)
        self.assertEqual(processes, ["init"])
        self.assertEqual(device.calls, ["full"])
        self.assertEqual(warnings, [])

    def test_minimal_scope_failure_is_propagated(self):
        device = FakeDevice(fail_scopes={"minimal"})
        with self.assertRaises(RuntimeError):
            _enumerate_with_icon_fallback(device.enumerate_processes, "minimal", lambda e: None)
        self.assertEqual(device.calls, ["minimal"])

    def test_failure_that_is_not_about_icons_is_not_reported_as_one(self):
        device = FakeDevice(fail_scopes={"full", "minimal"})
        warnings = []
        with self.assertRaises(RuntimeError):
            _enumerate_with_icon_fallback(device.enumerate_processes, "full", warnings.append)
        self.assertEqual(device.calls, ["full", "minimal"])
        self.assertEqual(warnings, [])


class FakeDevice:
    def __init__(self, fail_scopes):
        self.fail_scopes = fail_scopes
        self.calls = []

    def enumerate_processes(self, scope="minimal"):
        self.calls.append(scope)
        if scope in self.fail_scopes:
            raise RuntimeError(f"could not load icons for {scope}")
        return ["init"]
