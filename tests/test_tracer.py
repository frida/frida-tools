import subprocess
import threading
import time
import unittest

import frida

from frida_tools.reactor import Reactor
from frida_tools.tracer import UI, MemoryRepository, Tracer, TracerProfileBuilder

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


if __name__ == "__main__":
    unittest.main()
