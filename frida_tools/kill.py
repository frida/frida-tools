# -*- coding: utf-8 -*-
from __future__ import print_function

import frida
from frida_tools.application import ConsoleApplication, infer_target, expand_target


class KillApplication(ConsoleApplication):
    def _usage(self):
        return "%(prog)s [options] process"

    def _add_options(self, parser):
        parser.add_argument("process", help="process name or pid")

    def _initialize(self, parser, options, args):
        process = expand_target(infer_target(options.process))
        if process[0] == 'file':
            parser.error('process name or pid must be specified')

        self._process = process[1]

    def _start(self):
        try:
            self._device.kill(self._process)
        except frida.ProcessNotFoundError:
            self._update_status('unable to find process: %s' % self._process)
            self._exit(1)
        self._exit(0)


def main():
    app = KillApplication()
    app.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
