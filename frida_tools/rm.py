# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import codecs
import os
import sys

from colorama import Fore, Style

from frida_tools.application import ConsoleApplication


def main():
    app = RmApplication()
    app.run()


class RmApplication(ConsoleApplication):
    def _add_options(self, parser):
        parser.add_argument("files", help="files to remove", nargs="+")
        parser.add_argument("-f", "--force", help="ignore nonexistent files", action='store_true')
        parser.add_argument("-r", "--recursive", help="remove directories and their contents recursively", action='store_true')

    def _usage(self):
        return "%(prog)s [options] FILE..."

    def _initialize(self, parser, options, args):
        self._paths = options.files
        self._flags = []
        if options.force:
            self._flags.append("force")
        if options.recursive:
            self._flags.append("recursive")

    def _needs_target(self):
        return False

    def _start(self):
        try:
            self._attach(0)

            data_dir = os.path.dirname(__file__)
            with codecs.open(os.path.join(data_dir, "fs_agent.js"), "r", "utf-8") as f:
                source = f.read()

            def on_message(message, data):
                self._reactor.schedule(lambda: self._on_message(message, data))

            script = self._session.create_script(name="pull", source=source)
            script.on("message", on_message)
            script.load()

            errors = script.exports.rm(self._paths, self._flags)

            for message in errors:
                self._print(Fore.RED + Style.BRIGHT + message + Style.RESET_ALL, file=sys.stderr)

            status = 0 if len(errors) == 0 else 1
            self._exit(status)
        except Exception as e:
            self._update_status(str(e))
            self._exit(1)
            return

    def _on_message(self, message, data):
        print(message)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
