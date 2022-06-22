# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import codecs
import os
import sys
from threading import Event, Thread
import time

from colorama import Fore, Style

from frida_tools.application import ConsoleApplication
from frida_tools.stream_controller import DisposedException, StreamController
from frida_tools.units import bytes_to_megabytes


def main():
    app = PushApplication()
    app.run()


class PushApplication(ConsoleApplication):
    def _add_options(self, parser):
        parser.add_argument("files", help="local files to push", nargs="+")

    def _usage(self):
        return "%(prog)s [options] LOCAL... REMOTE"

    def _initialize(self, parser, options, args):
        paths = options.files
        if len(paths) == 1:
            raise ValueError("missing remote path")
        self._local_paths = paths[:-1]
        self._remote_path = paths[-1]

        self._script = None
        self._stream_controller = None
        self._total_bytes = 0
        self._time_started = None
        self._completed = Event()
        self._transfers = {}

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

            script = self._session.create_script(name="push", source=source)
            self._script = script
            script.on("message", on_message)
            script.load()

            self._stream_controller = StreamController(self._post_stream_stanza,
                                                       on_stats_updated=self._on_stream_stats_updated)

            worker = Thread(target=self._perform_push)
            worker.start()
        except Exception as e:
            self._update_status("Failed to push: {}".format(e))
            self._exit(1)
            return

    def _stop(self):
        for path in self._local_paths:
            if path not in self._transfers:
                self._complete_transfer(path, success=False)

        if self._stream_controller is not None:
            self._stream_controller.dispose()

    def _perform_push(self):
        for path in self._local_paths:
            try:
                self._total_bytes += os.path.getsize(path)
            except:
                pass
        self._time_started = time.time()

        for i, path in enumerate(self._local_paths):
            filename = os.path.basename(path)

            try:
                with open(path, "rb") as f:
                    sink = self._stream_controller.open(str(i), {
                        "filename": filename,
                        "target": self._remote_path
                    })
                    while True:
                        chunk = f.read(4 * 1024 * 1024)
                        if len(chunk) == 0:
                            break
                        sink.write(chunk)
                    sink.close()
            except DisposedException as e:
                break
            except Exception as e:
                self._print_error(str(e))
                self._complete_transfer(path, success=False)

        self._completed.wait()

        self._reactor.schedule(lambda: self._on_push_finished())

    def _on_push_finished(self):
        successes = self._transfers.values()

        if any(successes):
            self._render_summary_ui()

        status = 0 if all(successes) else 1
        self._exit(status)

    def _render_progress_ui(self):
        if self._completed.is_set():
            return
        megabytes_sent = bytes_to_megabytes(self._stream_controller.bytes_sent)
        total_megabytes = bytes_to_megabytes(self._total_bytes)
        if total_megabytes != 0 and megabytes_sent <= total_megabytes:
            self._update_status("Pushed {:.1f} out of {:.1f} MB".format(megabytes_sent, total_megabytes))
        else:
            self._update_status("Pushed {:.1f} MB".format(megabytes_sent))

    def _render_summary_ui(self):
        duration = time.time() - self._time_started

        if len(self._local_paths) == 1:
            prefix = "{}: ".format(self._local_paths[0])
        else:
            prefix = ""

        files_transferred = sum(map(int, self._transfers.values()))

        sc = self._stream_controller
        bytes_sent = sc.bytes_sent
        megabytes_per_second = bytes_to_megabytes(bytes_sent) / duration

        self._update_status("{}{} file{} pushed. {:.1f} MB/s ({} bytes in {:.3f}s)" \
                .format(prefix,
                        files_transferred,
                        "s" if files_transferred != 1 else "",
                        megabytes_per_second,
                        bytes_sent,
                        duration))

    def _on_message(self, message, data):
        handled = False

        if message["type"] == "send":
            payload = message["payload"]
            ptype = payload["type"]
            if ptype == "stream":
                stanza = payload["payload"]
                self._stream_controller.receive(stanza, data)
                handled = True
            elif ptype == "push:io-success":
                index = payload["index"]
                self._on_io_success(self._local_paths[index])
                handled = True
            elif ptype == "push:io-error":
                index = payload["index"]
                self._on_io_error(self._local_paths[index], payload["error"])
                handled = True

        if not handled:
            self._print(message)

    def _on_io_success(self, local_path):
        self._complete_transfer(local_path, success=True)

    def _on_io_error(self, local_path, error):
        self._print_error("{}: {}".format(local_path, error))
        self._complete_transfer(local_path, success=False)

    def _complete_transfer(self, local_path, success):
        self._transfers[local_path] = success
        if len(self._transfers) == len(self._local_paths):
            self._completed.set()

    def _post_stream_stanza(self, stanza, data=None):
        self._script.post({
            "type": "stream",
            "payload": stanza
        }, data=data)

    def _on_stream_stats_updated(self):
        self._render_progress_ui()

    def _print_error(self, message):
        self._print(Fore.RED + Style.BRIGHT + message + Style.RESET_ALL, file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
