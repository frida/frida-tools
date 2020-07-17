# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import codecs
import collections
import errno
import numbers
from optparse import OptionParser
import os
import platform
import re
import select
import shlex
import signal
import sys
import threading
import time
if platform.system() == 'Windows':
    import msvcrt

import colorama
from colorama import Cursor, Fore, Style
import frida


AUX_OPTION_PATTERN = re.compile(r"(.+)=\((string|bool|int)\)(.+)")


def input_with_cancellable(cancellable):
    if platform.system() == 'Windows':
        result = ""
        done = False

        while not done:
            while msvcrt.kbhit():
                c = msvcrt.getwche()
                if c in ("\x00", "\xe0"):
                    msvcrt.getwche()
                    continue

                result += c

                if c == "\n":
                    done = True
                    break

            cancellable.raise_if_cancelled()
            time.sleep(0.05)

        return result
    else:
        with cancellable.get_pollfd() as cancellable_fd:
            try:
                rlist, _, _ = select.select([sys.stdin, cancellable_fd], [], [])
            except (OSError, select.error) as e:
                if e.args[0] != errno.EINTR:
                    raise e

        cancellable.raise_if_cancelled()

        return sys.stdin.readline()


def await_enter(reactor):
    try:
        input_with_cancellable(reactor.ui_cancellable)
    except frida.OperationCancelledError:
        pass
    except KeyboardInterrupt:
        print("")


class ConsoleState:
    EMPTY = 1
    STATUS = 2
    TEXT = 3


class ConsoleApplication(object):
    def __init__(self, run_until_return=await_enter, on_stop=None):
        plain_terminal = os.environ.get("TERM", "").lower() == "none"

        colorama.init(strip=True if plain_terminal else None)

        parser = OptionParser(usage=self._usage(), version=frida.__version__)

        if self._needs_device():
            parser.add_option("-D", "--device", help="connect to device with the given ID",
                    metavar="ID", type='string', action='store', dest="device_id", default=None)
            parser.add_option("-U", "--usb", help="connect to USB device",
                    action='store_const', const='usb', dest="device_type", default=None)
            parser.add_option("-R", "--remote", help="connect to remote frida-server",
                    action='store_const', const='remote', dest="device_type", default=None)
            parser.add_option("-H", "--host", help="connect to remote frida-server on HOST",
                    metavar="HOST", type='string', action='store', dest="host", default=None)

        if self._needs_target():
            def store_target(option, opt_str, target_value, parser, target_type, *args, **kwargs):
                if target_type == 'file':
                    target_value = [target_value]
                setattr(parser.values, 'target', (target_type, target_value))
            parser.add_option("-f", "--file", help="spawn FILE", metavar="FILE",
                type='string', action='callback', callback=store_target, callback_args=('file',))
            parser.add_option("-F", "--attach-frontmost", help="attach to frontmost application",
                action='callback', callback=store_target, callback_args=('frontmost',))
            parser.add_option("-n", "--attach-name", help="attach to NAME", metavar="NAME",
                type='string', action='callback', callback=store_target, callback_args=('name',))
            parser.add_option("-p", "--attach-pid", help="attach to PID", metavar="PID",
                type='int', action='callback', callback=store_target, callback_args=('pid',))
            parser.add_option("--stdio", help="stdio behavior when spawning (defaults to “inherit”)", metavar="inherit|pipe",
                type='choice', choices=['inherit', 'pipe'], default='inherit')
            parser.add_option("--aux", help="set aux option when spawning, such as “uid=(int)42” (supported types are: string, bool, int)", metavar="option",
                type='string', action='append', dest="aux", default=[])
            parser.add_option("--runtime", help="script runtime to use", metavar="duk|v8",
                type='choice', choices=['duk', 'v8'], default=None)
            parser.add_option("--debug", help="enable the Node.js compatible script debugger",
                action='store_true', dest="enable_debugger", default=False)
            parser.add_option("--squelch-crash", help="if enabled, will not dump crash report to console",
                action='store_true', dest="squelch_crash", default=False)

        parser.add_option("-O", "--options-file", help="text file containing additional command line options",
                metavar="FILE", type='string', action='store')

        self._add_options(parser)

        real_args = compute_real_args(parser)
        (options, args) = parser.parse_args(real_args)

        if sys.version_info[0] < 3:
            input_encoding = sys.stdin.encoding or 'UTF-8'
            args = [arg.decode(input_encoding) for arg in args]

        if self._needs_device():
            self._device_id = options.device_id
            self._device_type = options.device_type
            self._host = options.host
        else:
            self._device_id = None
            self._device_type = None
            self._host = None
        self._device = None
        self._schedule_on_output = lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data))
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._spawned_pid = None
        self._spawned_argv = None
        self._target_pid = None
        self._session = None
        if self._needs_target():
            self._stdio = options.stdio
            self._aux = options.aux
            self._runtime = options.runtime
            self._enable_debugger = options.enable_debugger
            self._squelch_crash = options.squelch_crash
        else:
            self._stdio = 'inherit'
            self._aux = []
            self._runtime = 'duk'
            self._enable_debugger = False
            self._squelch_crash = False
        self._schedule_on_session_detached = lambda reason, crash: self._reactor.schedule(lambda: self._on_session_detached(reason, crash))
        self._started = False
        self._resumed = False
        self._reactor = Reactor(run_until_return, on_stop)
        self._exit_status = None
        self._console_state = ConsoleState.EMPTY
        self._have_terminal = sys.stdin.isatty() and sys.stdout.isatty() and not os.environ.get("TERM", '') == "dumb"
        self._plain_terminal = plain_terminal
        self._quiet = False
        if sum(map(lambda v: int(v is not None), (self._device_id, self._device_type, self._host))) > 1:
            parser.error("Only one of -D, -U, -R, and -H may be specified")

        if self._needs_target():
            target = getattr(options, 'target', None)
            if target is None:
                if len(args) < 1:
                    parser.error("target file, process name or pid must be specified")
                target = infer_target(args[0])
                args.pop(0)
            target = expand_target(target)
            if target[0] == 'file':
                argv = target[1]
                argv.extend(args)
            args = []
            self._target = target
        else:
            self._target = None

        try:
            self._initialize(parser, options, args)
        except Exception as e:
            parser.error(str(e))

    def run(self):
        mgr = frida.get_device_manager()

        on_devices_changed = lambda: self._reactor.schedule(self._try_start)
        mgr.on('changed', on_devices_changed)

        self._reactor.schedule(self._try_start)
        self._reactor.schedule(self._show_message_if_no_device, delay=1)

        signal.signal(signal.SIGTERM, self._on_sigterm)

        self._reactor.run()

        if self._started:
            try:
                self._perform_on_background_thread(self._stop)
            except frida.OperationCancelledError:
                pass

        if self._session is not None:
            self._session.off('detached', self._schedule_on_session_detached)
            try:
                self._perform_on_background_thread(self._session.detach)
            except frida.OperationCancelledError:
                pass
            self._session = None

        if self._device is not None:
            self._device.off('output', self._schedule_on_output)
            self._device.off('lost', self._schedule_on_device_lost)

        mgr.off('changed', on_devices_changed)

        frida.shutdown()
        sys.exit(self._exit_status)

    def _add_options(self, parser):
        pass

    def _initialize(self, parser, options, args):
        pass

    def _needs_device(self):
        return True

    def _needs_target(self):
        return False

    def _start(self):
        pass

    def _stop(self):
        pass

    def _resume(self):
        if self._resumed:
            return
        if self._spawned_pid is not None:
            self._device.resume(self._spawned_pid)
        self._resumed = True

    def _exit(self, exit_status):
        self._exit_status = exit_status
        self._reactor.stop()

    def _try_start(self):
        if self._device is not None:
            return
        if self._device_id is not None:
            try:
                self._device = frida.get_device(self._device_id)
            except:
                self._update_status("Device '%s' not found" % self._device_id)
                self._exit(1)
                return
        elif self._device_type is not None:
            self._device = find_device(self._device_type)
            if self._device is None:
                return
        elif self._host is not None:
            self._device = frida.get_device_manager().add_remote_device(self._host)
        else:
            self._device = frida.get_local_device()
        self._device.on('output', self._schedule_on_output)
        self._device.on('lost', self._schedule_on_device_lost)
        if self._target is not None:
            spawning = True
            try:
                target_type, target_value = self._target
                if target_type == 'frontmost':
                    try:
                        app = self._device.get_frontmost_application()
                    except Exception as e:
                        self._update_status("Unable to get frontmost application on {}: {}".format(self._device.name, e))
                        self._exit(1)
                        return
                    if app is None:
                        self._update_status("No frontmost application on {}".format(self._device.name))
                        self._exit(1)
                        return
                    self._target = ('name', app.name)
                    attach_target = app.pid
                elif target_type == 'file':
                    argv = target_value
                    if not self._quiet:
                        self._update_status("Spawning `%s`..." % " ".join(argv))

                    aux_kwargs = {}
                    if self._aux is not None:
                        aux_kwargs = dict([parse_aux_option(o) for o in self._aux])

                    self._spawned_pid = self._device.spawn(argv, stdio=self._stdio, **aux_kwargs)
                    self._spawned_argv = argv
                    attach_target = self._spawned_pid
                else:
                    attach_target = target_value
                    if not isinstance(attach_target, numbers.Number):
                        attach_target = self._device.get_process(attach_target).pid
                    if not self._quiet:
                        self._update_status("Attaching...")
                spawning = False
                self._target_pid = attach_target
                self._session = self._device.attach(attach_target)
                if self._enable_debugger:
                    self._session.enable_debugger()
                    self._print("Chrome Inspector server listening on port 9229\n")
                self._session.on('detached', self._schedule_on_session_detached)
            except frida.OperationCancelledError:
                self._exit(0)
                return
            except Exception as e:
                if spawning:
                    self._update_status("Failed to spawn: %s" % e)
                else:
                    self._update_status("Failed to attach: %s" % e)
                self._exit(1)
                return
        self._start()
        self._started = True

    def _show_message_if_no_device(self):
        if self._device is None:
            self._print("Waiting for USB device to appear...")

    def _on_sigterm(self, n, f):
        self._reactor.cancel_io()
        self._exit(0)

    def _on_output(self, pid, fd, data):
        if pid != self._target_pid or data is None:
            return
        if fd == 1:
            prefix = "stdout> "
            stream = sys.stdout
        else:
            prefix = "stderr> "
            stream = sys.stderr
        encoding = stream.encoding or 'UTF-8'
        text = data.decode(encoding, errors='replace')
        if text.endswith("\n"):
            text = text[:-1]
        lines = text.split("\n")
        self._print(prefix + ("\n" + prefix).join(lines))

    def _on_device_lost(self):
        if self._exit_status is not None:
            return
        self._print("Device disconnected.")
        self._exit(1)

    def _on_session_detached(self, reason, crash):
        if crash is None:
            message = reason[0].upper() + reason[1:].replace("-", " ")
        else:
            message = "Process crashed: " + crash.summary
        self._print(Fore.RED + Style.BRIGHT + message + Style.RESET_ALL)
        if crash is not None:
            if self._squelch_crash is True:
                self._print("\n*** Crash report was squelched due to user setting. ***")
            else:
                self._print("\n***\n{}\n***".format(crash.report.rstrip("\n")))
        self._exit(1)

    def _clear_status(self):
        if self._console_state == ConsoleState.STATUS:
            print(Cursor.UP() + (80 * " "))

    def _update_status(self, message):
        if self._have_terminal:
            if self._console_state == ConsoleState.STATUS:
                cursor_position = Cursor.UP()
            else:
                cursor_position = ""
            print("%-80s" % (cursor_position + Style.BRIGHT + message + Style.RESET_ALL,))
            self._console_state = ConsoleState.STATUS
        else:
            print(Style.BRIGHT + message + Style.RESET_ALL)

    def _print(self, *args, **kwargs):
        encoded_args = []
        encoding = sys.stdout.encoding or 'UTF-8'
        if encoding == 'UTF-8':
            encoded_args = args
        else:
            if sys.version_info[0] >= 3:
                string_type = str
            else:
                string_type = unicode
            for arg in args:
                if isinstance(arg, string_type):
                    encoded_args.append(arg.encode(encoding, errors='backslashreplace').decode(encoding))
                else:
                    encoded_args.append(arg)
        print(*encoded_args, **kwargs)
        self._console_state = ConsoleState.TEXT

    def _log(self, level, text):
        if level == 'info':
            self._print(text)
        else:
            color = Fore.RED if level == 'error' else Fore.YELLOW
            text = color + Style.BRIGHT + text + Style.RESET_ALL
            if level == 'error':
                self._print(text, file=sys.stderr)
            else:
                self._print(text)

    def _perform_on_reactor_thread(self, f):
        completed = threading.Event()
        result = [None, None]

        def work():
            try:
                result[0] = f()
            except Exception as e:
                result[1] = e
            completed.set()

        self._reactor.schedule(work)

        while not completed.is_set():
            try:
                completed.wait()
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                continue

        error = result[1]
        if error is not None:
            raise error

        return result[0]

    def _perform_on_background_thread(self, f, timeout=None):
        result = [None, None]

        def work():
            with self._reactor.io_cancellable:
                try:
                    result[0] = f()
                except Exception as e:
                    result[1] = e

        worker = threading.Thread(target=work)
        worker.start()

        try:
            worker.join(timeout)
        except KeyboardInterrupt:
            self._reactor.cancel_io()

        if timeout is not None and worker.is_alive():
            self._reactor.cancel_io()
            while worker.is_alive():
                try:
                    worker.join()
                except KeyboardInterrupt:
                    pass

        error = result[1]
        if error is not None:
            raise error

        return result[0]


def compute_real_args(parser):
    real_args = normalize_options_file_args(sys.argv[1:])

    files_processed = set()
    while True:
        offset = find_options_file_offset(real_args, parser)
        if offset == -1:
            break

        file_path = os.path.abspath(real_args[offset + 1])
        if file_path in files_processed:
            parser.error("File '{}' given twice as -O argument".format(file_path))

        if os.path.isfile(file_path):
            with codecs.open(file_path, 'r', 'utf-8') as f:
                new_arg_text = f.read()
        else:
            parser.error("File '{}' following -O option is not a valid file".format(file_path))

        real_args = insert_options_file_args_in_list(real_args, offset, new_arg_text)
        files_processed.add(file_path)

    return real_args


def normalize_options_file_args(raw_args):
    result = []
    for arg in raw_args:
        if arg.startswith("--options-file="):
            result.append(arg[0:14])
            result.append(arg[15:])
        else:
            result.append(arg)
    return result


def find_options_file_offset(arglist, parser):
    for i, arg in enumerate(arglist):
        if arg in ("-O", "--options-file"):
            if i < len(arglist) - 1:
                return i
            else:
                parser.error("No argument given for -O option")
    return -1


def insert_options_file_args_in_list(args, offset, new_arg_text):
    new_args = shlex.split(new_arg_text)
    new_args = normalize_options_file_args(new_args)
    new_args_list = args[:offset] + new_args + args[offset + 2:]
    return new_args_list


def find_device(type):
    for device in frida.enumerate_devices():
        if device.type == type:
            return device
    return None


def infer_target(target_value):
    if target_value.startswith('.') or target_value.startswith(os.path.sep) \
            or (platform.system() == 'Windows' \
                and target_value[0].isalpha() \
                and target_value[1] == ":" \
                and target_value[2] == "\\"):
        target_type = 'file'
        target_value = [target_value]
    else:
        try:
            target_value = int(target_value)
            target_type = 'pid'
        except:
            target_type = 'name'
    return (target_type, target_value)


def expand_target(target):
    target_type, target_value = target
    if target_type == 'file':
        target_value = [target_value[0]]
    return (target_type, target_value)


def parse_aux_option(option):
    m = AUX_OPTION_PATTERN.match(option)
    if m is None:
        raise ValueError("expected name=(type)value, e.g. “uid=(int)42”; supported types are: string, bool, int")

    name = m.group(1)
    type_decl = m.group(2)
    raw_value = m.group(3)
    if type_decl == 'string':
        value = raw_value
    elif type_decl == 'bool':
        value = bool(raw_value)
    else:
        value = int(raw_value)

    return (name, value)


class Reactor(object):
    def __init__(self, run_until_return, on_stop=None):
        self._running = False
        self._run_until_return = run_until_return
        self._on_stop = on_stop
        self._pending = collections.deque([])
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

        self.io_cancellable = frida.Cancellable()

        self.ui_cancellable = frida.Cancellable()
        self._ui_cancellable_fd = self.ui_cancellable.get_pollfd()

    def __del__(self):
        self._ui_cancellable_fd.release()

    def is_running(self):
        with self._lock:
            return self._running

    def run(self):
        with self._lock:
            self._running = True

        worker = threading.Thread(target=self._run)
        worker.start()

        self._run_until_return(self)

        self.stop()
        worker.join()

    def _run(self):
        running = True
        while running:
            now = time.time()
            work = None
            timeout = None
            previous_pending_length = -1
            with self._lock:
                for item in self._pending:
                    (f, when) = item
                    if now >= when:
                        work = f
                        self._pending.remove(item)
                        break
                if len(self._pending) > 0:
                    timeout = max([min(map(lambda item: item[1], self._pending)) - now, 0])
                previous_pending_length = len(self._pending)

            if work is not None:
                with self.io_cancellable:
                    try:
                        work()
                    except frida.OperationCancelledError:
                        pass

            with self._lock:
                if self._running and len(self._pending) == previous_pending_length:
                    self._cond.wait(timeout)
                running = self._running

        if self._on_stop is not None:
            self._on_stop()

        self.ui_cancellable.cancel()

    def stop(self):
        self.schedule(self._stop)

    def _stop(self):
        with self._lock:
            self._running = False

    def schedule(self, f, delay=None):
        now = time.time()
        if delay is not None:
            when = now + delay
        else:
            when = now
        with self._lock:
            self._pending.append((f, when))
            self._cond.notify()

    def cancel_io(self):
        self.io_cancellable.cancel()
