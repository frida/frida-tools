# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import argparse
import codecs
import collections
import errno
import numbers
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


def await_ctrl_c(reactor):
    while True:
        try:
            input_with_cancellable(reactor.ui_cancellable)
        except frida.OperationCancelledError:
            break
        except KeyboardInterrupt:
            break


def deserialize_relay(value):
    address, username, password, kind = value.split(",")
    return frida.Relay(address, username, password, kind)


def create_target_parser(type):
    def parse_target(value):
        if type == 'file':
            value = [value]
        elif type == 'gated':
            value = re.compile(value)
        elif type == 'pid':
            value = int(value)
        return (type, value)
    return parse_target


class ConsoleState:
    EMPTY = 1
    STATUS = 2
    TEXT = 3


class ConsoleApplication(object):
    def __init__(self, run_until_return=await_enter, on_stop=None, args=None):
        plain_terminal = os.environ.get("TERM", "").lower() == "none"

        # Windows doesn't have SIGPIPE
        if hasattr(signal, 'SIGPIPE'):
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)

        colorama.init(strip=True if plain_terminal else None)

        parser = self._initialize_arguments_parser()
        real_args = compute_real_args(parser, args=args)
        options = parser.parse_args(real_args)

        # handle scripts that don't need a target
        if not hasattr(options, 'args'):
            options.args = []

        if sys.version_info[0] < 3:
            input_encoding = sys.stdin.encoding or 'UTF-8'
            options.args = [arg.decode(input_encoding) for arg in options.args]

        if self._needs_device():
            self._device_id = options.device_id
            self._device_type = options.device_type
            self._host = options.host
            if all([x is None for x in [self._device_id, self._device_type, self._host]]):
                self._device_id = os.environ.get("FRIDA_DEVICE")
                if self._device_id is None:
                    self._host = os.environ.get("FRIDA_HOST")
            self._certificate = options.certificate or os.environ.get("FRIDA_CERTIFICATE")
            self._origin = options.origin or os.environ.get("FRIDA_ORIGIN")
            self._token = options.token or os.environ.get("FRIDA_TOKEN")
            self._keepalive_interval = options.keepalive_interval
            self._session_transport = options.session_transport
            self._stun_server = options.stun_server
            self._relays = options.relays
        else:
            self._device_id = None
            self._device_type = None
            self._host = None
            self._certificate = None
            self._origin = None
            self._token = None
            self._keepalive_interval = None
            self._session_transport = 'multiplexed'
            self._stun_server = None
            self._relays = None
        self._device = None
        self._schedule_on_output = lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data))
        self._schedule_on_device_lost = lambda: self._reactor.schedule(self._on_device_lost)
        self._spawned_pid = None
        self._spawned_argv = None
        self._selected_spawn = None
        self._target_pid = None
        self._session = None
        if self._needs_target():
            self._stdio = options.stdio
            self._aux = options.aux
            self._realm = options.realm
            self._runtime = options.runtime
            self._enable_debugger = options.enable_debugger
            self._squelch_crash = options.squelch_crash
        else:
            self._stdio = 'inherit'
            self._aux = []
            self._realm = 'native'
            self._runtime = 'qjs'
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
                if len(options.args) < 1:
                    parser.error("target must be specified")
                target = infer_target(options.args[0])
                options.args.pop(0)
            target = expand_target(target)
            if target[0] == 'file':
                argv = target[1]
                argv.extend(options.args)
                options.args = []
            self._target = target
        else:
            self._target = None

        try:
            self._initialize(parser, options, options.args)
        except Exception as e:
            parser.error(str(e))

    def _initialize_arguments_parser(self):
        parser = self._initialize_base_arguments_parser()
        self._add_options(parser)
        return parser

    def _initialize_base_arguments_parser(self):
        parser = argparse.ArgumentParser(usage=self._usage())

        if self._needs_device():
            self._add_device_arguments(parser)

        if self._needs_target():
            self._add_target_arguments(parser)

        parser.add_argument("-O", "--options-file", help="text file containing additional command line options", metavar="FILE")
        parser.add_argument('--version', action='version', version=frida.__version__)

        return parser

    def _add_device_arguments(self, parser):
        parser.add_argument("-D", "--device", help="connect to device with the given ID", metavar="ID", dest="device_id")
        parser.add_argument("-U", "--usb", help="connect to USB device", action='store_const', const='usb', dest="device_type")
        parser.add_argument("-R", "--remote", help="connect to remote frida-server", action='store_const', const='remote', dest="device_type")
        parser.add_argument("-H", "--host", help="connect to remote frida-server on HOST")
        parser.add_argument("--certificate", help="speak TLS with HOST, expecting CERTIFICATE")
        parser.add_argument("--origin", help="connect to remote server with “Origin” header set to ORIGIN")
        parser.add_argument("--token", help="authenticate with HOST using TOKEN")
        parser.add_argument("--keepalive-interval", help="set keepalive interval in seconds, or 0 to disable (defaults to -1 to auto-select based on transport)", metavar="INTERVAL", type=int)
        parser.add_argument("--p2p", help="establish a peer-to-peer connection with target", action='store_const', const='p2p', dest="session_transport", default="multiplexed")
        parser.add_argument("--stun-server", help="set STUN server ADDRESS to use with --p2p", metavar="ADDRESS")
        parser.add_argument("--relay", help="add relay to use with --p2p", metavar="address,username,password,turn-{udp,tcp,tls}", dest="relays", action='append', type=deserialize_relay)

    def _add_target_arguments(self, parser):
        parser.add_argument("-f", "--file", help="spawn FILE", dest="target", type=create_target_parser("file"))
        parser.add_argument("-F", "--attach-frontmost", help="attach to frontmost application", dest="target", action="store_const", const=('frontmost', None))
        parser.add_argument("-n", "--attach-name", help="attach to NAME", metavar="NAME", dest="target", type=create_target_parser("name"))
        parser.add_argument("-N", "--attach-identifier", help="attach to IDENTIFIER", metavar="IDENTIFIER", dest="target", type=create_target_parser("identifier"))
        parser.add_argument("-p", "--attach-pid", help="attach to PID", metavar="PID", dest="target", type=create_target_parser("pid"))
        parser.add_argument("-W", "--await", help="await spawn matching PATTERN", metavar="PATTERN", dest="target", type=create_target_parser("gated"))
        parser.add_argument("--stdio", help="stdio behavior when spawning (defaults to “inherit”)", choices=["inherit", "pipe"], default="inherit")
        parser.add_argument("--aux", help="set aux option when spawning, such as “uid=(int)42” (supported types are: string, bool, int)", metavar="option", action="append", dest="aux", default=[])
        parser.add_argument("--realm", help="realm to attach in", choices=["native", "emulated"], default="native")
        parser.add_argument("--runtime", help="script runtime to use", choices=["qjs", "v8"])
        parser.add_argument("--debug", help="enable the Node.js compatible script debugger", action="store_true", dest="enable_debugger", default=False)
        parser.add_argument("--squelch-crash", help="if enabled, will not dump crash report to console", action="store_true", default=False)
        parser.add_argument("args", help="extra arguments and/or target", nargs="*")

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
            if self._target[0] == 'gated':
                self._device.disable_spawn_gating()
                self._device.off('spawn-added', self._on_spawn_added)
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
        elif (self._host is not None) or (self._device_type == 'remote'):
            host = self._host

            options = {}
            if self._certificate is not None:
                options['certificate'] = self._certificate
            if self._origin is not None:
                options['origin'] = self._origin
            if self._token is not None:
                options['token'] = self._token
            if self._keepalive_interval is not None:
                options['keepalive_interval'] = self._keepalive_interval

            if host is None and len(options) == 0:
                self._device = frida.get_remote_device()
            else:
                self._device = frida.get_device_manager().add_remote_device(host if host is not None else "127.0.0.1",
                                                                            **options)
        elif self._device_type is not None:
            self._device = find_device(self._device_type)
            if self._device is None:
                return
        else:
            self._device = frida.get_local_device()
        self._on_device_found()
        self._device.on('output', self._schedule_on_output)
        self._device.on('lost', self._schedule_on_device_lost)
        if self._target is not None:
            target_type, target_value = self._target

            if target_type == 'gated':
                self._device.on('spawn-added', self._on_spawn_added)
                try:
                    self._device.enable_spawn_gating()
                except Exception as e:
                    self._update_status("Failed to enable spawn gating: %s" % e)
                    self._exit(1)
                    return
                self._update_status("Waiting for spawn to appear...")
                return

            spawning = True
            try:
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
                elif target_type == 'identifier':
                    spawning = False
                    app_list = self._device.enumerate_applications()
                    app_identifier_lc = target_value.lower()
                    matching = [app for app in app_list if app.identifier.lower() == app_identifier_lc]
                    if len(matching) == 1 and matching[0].pid != 0:
                        attach_target = matching[0].pid
                    elif len(matching) > 1:
                        raise frida.ProcessNotFoundError("ambiguous identifier; it matches: %s" % ", ".join(
                            ["%s (pid: %d)" % (process.identifier, process.pid) for process in matching]))
                    else:
                        raise frida.ProcessNotFoundError("unable to find process with identifier '%s'" % target_value)
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
                self._attach(attach_target)
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

    def _attach(self, pid):
        self._target_pid = pid

        self._session = self._device.attach(pid, realm=self._realm)
        self._session.on('detached', self._schedule_on_session_detached)

        if self._session_transport == 'p2p':
            peer_options = {}
            if self._stun_server is not None:
                peer_options['stun_server'] = self._stun_server
            if self._relays is not None:
                peer_options['relays'] = self._relays
            self._session.setup_peer_connection(**peer_options)

        if self._enable_debugger:
            self._session.enable_debugger()
            self._print("Chrome Inspector server listening on port 9229\n")

    def _show_message_if_no_device(self):
        if self._device is None:
            self._print("Waiting for USB device to appear...")

    def _on_sigterm(self, n, f):
        self._reactor.cancel_io()
        self._exit(0)

    def _on_spawn_added(self, spawn):
        thread = threading.Thread(target=self._handle_spawn, args=(spawn,))
        thread.start()

    def _handle_spawn(self, spawn):
        pid = spawn.pid

        pattern = self._target[1]
        if pattern.match(spawn.identifier) is None or self._selected_spawn is not None:
            self._print(Fore.YELLOW + Style.BRIGHT + "Ignoring: " + str(spawn) + Style.RESET_ALL)
            try:
                self._device.resume(pid)
            except:
                pass
            return

        self._selected_spawn = spawn

        self._print(Fore.GREEN + Style.BRIGHT + "Handling: " + str(spawn) + Style.RESET_ALL)
        try:
            self._attach(pid)
            self._reactor.schedule(lambda: self._on_spawn_handled(spawn))
        except Exception as e:
            error = e
            self._reactor.schedule(lambda: self._on_spawn_unhandled(spawn, error))

    def _on_spawn_handled(self, spawn):
        self._spawned_pid = spawn.pid
        self._start()
        self._started = True

    def _on_spawn_unhandled(self, spawn, error):
        self._update_status("Failed to handle spawn: %s" % error)
        self._exit(1)

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

    def _on_device_found(self):
        pass

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

    def _get_default_frida_dir(self):
        return os.path.join(os.path.expanduser('~'), '.frida')

    def _get_windows_frida_dir(self):
        appdata = os.getenv('LOCALAPPDATA')
        return os.path.join(appdata, 'frida')

    def _get_or_create_config_dir(self):
        config_dir = os.path.join(self._get_default_frida_dir(), 'config')
        if platform.system() == 'Linux':
            xdg_config_home = os.getenv('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
            config_dir = os.path.join(xdg_config_home, 'frida')
        elif platform.system() == 'Windows':
            config_dir = os.path.join(self._get_windows_frida_dir(), 'Config')
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        return config_dir

    def _get_or_create_data_dir(self):
        data_dir = os.path.join(self._get_default_frida_dir(), 'data')
        if platform.system() == 'Linux':
            xdg_data_home = os.getenv('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))
            data_dir = os.path.join(xdg_data_home, 'frida')
        elif platform.system() == 'Windows':
            data_dir = os.path.join(self._get_windows_frida_dir(), 'Data')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        return data_dir

    def _get_or_create_state_dir(self):
        state_dir = os.path.join(self._get_default_frida_dir(), 'state')
        if platform.system() == 'Linux':
            xdg_state_home = os.getenv('XDG_STATE_HOME', os.path.expanduser('~/.local/state'))
            state_dir = os.path.join(xdg_state_home, 'frida')
        elif platform.system() == 'Windows':
            appdata = os.getenv('LOCALAPPDATA')
            state_dir = os.path.join(appdata, 'frida', 'State')
        if not os.path.exists(state_dir):
            os.makedirs(state_dir)
        return state_dir


def compute_real_args(parser, args=None):
    if args is None:
        args = sys.argv[1:]
    real_args = normalize_options_file_args(args)

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
