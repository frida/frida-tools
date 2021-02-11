# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import os
import signal
import string
import threading


def main():
    import codecs
    import hashlib
    import json
    import os
    import platform
    import re
    import sys
    try:
        from urllib.request import build_opener
    except:
        from urllib2 import build_opener

    from colorama import Fore, Style
    import frida
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.completion import Completion, Completer
    from prompt_toolkit.lexers import PygmentsLexer
    from prompt_toolkit.styles import Style as PromptToolkitStyle
    from pygments.lexers.javascript import JavascriptLexer
    from pygments.token import Token

    from frida_tools.application import ConsoleApplication

    class REPLApplication(ConsoleApplication):
        def __init__(self):
            self._script = None
            self._ready = threading.Event()
            self._stopping = threading.Event()
            self._errors = 0
            config_dir = self._get_or_create_config_dir()
            self._completer = FridaCompleter(self)
            self._cli = None
            self._last_change_id = 0
            self._monitored_files = {}

            super(REPLApplication, self).__init__(self._process_input, self._on_stop)

            if self._have_terminal and not self._plain_terminal:
                style = PromptToolkitStyle([
                    ("completion-menu", "bg:#3d3d3d #ef6456"),
                    ("completion-menu.completion.current", "bg:#ef6456 #3d3d3d"),
                ])
                history = FileHistory(os.path.join(config_dir, 'history'))
                self._cli = PromptSession(lexer=PygmentsLexer(JavascriptLexer),
                                          style=style,
                                          history=history,
                                          completer=self._completer,
                                          complete_in_thread=True)
                self._dumb_stdin_reader = None
            else:
                self._cli = None
                self._dumb_stdin_reader = DumbStdinReader(valid_until=self._stopping.is_set)

            if not self._have_terminal:
                self._rpc_complete_server = start_completion_thread(self)

        def _add_options(self, parser):
            parser.add_option("-l", "--load", help="load SCRIPT", metavar="SCRIPT",
                              type='string', action='store', dest="user_script", default=None)
            parser.add_option("-P", "--parameters", help="parameters as JSON, same as Gadget", metavar="PARAMETERS_JSON",
                              type='string', action='store', dest="user_parameters", default=None)
            parser.add_option("-C", "--cmodule", help="load CMODULE", metavar="CMODULE",
                              type='string', action='store', dest="user_cmodule", default=None)
            parser.add_option("--toolchain", help="CModule toolchain to use when compiling from source code",
                              metavar="any|internal|external", type='choice', choices=['any', 'internal', 'external'], default='any')
            parser.add_option("-c", "--codeshare", help="load CODESHARE_URI", metavar="CODESHARE_URI",
                              type='string', action='store', dest="codeshare_uri", default=None)
            parser.add_option("-e", "--eval", help="evaluate CODE", metavar="CODE",
                              type='string', action='append', dest="eval_items", default=None)
            parser.add_option("-q", help="quiet mode (no prompt) and quit after -l and -e",
                              action='store_true', dest="quiet", default=False)
            parser.add_option("--no-pause", help="automatically start main thread after startup",
                              action='store_true', dest="no_pause", default=False)
            parser.add_option("-o", "--output", help="output to log file", dest="logfile", default=None)
            parser.add_option("--eternalize", help="eternalize the script before exit",
                              action='store_true', dest="eternalize", default=False)
            parser.add_option("--exit-on-error", help="exit with code 1 after encountering any exception in the SCRIPT",
                              action='store_true', dest="exit_on_error", default=False)

        def _initialize(self, parser, options, args):
            if options.user_script is not None:
                self._user_script = os.path.abspath(options.user_script)
                with codecs.open(self._user_script, 'rb', 'utf-8') as f:
                    pass
            else:
                self._user_script = None

            if options.user_parameters is not None:
                try:
                    params = json.loads(options.user_parameters)
                except Exception as e:
                    raise ValueError("failed to parse parameters argument as JSON: {}".format(e))
                if not isinstance(params, dict):
                    raise ValueError("failed to parse parameters argument as JSON: not an object")
                self._user_parameters = params
            else:
                self._user_parameters = {}

            if options.user_cmodule is not None:
                self._user_cmodule = os.path.abspath(options.user_cmodule)
                with open(self._user_cmodule, 'rb') as f:
                    pass
            else:
                self._user_cmodule = None
            self._toolchain = options.toolchain

            self._codeshare_uri = options.codeshare_uri
            self._codeshare_script = None

            self._pending_eval = options.eval_items

            self._quiet = options.quiet
            self._no_pause = options.no_pause
            self._eternalize = options.eternalize
            self._exit_on_error = options.exit_on_error

            if options.logfile is not None:
                self._logfile = codecs.open(options.logfile, 'w', 'utf-8')
            else:
                self._logfile = None

        def _log(self, level, text):
            ConsoleApplication._log(self, level, text)
            if self._logfile is not None:
                self._logfile.write(text + "\n")

        def _usage(self):
            return "usage: %prog [options] target"

        def _needs_target(self):
            return True

        def _start(self):
            self._prompt_string = self._create_prompt()

            if self._codeshare_uri is not None:
                self._codeshare_script = self._load_codeshare_script(self._codeshare_uri)
                if self._codeshare_script is None:
                    self._print("Exiting!")
                    self._exit(1)
                    return

            try:
                self._load_script()
            except Exception as e:
                self._update_status("Failed to load script: {error}".format(error=e))
                self._exit(1)
                return

            if self._spawned_argv is not None:
                if self._no_pause:
                    self._update_status(
                        "Spawned `{command}`. Resuming main thread!".format(command=" ".join(self._spawned_argv)))
                    self._do_magic("resume")
                else:
                    self._update_status(
                        "Spawned `{command}`. Use %resume to let the main thread start executing!".format(
                            command=" ".join(self._spawned_argv)))
            else:
                self._clear_status()
            self._ready.set()

        def _on_stop(self):
            self._stopping.set()

            if self._cli is not None:
                try:
                    self._cli.app.exit()
                except:
                    pass

        def _stop(self):
            if self._eternalize:
                self._eternalize_script()
            else:
                self._unload_script()

            with frida.Cancellable() as c:
                self._demonitor_all()

            if self._logfile is not None:
                self._logfile.close()

            if not self._quiet:
                self._print("\nThank you for using Frida!")

        def _load_script(self):
            self._monitor_all()

            if self._user_script is not None:
                name, ext = os.path.splitext(os.path.basename(self._user_script))
            else:
                name = "repl"

            is_first_load = self._script is None

            script = self._session.create_script(name=name,
                                                 source=self._create_repl_script(),
                                                 runtime=self._runtime)
            script.set_log_handler(self._log)
            self._unload_script()
            self._script = script

            def on_message(message, data):
                self._reactor.schedule(lambda: self._process_message(message, data))

            script.on('message', on_message)
            script.load()

            cmodule_code = self._load_cmodule_code()
            if cmodule_code is not None:
                # TODO: Remove this hack once RPC implementation supports passing binary data in both directions.
                if is_byte_array(cmodule_code):
                    script.post({'type': 'frida:cmodule-payload'}, data=cmodule_code)
                    cmodule_code = None
                script.exports.frida_load_cmodule(cmodule_code, self._toolchain)

            stage = 'early' if self._target[0] == 'file' and is_first_load else 'late'
            try:
                script.exports.init(stage, self._user_parameters)
            except:
                pass

        def _eternalize_script(self):
            if self._script is None:
                return

            try:
                self._script.eternalize()
            except:
                pass
            self._script = None

        def _unload_script(self):
            if self._script is None:
                return

            try:
                self._script.unload()
            except:
                pass
            self._script = None

        def _monitor_all(self):
            for path in [self._user_script, self._user_cmodule]:
                self._monitor(path)

        def _demonitor_all(self):
            for monitor in self._monitored_files.values():
                monitor.disable()
            self._monitored_files = {}

        def _monitor(self, path):
            if path is None or path in self._monitored_files:
                return

            monitor = frida.FileMonitor(path)
            monitor.on('change', self._on_change)
            monitor.enable()
            self._monitored_files[path] = monitor

        def _process_input(self, reactor):
            if not self._quiet:
                self._print_startup_message()

            try:
                while self._ready.wait(0.5) != True:
                    if not reactor.is_running():
                        return
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                return

            while True:
                expression = ""
                line = ""
                while len(expression) == 0 or line.endswith("\\"):
                    if not reactor.is_running():
                        return

                    prompt = "[%s]" % self._prompt_string + "-> " if len(expression) == 0 else "... "

                    pending_eval = self._pending_eval
                    if pending_eval is not None:
                        if len(pending_eval) > 0:
                            expression = pending_eval.pop(0)
                            if not self._quiet:
                                self._print(prompt + expression)
                        else:
                            self._pending_eval = None
                    else:
                        if self._quiet:
                            self._exit_status = 0 if self._errors == 0 else 1
                            return

                        try:
                            if self._cli is not None:
                                line = self._cli.prompt(prompt)
                                if line is None:
                                    return
                            else:
                                line = self._dumb_stdin_reader.read_line(prompt)
                                self._print(line)
                        except EOFError:
                            if not self._have_terminal and os.environ.get("TERM", '') != "dumb":
                                while not self._stopping.wait(1):
                                    pass
                            return
                        except KeyboardInterrupt:
                            line = ""
                            if not self._have_terminal:
                                sys.stdout.write("\n" + prompt)
                            continue
                        if len(line.strip()) > 0:
                            if len(expression) > 0:
                                expression += "\n"
                            expression += line.rstrip("\\")

                if expression.endswith("?"):
                    try:
                        self._print_help(expression)
                    except JavaScriptError as e:
                        error = e.error
                        self._print(Style.BRIGHT + error['name'] + Style.RESET_ALL + ": " + error['message'])
                    except frida.InvalidOperationError:
                        return
                elif expression == "help":
                    self._print("Help: #TODO :)")
                elif expression in ("exit", "quit", "q"):
                    return
                else:
                    try:
                        if expression.startswith("%"):
                            self._do_magic(expression[1:].rstrip())
                        else:
                            if not self._eval_and_print(expression):
                                self._errors += 1
                    except frida.OperationCancelledError:
                        return

        def _eval_and_print(self, expression):
            success = False
            try:
                (t, value) = self._perform_on_reactor_thread(lambda: self._evaluate(expression))
                if t in ('function', 'undefined', 'null'):
                    output = t
                elif t == 'binary':
                    output = hexdump(value).rstrip("\n")
                else:
                    output = json.dumps(value, sort_keys=True, indent=4, separators=(",", ": "))
                success = True
            except JavaScriptError as e:
                error = e.error

                output = Fore.RED + Style.BRIGHT + error['name'] + Style.RESET_ALL + ": " + error['message']

                stack = error.get('stack', None)
                if stack is not None:
                    trim_amount = 5 if self._runtime == 'v8' else 6
                    trimmed_stack = stack.split("\n")[1:-trim_amount]
                    if len(trimmed_stack) > 0:
                        output += "\n" + "\n".join(trimmed_stack)
            except frida.InvalidOperationError:
                return success
            if output != "undefined":
                self._print(output)
            return success

        def _print_startup_message(self):
            self._print("""\
     ____
    / _  |   Frida {version} - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/""".format(version=frida.__version__))

        def _print_help(self, expression):
            # TODO: Figure out docstrings and implement here. This is real jankaty right now.
            help_text = ""
            if expression.endswith(".?"):
                expression = expression[:-2] + "?"

            obj_to_identify = [x for x in expression.split(' ') if x.endswith("?")][0][:-1]
            (obj_type, obj_value) = self._evaluate(obj_to_identify)

            if obj_type == "function":
                signature = self._evaluate("%s.toString()" % obj_to_identify)[1]
                clean_signature = signature.split("{")[0][:-1].split('function ')[-1]

                if "[native code]" in signature:
                    help_text += "Type:      Function (native)\n"
                else:
                    help_text += "Type:      Function\n"

                help_text += "Signature: %s\n" % clean_signature
                help_text += "Docstring: #TODO :)"

            elif obj_type == "object":
                help_text += "Type:      Object\n"
                help_text += "Docstring: #TODO :)"

            elif obj_type == "boolean":
                help_text += "Type:      Boolean\n"
                help_text += "Docstring: #TODO :)"

            elif obj_type == "string":
                help_text += "Type:      Boolean\n"
                help_text += "Text:      %s\n" % self._evaluate("%s.toString()" % obj_to_identify)[1]
                help_text += "Docstring: #TODO :)"

            self._print(help_text)

        # Negative means at least abs(val) - 1
        _magic_command_args = {
            'resume': 0,
            'load': 1,
            'reload': 0,
            'unload': 0,
            'time': -2  # At least 1 arg
        }

        def _do_magic(self, statement):
            tokens = statement.split(" ")
            command = tokens[0]
            args = tokens[1:]

            required_args = self._magic_command_args.get(command)

            if required_args == None:
                self._print("Unknown command: {}".format(command))
                self._print("Valid commands: {}".format(", ".join(self._magic_command_args.keys())))
                return

            atleast_args = False
            if required_args < 0:
                atleast_args = True
                required_args = abs(required_args) - 1

            if (not atleast_args and len(args) != required_args) or \
                    (atleast_args and len(args) < required_args):
                self._print("{cmd} command expects {atleast}{n} argument{s}".format(
                    cmd=command, atleast='atleast ' if atleast_args else '', n=required_args,
                    s='' if required_args == 1 else ' '))
                return

            if command == 'resume':
                self._reactor.schedule(lambda: self._resume())
            elif command == 'reload':
                self._reload()
            elif command == 'time':
                self._eval_and_print('''
                    (() => {{
                        const _startTime = Date.now();
                        const _result = eval({expression});
                        const _endTime = Date.now();
                        console.log('Time: ' + (_endTime - _startTime) + ' ms.');
                        return _result;
                    }})();'''.format(expression=json.dumps(" ".join(args))))

        def _reload(self):
            try:
                self._perform_on_reactor_thread(lambda: self._load_script())
                return True
            except Exception as e:
                self._print("Failed to load script: {}".format(e))
                return False

        def _create_prompt(self):
            device_type = self._device.type
            type_name = self._target[0]
            if type_name == 'pid':
                if self._target[1] == 0:
                    target = 'SystemSession'
                else:
                    target = 'PID::%u' % self._target[1]
            elif type_name == 'file':
                target = os.path.basename(self._target[1][0])
            else:
                target = self._target[1]

            if device_type in ('local', 'remote'):
                prompt_string = "%s::%s" % (device_type.title(), target)
            else:
                prompt_string = "%s::%s" % (self._device.name, target)

            return prompt_string

        def _evaluate(self, text):
            result = self._script.exports.frida_evaluate(text)
            if is_byte_array(result):
                return ('binary', result)
            elif isinstance(result, dict):
                return ('binary', bytes())
            elif result[0] == 'error':
                raise JavaScriptError(result[1])
            else:
                return result

        def _process_message(self, message, data):
            message_type = message['type']
            if message_type == 'error':
                text = message.get('stack', message['description'])
                self._log('error', text)
                self._errors += 1
                if self._exit_on_error:
                    self._exit(1)
            else:
                self._print("message:", message, "data:", data)

        def _on_change(self, changed_file, other_file, event_type):
            if event_type == 'changes-done-hint':
                return
            self._last_change_id += 1
            change_id = self._last_change_id
            self._reactor.schedule(lambda: self._process_change(change_id), delay=0.05)

        def _process_change(self, change_id):
            if change_id != self._last_change_id:
                return
            try:
                self._load_script()
            except Exception as e:
                self._print("Failed to load script: {error}".format(error=e))

        def _create_repl_script(self):
            user_script = ""

            if self._codeshare_script is not None:
                user_script = self._codeshare_script

            if self._user_script is not None:
                with codecs.open(self._user_script, 'rb', 'utf-8') as f:
                    user_script += f.read().rstrip("\r\n") + "\n\n// Frida REPL script:\n"

            return "_init();" + user_script + """\

function _init() {
    global.cm = null;
    global.cs = {};

    const rpcExports = {
        fridaEvaluate(expression) {
            try {
                const result = (1, eval)(expression);
                if (result instanceof ArrayBuffer) {
                    return result;
                } else {
                    const type = (result === null) ? 'null' : typeof result;
                    return [type, result];
                }
            } catch (e) {
                return ['error', {
                    name: e.name,
                    message: e.message,
                    stack: e.stack
                }];
            }
        },
        fridaLoadCmodule(code, toolchain) {
            const cs = global.cs;

            if (cs._frida_log === undefined)
                cs._frida_log = new NativeCallback(onLog, 'void', ['pointer']);

            if (code === null) {
                recv('frida:cmodule-payload', (message, data) => {
                    code = data;
                });
            }

            global.cm = new CModule(code, cs, { toolchain });
        },
    };

    Object.defineProperty(rpc, 'exports', {
        get() {
            return rpcExports;
        },
        set(value) {
            for (const [k, v] of Object.entries(value)) {
                rpcExports[k] = v;
            }
        }
    });

    function onLog(messagePtr) {
        const message = messagePtr.readUtf8String();
        console.log(message);
    }
}
"""

        def _load_cmodule_code(self):
            if self._user_cmodule is None:
                return None

            with open(self._user_cmodule, 'rb') as f:
                code = f.read()
            if code_is_native(code):
                return code
            source = code.decode('utf-8')

            name = os.path.basename(self._user_cmodule)

            return """static void frida_log (const char * format, ...);\n#line 1 "{name}"\n""".format(name=name) + source + """\
#line 1 "frida-repl-builtins.c"
#include <glib.h>

extern void _frida_log (const gchar * message);

static void
frida_log (const char * format,
           ...)
{
  gchar * message;
  va_list args;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);

  _frida_log (message);

  g_free (message);
}
"""

        def _load_codeshare_script(self, uri):
            trust_store = self._get_or_create_truststore()

            project_url = "https://codeshare.frida.re/api/project/{}/".format(uri)
            response_json = None
            try:
                request = build_opener()
                request.addheaders = [('User-Agent', 'Frida v{} | {}'.format(frida.__version__, platform.platform()))]
                response = request.open(project_url)
                response_content = response.read().decode('utf-8')
                response_json = json.loads(response_content)
            except Exception as e:
                self._print("Got an unhandled exception while trying to retrieve {} - {}".format(uri, e))
                return None

            trusted_signature = trust_store.get(uri, "")
            fingerprint = hashlib.sha256(response_json['source'].encode('utf-8')).hexdigest()
            if fingerprint == trusted_signature:
                return response_json['source']

            self._print("""Hello! This is the first time you're running this particular snippet, or the snippet's source code has changed.

Project Name: {project_name}
Author: {author}
Slug: {slug}
Fingerprint: {fingerprint}
URL: {url}
            """.format(
                project_name=response_json['project_name'],
                author="@" + uri.split('/')[0],
                slug=uri,
                fingerprint=fingerprint,
                url="https://codeshare.frida.re/@{}".format(uri)
            ))

            while True:
                prompt_string = "Are you sure you'd like to trust this project? [y/N] "
                response = get_input(prompt_string)

                if response.lower() in ('n', 'no') or response == '':
                    return None

                if response.lower() in ('y', 'yes'):
                    self._print(
                        "Adding fingerprint {} to the trust store! You won't be prompted again unless the code changes.".format(
                            fingerprint))
                    script = response_json['source']
                    self._update_truststore({
                        uri: fingerprint
                    })
                    return script

        def _get_or_create_config_dir(self):
            xdg_home = os.getenv("XDG_CONFIG_HOME")
            if xdg_home is not None:
                config_dir = os.path.join(xdg_home, "frida")
            else:
                config_dir = os.path.join(os.path.expanduser("~"), ".frida")
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            return config_dir

        def _update_truststore(self, record):
            trust_store = self._get_or_create_truststore()
            trust_store.update(record)

            config_dir = self._get_or_create_config_dir()
            codeshare_trust_store = os.path.join(config_dir, "codeshare-truststore.json")

            with open(codeshare_trust_store, 'w') as f:
                f.write(json.dumps(trust_store))

        def _get_or_create_truststore(self):
            config_dir = self._get_or_create_config_dir()

            codeshare_trust_store = os.path.join(config_dir, "codeshare-truststore.json")

            if os.path.exists(codeshare_trust_store):
                try:
                    with open(codeshare_trust_store) as f:
                        trust_store = json.load(f)
                except Exception as e:
                    self._print(
                        "Unable to load the codeshare truststore ({}), defaulting to an empty truststore. You will be prompted every time you want to run a script!".format(
                            e))
                    trust_store = {}
            else:
                with open(codeshare_trust_store, 'w') as f:
                    f.write(json.dumps({}))
                trust_store = {}

            return trust_store

    class FridaCompleter(Completer):
        def __init__(self, repl):
            self._repl = repl
            self._lexer = JavascriptLexer()

        def get_completions(self, document, complete_event):
            prefix = document.text_before_cursor

            magic = len(prefix) > 0 and prefix[0] == '%' and not any(map(lambda c: c.isspace(), prefix))

            tokens = list(self._lexer.get_tokens(prefix))[:-1]

            # 0.toString() is invalid syntax,
            # but pygments doesn't seem to know that
            for i in range(len(tokens) - 1):
                if tokens[i][0] == Token.Literal.Number.Integer \
                        and tokens[i + 1][0] == Token.Punctuation and tokens[i + 1][1] == '.':
                    tokens[i] = (Token.Literal.Number.Float, tokens[i][1] + tokens[i + 1][1])
                    del tokens[i + 1]

            before_dot = ''
            after_dot = ''
            encountered_dot = False
            for t in tokens[::-1]:
                if t[0] in Token.Name.subtypes:
                    before_dot = t[1] + before_dot
                elif t[0] == Token.Punctuation and t[1] == '.':
                    before_dot = '.' + before_dot
                    if not encountered_dot:
                        encountered_dot = True
                        after_dot = before_dot[1:]
                        before_dot = ''
                else:
                    if encountered_dot:
                        # The value/contents of the string, number or array doesn't matter,
                        # so we just use the simplest value with that type
                        if t[0] in Token.Literal.String.subtypes:
                            before_dot = '""' + before_dot
                        elif t[0] in Token.Literal.Number.subtypes:
                            before_dot = '0.0' + before_dot
                        elif t[0] == Token.Punctuation and t[1] == ']':
                            before_dot = '[]' + before_dot

                    break

            try:
                if encountered_dot:
                    if before_dot == "" or before_dot.endswith("."):
                        return
                    for key in self._get_keys("""\
                            (() => {
                                let o;
                                try {
                                    o = """ + before_dot + """;
                                } catch (e) {
                                    return [];
                                }

                                if (o === undefined || o === null)
                                    return [];

                                let k = Object.getOwnPropertyNames(o);

                                let p;
                                if (typeof o !== 'object')
                                    p = o.__proto__;
                                else
                                    p = Object.getPrototypeOf(o);
                                if (p !== null && p !== undefined)
                                    k = k.concat(Object.getOwnPropertyNames(p));

                                return k;
                            })();"""):
                        if self._pattern_matches(after_dot, key):
                            yield Completion(key, -len(after_dot))
                else:
                    if magic:
                        keys = self._repl._magic_command_args.keys()
                    else:
                        keys = self._get_keys("Object.getOwnPropertyNames(this)")
                    for key in keys:
                        if not self._pattern_matches(before_dot, key) or (key.startswith('_') and before_dot == ''):
                            continue
                        yield Completion(key, -len(before_dot))
            except frida.InvalidOperationError:
                pass
            except frida.OperationCancelledError:
                pass
            except Exception as e:
                self._repl._print(e)

        def _get_keys(self, code):
            repl = self._repl
            with repl._reactor.io_cancellable:
                (t, value) = repl._evaluate(code)

            if t == 'error':
                return []

            return sorted(filter(self._is_valid_name, set(value)))

        def _is_valid_name(self, name):
            tokens = list(self._lexer.get_tokens(name))
            return len(tokens) == 2 and tokens[0][0] in Token.Name.subtypes

        def _pattern_matches(self, pattern, text):
            return re.search(re.escape(pattern), text, re.IGNORECASE) != None

    def hexdump(src, length=16):
        try:
            xrange
        except NameError:
            xrange = range
        FILTER = "".join([(len(repr(chr(x))) == 3) and chr(x) or "." for x in range(256)])
        lines = []
        for c in xrange(0, len(src), length):
            chars = src[c:c + length]
            hex = " ".join(["%02x" % x for x in iterbytes(chars)])
            printable = ''.join(["%s" % ((x <= 127 and FILTER[x]) or ".") for x in iterbytes(chars)])
            lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
        return "".join(lines)

    def is_byte_array(value):
        if sys.version_info[0] >= 3:
            return isinstance(value, bytes)
        else:
            return isinstance(value, str)

    if sys.version_info[0] >= 3:
        iterbytes = lambda x: iter(x)
    else:
        def iterbytes(data):
            return (ord(char) for char in data)

    OS_BINARY_SIGNATURES = set([
        b"\x4d\x5a",         # PE
        b"\xca\xfe\xba\xbe", # Fat Mach-O
        b"\xcf\xfa\xed\xfe", # Mach-O
        b"\x7fELF",          # ELF
    ])

    def code_is_native(code):
        return (code[:4] in OS_BINARY_SIGNATURES) or (code[:2] in OS_BINARY_SIGNATURES)

    app = REPLApplication()
    app.run()


class JavaScriptError(Exception):
    def __init__(self, error):
        super(JavaScriptError, self).__init__(error['message'])

        self.error = error


class DumbStdinReader(object):
    def __init__(self, valid_until):
        self._valid_until = valid_until

        self._prompt = None
        self._result = None
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

        worker = threading.Thread(target=self._process_requests, name="stdin-reader")
        worker.daemon = True
        worker.start()

        signal.signal(signal.SIGINT, lambda n, f: self._cancel_line())

    def read_line(self, prompt_string):
        with self._lock:
            self._prompt = prompt_string
            self._cond.notify()

        with self._lock:
            while self._result is None:
                if self._valid_until():
                    raise EOFError()
                self._cond.wait(1)
            line, error = self._result
            self._result = None

        if error is not None:
            raise error

        return line

    def _process_requests(self):
        error = None
        while error is None:
            with self._lock:
                while self._prompt is None:
                    self._cond.wait()
                prompt = self._prompt

            try:
                line = get_input(prompt)
            except Exception as e:
                line = None
                error = e

            with self._lock:
                self._prompt = None
                self._result = (line, error)
                self._cond.notify()

    def _cancel_line(self):
        with self._lock:
            self._prompt = None
            self._result = (None, KeyboardInterrupt())
            self._cond.notify()


if os.environ.get("TERM", "") == 'dumb':
    try:
        from collections import namedtuple
        from epc.client import EPCClient
        import sys
    except ImportError:
        def start_completion_thread(repl, epc_port=None):
            # Do nothing when we cannot import the EPC module.
            _, _ = repl, epc_port
    else:
        class EPCCompletionClient(EPCClient):
            def __init__(self, address="localhost", port=None, *args, **kargs):
                if port is not None:
                    args = ((address, port),) + args
                EPCClient.__init__(self, *args, **kargs)

                def complete(*cargs, **ckargs):
                    return self.complete(*cargs, **ckargs)
                self.register_function(complete)

        EpcDocument = namedtuple('Document', ['text_before_cursor',])

        SYMBOL_CHARS = "._" + string.ascii_letters + string.digits
        FIRST_SYMBOL_CHARS = "_" + string.ascii_letters
        class ReplEPCCompletion(object):
            def __init__(self, repl, *args, **kargs):
                _, _ = args, kargs
                self._repl = repl

            def complete(self, *to_complete):
                to_complete = "".join(to_complete)
                prefix = ''
                if len(to_complete) != 0:
                    for i, x in enumerate(to_complete[::-1]):
                        if x not in SYMBOL_CHARS:
                            while i >= 0 and to_complete[-i] not in FIRST_SYMBOL_CHARS:
                                i -= 1
                            prefix, to_complete = to_complete[:-i], to_complete[-i:]
                            break
                pos = len(prefix)
                if "." in to_complete:
                    prefix += to_complete.rsplit(".", 1)[0] + "."
                try:
                    completions = self._repl._completer.get_completions(
                        EpcDocument(text_before_cursor=to_complete), None)
                except Exception as ex:
                    _ = ex
                    return tuple()
                completions = [
                    {
                        "word": prefix + c.text,
                        "pos": pos,
                    }
                    for c in completions
                ]
                return tuple(completions)

        class ReplEPCCompletionClient(EPCCompletionClient, ReplEPCCompletion):
            def __init__(self, repl, *args, **kargs):
                EPCCompletionClient.__init__(self, *args, **kargs)
                ReplEPCCompletion.__init__(self, repl)

        def start_completion_thread(repl, epc_port=None):
            if epc_port is None:
                epc_port = os.environ.get("EPC_COMPLETION_SERVER_PORT", None)
            rpc_complete_thread = None
            if epc_port is not None:
                epc_port = int(epc_port)
                rpc_complete = ReplEPCCompletionClient(repl, port=epc_port)
                rpc_complete_thread = threading.Thread(
                    target=rpc_complete.connect,
                    name="PythonModeEPCCompletion",
                    kwargs={'socket_or_address': ("localhost", epc_port)})
            if rpc_complete_thread is not None:
                rpc_complete_thread.daemon = True
                rpc_complete_thread.start()
                return rpc_complete_thread
else:
    def start_completion_thread(repl, epc_port=None):
        # Do nothing as completion-epc is not needed when not running in Emacs.
        _, _ = repl, epc_port


try:
    input_impl = raw_input
except NameError:
    input_impl = input


def get_input(prompt_string):
    return input_impl(prompt_string)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
