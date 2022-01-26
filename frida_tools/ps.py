# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function


def main():
    from base64 import b64encode
    import json
    import math
    import platform
    import sys
    try:
        import termios
        import tty
    except:
        pass

    from frida_tools.application import ConsoleApplication


    class PSApplication(ConsoleApplication):
        def _add_options(self, parser):
            parser.add_argument("-a", "--applications", help="list only applications", action='store_true', dest="list_only_applications", default=False)
            parser.add_argument("-i", "--installed", help="include all installed applications", action='store_true', dest="include_all_applications", default=False)
            parser.add_argument("-j", "--json", help="output results as JSON", action='store_const', dest="output_format", const='json', default='text')

        def _initialize(self, parser, options, args):
            if options.include_all_applications and not options.list_only_applications:
                parser.error("-i cannot be used without -a")
            self._list_only_applications = options.list_only_applications
            self._include_all_applications = options.include_all_applications
            self._output_format = options.output_format
            self._terminal_type, self._icon_size = self._detect_terminal()

        def _usage(self):
            return "%(prog)s [options]"

        def _start(self):
            if self._list_only_applications:
                self._list_applications()
            else:
                self._list_processes()

        def _list_processes(self):
            if self._output_format == 'text' and self._terminal_type == 'iterm2':
                scope = 'full'
            else:
                scope = 'minimal'

            try:
                processes = self._device.enumerate_processes(scope=scope)
            except Exception as e:
                self._update_status("Failed to enumerate processes: %s" % e)
                self._exit(1)
                return

            if self._output_format == 'text':
                if len(processes) > 0:
                    pid_column_width = max(map(lambda p: len("%d" % p.pid), processes))
                    icon_width = max(map(compute_icon_width, processes))
                    name_column_width = icon_width + max(map(lambda p: len(p.name), processes))

                    header_format = "%" + str(pid_column_width) + "s  %s"
                    self._print(header_format % ("PID", "Name"))
                    self._print("%s  %s" % (pid_column_width * "-", name_column_width * "-"))

                    line_format = "%" + str(pid_column_width) + "d  %s"
                    name_format = "%-" + str(name_column_width - icon_width) + "s"

                    for process in sorted(processes, key=cmp_to_key(compare_processes)):
                        if icon_width != 0:
                            icons = process.parameters.get('icons', None)
                            if icons is not None:
                                icon = self._render_icon(icons[0])
                            else:
                                icon = "   "
                            name = icon + " " + name_format % process.name
                        else:
                            name = name_format % process.name

                        self._print(line_format % (process.pid, name))
                else:
                    self._log('error', "No running processes.")
            elif self._output_format == 'json':
                result = []
                for process in sorted(processes, key=cmp_to_key(compare_processes)):
                    result.append({'pid': process.pid, 'name': process.name})
                self._print(json.dumps(result, sort_keys=False, indent=2))

            self._exit(0)

        def _list_applications(self):
            if self._output_format == 'text' and self._terminal_type == 'iterm2':
                scope = 'full'
            else:
                scope = 'minimal'

            try:
                applications = self._device.enumerate_applications(scope=scope)
            except Exception as e:
                self._update_status("Failed to enumerate applications: %s" % e)
                self._exit(1)
                return

            if not self._include_all_applications:
                applications = list(filter(lambda app: app.pid != 0, applications))

            if self._output_format == 'text':
                if len(applications) > 0:
                    pid_column_width = max(map(lambda app: len("%d" % app.pid), applications))
                    icon_width = max(map(compute_icon_width, applications))
                    name_column_width = icon_width + max(map(lambda app: len(app.name), applications))
                    identifier_column_width = max(map(lambda app: len(app.identifier), applications))

                    header_format = "%" + str(pid_column_width) + "s  " + \
                        "%-" + str(name_column_width) + "s  " + \
                        "%-" + str(identifier_column_width) + "s"
                    self._print(header_format % ("PID", "Name", "Identifier"))
                    self._print("%s  %s  %s" % (pid_column_width * "-", name_column_width * "-", identifier_column_width * "-"))

                    line_format = "%" + str(pid_column_width) + "s  %s  %-" + str(identifier_column_width) + "s"
                    name_format = "%-" + str(name_column_width - icon_width) + "s"

                    for app in sorted(applications, key=cmp_to_key(compare_applications)):
                        if icon_width != 0:
                            icons = app.parameters.get('icons', None)
                            if icons is not None:
                                icon = self._render_icon(icons[0])
                            else:
                                icon = "   "
                            name = icon + " " + name_format % app.name
                        else:
                            name = name_format % app.name

                        if app.pid == 0:
                            self._print(line_format % ("-", name, app.identifier))
                        else:
                            self._print(line_format % (app.pid, name, app.identifier))

                elif self._include_all_applications:
                    self._log('error', "No installed applications.")
                else:
                    self._log('error', "No running applications.")
            elif self._output_format == 'json':
                result = []
                if len(applications) > 0:
                    for app in sorted(applications, key=cmp_to_key(compare_applications)):
                        result.append({'pid': (app.pid or None), 'name': app.name, 'identifier': app.identifier})
                self._print(json.dumps(result, sort_keys=False, indent=2))

            self._exit(0)

        def _render_icon(self, icon):
            return "\033]1337;File=inline=1;width={}px;height={}px;:{}\007".format(self._icon_size,
                                                                                   self._icon_size,
                                                                                   b64encode(icon['image']).decode('ascii'))

        def _detect_terminal(self):
            icon_size = 0

            if not self._have_terminal or self._plain_terminal or platform.system() != 'Darwin':
                return ('simple', icon_size)

            fd = sys.stdin.fileno()
            old_attributes = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                new_attributes = termios.tcgetattr(fd)
                new_attributes[3] = new_attributes[3] & ~termios.ICANON & ~termios.ECHO
                termios.tcsetattr(fd, termios.TCSANOW, new_attributes)

                sys.stdout.write("\033[1337n")
                sys.stdout.write("\033[5n")
                sys.stdout.flush()

                response = self._read_terminal_response('n')
                if response not in ("0", "3"):
                    self._read_terminal_response('n')

                    if response.startswith("ITERM2 "):
                        version_tokens = response.split(" ", 1)[1].split(".", 2)
                        if len(version_tokens) >= 2 and int(version_tokens[0]) >= 3:
                            sys.stdout.write("\033[14t")
                            sys.stdout.flush()
                            height_in_pixels = int(self._read_terminal_response('t').split(";")[1])

                            sys.stdout.write("\033[18t")
                            sys.stdout.flush()
                            height_in_cells = int(self._read_terminal_response('t').split(";")[1])

                            icon_size = math.ceil((height_in_pixels / height_in_cells) * 1.77)

                            return ('iterm2', icon_size)

                return ('simple', icon_size)
            finally:
                termios.tcsetattr(fd, termios.TCSANOW, old_attributes)

        def _read_terminal_response(self, terminator):
            sys.stdin.read(1)
            sys.stdin.read(1)
            result = ""
            while True:
                ch = sys.stdin.read(1)
                if ch == terminator:
                    break
                result += ch
            return result


    def compare_applications(a, b):
        a_is_running = a.pid != 0
        b_is_running = b.pid != 0
        if a_is_running == b_is_running:
            if a.name > b.name:
                return 1
            elif a.name < b.name:
                return -1
            else:
                return 0
        elif a_is_running:
            return -1
        else:
            return 1


    def compare_processes(a, b):
        a_has_icon = 'icons' in a.parameters
        b_has_icon = 'icons' in b.parameters
        if a_has_icon == b_has_icon:
            if a.name > b.name:
                return 1
            elif a.name < b.name:
                return -1
            else:
                return 0
        elif a_has_icon:
            return -1
        else:
            return 1


    def compute_icon_width(item):
        for icon in item.parameters.get('icons', []):
            if icon['format'] == 'png':
                return 4
        return 0


    def cmp_to_key(mycmp):
        "Convert a cmp= function into a key= function"
        class K:
            def __init__(self, obj, *args):
                self.obj = obj
            def __lt__(self, other):
                return mycmp(self.obj, other.obj) < 0
            def __gt__(self, other):
                return mycmp(self.obj, other.obj) > 0
            def __eq__(self, other):
                return mycmp(self.obj, other.obj) == 0
            def __le__(self, other):
                return mycmp(self.obj, other.obj) <= 0
            def __ge__(self, other):
                return mycmp(self.obj, other.obj) >= 0
            def __ne__(self, other):
                return mycmp(self.obj, other.obj) != 0
        return K


    app = PSApplication()
    app.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
