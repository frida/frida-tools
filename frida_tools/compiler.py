# -*- coding: utf-8 -*-
import frida
import os
import sys
from timeit import default_timer as timer

from frida_tools.application import ConsoleApplication, await_ctrl_c
from frida_tools.cli_formatting import format_error, format_compiling, format_compiled, format_diagnostic


def main():
    app = CompilerApplication()
    app.run()


class CompilerApplication(ConsoleApplication):
    def __init__(self):
        super(CompilerApplication, self).__init__(await_ctrl_c)

    def _usage(self):
        return "%(prog)s [options] <module>"

    def _add_options(self, parser):
        parser.add_argument("module", help="TypeScript/JavaScript module to compile")
        parser.add_argument("-o", "--output", help="write output to <file>")
        parser.add_argument("-w", "--watch", help="watch for changes and recompile", action="store_true")
        parser.add_argument("-S", "--no-source-maps", help="omit source-maps", action="store_true")
        parser.add_argument("-c", "--compress", help="compress using terser", action="store_true")
        parser.add_argument("-v", "--verbose", help="be verbose", action="store_true")

    def _initialize(self, parser, options, args):
        self._module = os.path.abspath(options.module)
        self._output = options.output
        self._mode = "watch" if options.watch else "build"
        self._verbose = self._mode == "watch" or options.verbose
        self._compiler_options = {
            "source_maps": "omitted" if options.no_source_maps else "included",
            "compression": "terser" if options.compress else "none",
        }

        compiler = frida.Compiler()
        self._compiler = compiler

        def on_compiler_finished():
            self._reactor.schedule(lambda: self._on_compiler_finished())

        def on_compiler_output(bundle):
            self._reactor.schedule(lambda: self._on_compiler_output(bundle))

        def on_compiler_diagnostics(diagnostics):
            self._reactor.schedule(lambda: self._on_compiler_diagnostics(diagnostics))

        compiler.on("starting", self._on_compiler_starting)
        compiler.on("finished", on_compiler_finished)
        compiler.on("output", on_compiler_output)
        compiler.on("diagnostics", on_compiler_diagnostics)

        self._compilation_started = None

    def _needs_device(self):
        return False

    def _start(self):
        try:
            if self._mode == "build":
                self._compiler.build(self._module, **self._compiler_options)
                self._exit(0)
            else:
                self._compiler.watch(self._module, **self._compiler_options)
        except Exception as e:
            error = e
            self._reactor.schedule(lambda: self._on_fatal_error(error))

    def _on_fatal_error(self, error):
        self._print(format_error(error))
        self._exit(1)

    def _on_compiler_starting(self):
        self._compilation_started = timer()
        if self._verbose:
            self._reactor.schedule(lambda: self._print_compiler_starting())

    def _print_compiler_starting(self):
        if self._mode == "watch":
            sys.stdout.write("\x1Bc")
        self._print(format_compiling(self._module, os.getcwd()))

    def _on_compiler_finished(self):
        if self._verbose:
            time_finished = timer()
            self._print(format_compiled(self._module, os.getcwd(), self._compilation_started, time_finished))

    def _on_compiler_output(self, bundle):
        if self._output is not None:
            try:
                with open(self._output, "w", encoding="utf-8", newline="\n") as f:
                    f.write(bundle)
            except Exception as e:
                self._on_fatal_error(e)
        else:
            sys.stdout.write(bundle)

    def _on_compiler_diagnostics(self, diagnostics):
        cwd = os.getcwd()
        for diag in diagnostics:
            self._print(format_diagnostic(diag, cwd))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
