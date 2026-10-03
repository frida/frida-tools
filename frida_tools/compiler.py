import argparse
import os
import sys
from pathlib import Path
from timeit import default_timer as timer
from typing import Any, Dict, List, Optional

import frida

from frida_tools.application import ConsoleApplication, await_ctrl_c
from frida_tools.cli_formatting import format_compiled, format_compiling, format_diagnostic, format_error


def main() -> None:
    app = CompilerApplication()
    app.run()


class CompilerApplication(ConsoleApplication):
    def __init__(self) -> None:
        super().__init__(await_ctrl_c)

    def _usage(self) -> str:
        return "%(prog)s [options] <module>"

    def _add_options(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("module", help="TypeScript/JavaScript module to compile")
        parser.add_argument("-o", "--output", help="write output to <file>")
        parser.add_argument("-w", "--watch", help="watch for changes and recompile", action="store_true")
        parser.add_argument(
            "-L", "--library", help="emit a library into the directory given by -o", action="store_true"
        )
        parser.add_argument("-S", "--no-source-maps", help="omit source-maps", action="store_true")
        parser.add_argument("-c", "--compress", help="minify code", action="store_true")
        parser.add_argument("-v", "--verbose", help="be verbose", action="store_true")
        parser.add_argument(
            "-F",
            "--output-format",
            help="desired output format",
            choices=["unescaped", "hex-bytes", "c-string"],
            default="unescaped",
        )
        parser.add_argument(
            "-B", "--bundle-format", help="desired bundle format", choices=["esm", "iife"], default="esm"
        )
        parser.add_argument(
            "-T", "--type-check", help="desired type-checking mode", choices=["full", "none"], default="full"
        )
        parser.add_argument(
            "-P",
            "--platform",
            help="JavaScript runtime platform",
            choices=["gum", "browser", "neutral"],
            default="gum",
        )
        parser.add_argument(
            "-E",
            "--external",
            metavar="MODULE",
            action="append",
            default=[],
            help="mark MODULE as external (may be specified multiple times)",
        )

    def _initialize(self, parser: argparse.ArgumentParser, options: argparse.Namespace, args: List[str]) -> None:
        self._module = os.path.abspath(options.module)
        self._output = options.output
        if options.library and options.output is None:
            parser.error("--library requires -o <directory>")
        self._library = options.library
        self._mode = "watch" if options.watch else "build"
        self._verbose = self._mode == "watch" or options.verbose
        self._compiler_options = {
            "project_root": os.getcwd(),
            "output_format": options.output_format,
            "bundle_format": options.bundle_format,
            "type_check": options.type_check,
            "source_maps": "omitted" if options.no_source_maps else "included",
            "compression": "terser" if options.compress else "none",
            "platform": options.platform,
            "externals": options.external,
        }

        compiler = frida.Compiler()
        self._compiler = compiler

        def on_compiler_finished() -> None:
            self._reactor.schedule(lambda: self._on_compiler_finished())

        def on_compiler_output(bundle: str) -> None:
            self._reactor.schedule(lambda: self._on_compiler_output(bundle))

        def on_compiler_diagnostics(diagnostics: List[Dict[str, Any]]) -> None:
            self._reactor.schedule(lambda: self._on_compiler_diagnostics(diagnostics))

        compiler.on("starting", self._on_compiler_starting)
        compiler.on("finished", on_compiler_finished)
        compiler.on("output", on_compiler_output)
        compiler.on("diagnostics", on_compiler_diagnostics)

        self._compilation_started: Optional[float] = None

    def _needs_device(self) -> bool:
        return False

    def _start(self) -> None:
        try:
            if self._library:
                self._start_library()
            elif self._mode == "build":
                self._compiler.build(self._module, **self._compiler_options)
                self._exit(0)
            else:
                self._compiler.watch(self._module, **self._compiler_options)
        except Exception as e:
            error = e
            self._reactor.schedule(lambda: self._on_fatal_error(error))

    def _start_library(self) -> None:
        options = {
            "project_root": self._compiler_options["project_root"],
            "source_maps": self._compiler_options["source_maps"],
        }
        if self._mode == "build":
            self._compiler.build_library(self._module, self._output, **options)
            self._exit(0)
        else:
            self._compiler.watch_library(self._module, self._output, **options)

    def _on_fatal_error(self, error: Exception) -> None:
        self._print(format_error(error))
        self._exit(1)

    def _on_compiler_starting(self) -> None:
        self._compilation_started = timer()
        if self._verbose:
            self._reactor.schedule(lambda: self._print_compiler_starting())

    def _print_compiler_starting(self) -> None:
        if self._mode == "watch":
            sys.stdout.write("\x1bc")
        self._print(format_compiling(self._module, os.getcwd()))

    def _on_compiler_finished(self) -> None:
        if self._verbose:
            time_finished = timer()
            assert self._compilation_started is not None
            self._print(format_compiled(self._module, os.getcwd(), self._compilation_started, time_finished))

    def _on_compiler_output(self, bundle: str) -> None:
        if self._output is not None:
            try:
                output = Path(self._output)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(bundle, encoding="utf-8", newline="\n")
            except Exception as e:
                self._on_fatal_error(e)
        else:
            sys.stdout.write(bundle)

    def _on_compiler_diagnostics(self, diagnostics: List[Dict[str, Any]]) -> None:
        cwd = os.getcwd()
        for diag in diagnostics:
            self._print(format_diagnostic(diag, cwd))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
