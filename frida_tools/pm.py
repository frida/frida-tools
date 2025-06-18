#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import itertools
import json
import os
import re
import sys
import textwrap
import threading
import time
from typing import List, Optional

import frida
from colorama import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import print_formatted_text

from frida_tools.application import ConsoleApplication
from frida_tools.cli_formatting import THEME_COLOR

VERSION_COLOR = "#9e9e9e"

THEME_ATTR = f'fg="{THEME_COLOR}"'
VERSION_ATTR = f'fg="{VERSION_COLOR}"'

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def main() -> None:
    PackageManagerApplication().run()


class PackageManagerApplication(ConsoleApplication):
    def _usage(self) -> str:
        return "%(prog)s [options] <command> [...]"

    def _add_options(self, parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="command", metavar="<command>", required=True)

        search_p = sub.add_parser("search", help="Search for packages")
        search_p.add_argument("query", nargs="?", default="", help="Search string, e.g. 'trace'")
        search_p.add_argument("--offset", type=int, metavar="N", help="Result offset")
        search_p.add_argument("--limit", type=int, metavar="N", help="Max results")
        search_p.add_argument(
            "--json",
            action="store_true",
            help="Emit raw JSON instead of a table",
        )

        install_p = sub.add_parser("install", help="Install one or more packages")
        install_p.add_argument(
            "specs",
            nargs="*",
            metavar="SPEC",
            help="Package spec, e.g. 'frida-objc-bridge@^8.0.5' or 'frida-il2cpp-bridge'",
        )
        install_p.add_argument(
            "--project-root",
            default=os.getcwd(),
            metavar="DIR",
            help="Directory that will receive node_modules (default: CWD)",
        )
        install_p.add_argument("--quiet", action="store_true", help="Suppress the progress bar")

    def _initialize(
        self,
        parser: argparse.ArgumentParser,
        options: argparse.Namespace,
        args: List[str],
    ) -> None:
        self._opts = options
        self._extra = args

    def _needs_device(self) -> bool:
        return False

    def _start(self) -> None:
        try:
            if self._opts.command == "search":
                self._cmd_search()
            elif self._opts.command == "install":
                self._cmd_install()
            self._exit(0)
        except Exception as e:
            self._log("error", str(e))
            self._exit(1)

    def _cmd_search(self) -> None:
        pm = frida.PackageManager()

        interactive = self._have_terminal and not self._plain_terminal
        show_spinner = (not self._opts.json) and interactive

        stop_event = None
        spinner_thread = None
        if show_spinner:
            stop_event, spinner_thread = start_spinner(THEME_COLOR)

        try:
            res = pm.search(
                self._opts.query,
                offset=self._opts.offset,
                limit=self._opts.limit,
            )
        finally:
            if stop_event is not None:
                stop_event.set()
            if spinner_thread is not None:
                spinner_thread.join()

        if self._opts.json:
            print(
                json.dumps(
                    {
                        "packages": [
                            {
                                "name": p.name,
                                "version": p.version,
                                "description": p.description,
                                "url": p.url,
                            }
                            for p in res.packages
                        ],
                        "total": res.total,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return

        use_color = interactive
        col_w = 80

        for pkg in res.packages:
            header = (
                (f"<style {THEME_ATTR}>{esc(pkg.name)}</style>" f"<style {VERSION_ATTR}>@{esc(pkg.version)}</style>")
                if use_color
                else f"{pkg.name}@{pkg.version}"
            )

            desc = pkg.description or ""
            raw_len = len(pkg.name) + 1 + len(pkg.version)
            gap = " " * max(1, 32 - raw_len)
            wrapped = textwrap.wrap(desc, width=col_w - 32)

            first_line = f"{header}{gap}{esc(wrapped[0]) if wrapped else ''}"
            if use_color:
                print_formatted_text(HTML(first_line))
            else:
                print(first_line)

            for w in wrapped[1:]:
                print(" " * 32 + w)

            url_chunk = f"<style {THEME_ATTR}>{esc(pkg.url)}</style>" if use_color else pkg.url
            if use_color:
                print_formatted_text(HTML(" " * 32 + url_chunk))
            else:
                print(" " * 32 + pkg.url)
            print()

        shown = len(res.packages)
        offset = self._opts.offset or 0
        earlier = offset
        later = max(res.total - (offset + shown), 0)

        if earlier or later:
            parts = []
            if earlier:
                parts.append(f"{earlier} earlier")
            if later:
                parts.append(f"{later} more")
            print("… " + " and ".join(parts) + ". Use --limit and --offset to navigate through results.")

    def _cmd_install(self) -> None:
        pm = frida.PackageManager()

        interactive = self._have_terminal and not self._plain_terminal
        if self._opts.quiet or not interactive:
            result = pm.install(
                project_root=self._opts.project_root,
                specs=self._opts.specs,
            )
        else:
            BAR_LEN = 30
            FG = ansi_fg(THEME_COLOR)
            RESET = Style.RESET_ALL
            longest = 0

            def render(phase: str, fraction: float, details: Optional[str]) -> None:
                if details is not None:
                    return

                pct = int(fraction * 100)
                fill = int(fraction * BAR_LEN)
                bar = "█" * fill + " " * (BAR_LEN - fill)

                msg = phase.replace("-", " ")

                colored = f"\r{FG}[{bar}]{RESET} {pct:3d}% {msg}"

                visible_len = len(ANSI_PATTERN.sub("", colored)) - 1

                nonlocal longest
                if visible_len < longest:
                    pad = " " * (longest - visible_len)
                else:
                    pad = ""
                    longest = visible_len

                sys.stderr.write(colored + pad)
                sys.stderr.flush()

            pm.on("install-progress", render)
            try:
                result = pm.install(
                    project_root=self._opts.project_root,
                    specs=self._opts.specs,
                )
            finally:
                pm.off("install-progress", render)
                sys.stderr.write("\n")

        if not self._opts.quiet:
            for pkg in result.packages:
                print(f"✓ {pkg.name}@{pkg.version}")

            print(f"\n{len(result.packages)} package(s) installed " f"into {os.path.abspath(self._opts.project_root)}")


def start_spinner(theme_hex: str) -> tuple[threading.Event, threading.Thread]:
    stop = threading.Event()
    frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    colour = ansi_fg(theme_hex)
    reset = Style.RESET_ALL

    def run() -> None:
        while not stop.is_set():
            frame = next(frames)
            sys.stdout.write(f"\r{colour}{frame}{reset} Searching…")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return stop, t


def esc(text: str) -> str:
    return html.escape(text, quote=False)


def ansi_fg(hex_color: str) -> str:
    r, g, b = (int(hex_color[i : i + 2], 16) for i in (1, 3, 5))
    return f"\x1b[38;2;{r};{g};{b}m"


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
