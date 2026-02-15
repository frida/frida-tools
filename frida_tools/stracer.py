from __future__ import annotations

import json
import queue
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import frida
from frida.core import RPCException

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.filters import Condition, has_focus
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import ConditionalContainer, Float, FloatContainer, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame, TextArea

from frida_tools.application import ConsoleApplication
from frida_tools.reactor import Reactor


AT_FDCWD = -100


# Linux errno table (kernel ABI). We cannot use host errno (may be different OS).
# Only include the common ones; unknown errors will be shown as "errno=<n>".
LINUX_ERRNO: Dict[int, str] = {
    1: "EPERM",
    2: "ENOENT",
    3: "ESRCH",
    4: "EINTR",
    5: "EIO",
    6: "ENXIO",
    7: "E2BIG",
    8: "ENOEXEC",
    9: "EBADF",
    10: "ECHILD",
    11: "EAGAIN",
    12: "ENOMEM",
    13: "EACCES",
    14: "EFAULT",
    15: "ENOTBLK",
    16: "EBUSY",
    17: "EEXIST",
    18: "EXDEV",
    19: "ENODEV",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    23: "ENFILE",
    24: "EMFILE",
    25: "ENOTTY",
    26: "ETXTBSY",
    27: "EFBIG",
    28: "ENOSPC",
    29: "ESPIPE",
    30: "EROFS",
    31: "EMLINK",
    32: "EPIPE",
    33: "EDOM",
    34: "ERANGE",
    35: "EDEADLK",
    36: "ENAMETOOLONG",
    37: "ENOLCK",
    38: "ENOSYS",
    39: "ENOTEMPTY",
    40: "ELOOP",
    42: "ENOMSG",
    43: "EIDRM",
    44: "ECHRNG",
    45: "EL2NSYNC",
    46: "EL3HLT",
    47: "EL3RST",
    48: "ELNRNG",
    49: "EUNATCH",
    50: "ENOCSI",
    51: "EL2HLT",
    52: "EBADE",
    53: "EBADR",
    54: "EXFULL",
    55: "ENOANO",
    56: "EBADRQC",
    57: "EBADSLT",
    59: "EBFONT",
    60: "ENOSTR",
    61: "ENODATA",
    62: "ETIME",
    63: "ENOSR",
    64: "ENONET",
    65: "ENOPKG",
    66: "EREMOTE",
    67: "ENOLINK",
    68: "EADV",
    69: "ESRMNT",
    70: "ECOMM",
    71: "EPROTO",
    72: "EMULTIHOP",
    73: "EDOTDOT",
    74: "EBADMSG",
    75: "EOVERFLOW",
    76: "ENOTUNIQ",
    77: "EBADFD",
    78: "EREMCHG",
    79: "ELIBACC",
    80: "ELIBBAD",
    81: "ELIBSCN",
    82: "ELIBMAX",
    83: "ELIBEXEC",
    84: "EILSEQ",
    85: "ERESTART",
    86: "ESTRPIPE",
    87: "EUSERS",
    88: "ENOTSOCK",
    89: "EDESTADDRREQ",
    90: "EMSGSIZE",
    91: "EPROTOTYPE",
    92: "ENOPROTOOPT",
    93: "EPROTONOSUPPORT",
    94: "ESOCKTNOSUPPORT",
    95: "EOPNOTSUPP",
    96: "EPFNOSUPPORT",
    97: "EAFNOSUPPORT",
    98: "EADDRINUSE",
    99: "EADDRNOTAVAIL",
    100: "ENETDOWN",
    101: "ENETUNREACH",
    102: "ENETRESET",
    103: "ECONNABORTED",
    104: "ECONNRESET",
    105: "ENOBUFS",
    106: "EISCONN",
    107: "ENOTCONN",
    108: "ESHUTDOWN",
    109: "ETOOMANYREFS",
    110: "ETIMEDOUT",
    111: "ECONNREFUSED",
    112: "EHOSTDOWN",
    113: "EHOSTUNREACH",
    114: "EALREADY",
    115: "EINPROGRESS",
    116: "ESTALE",
    117: "EUCLEAN",
    118: "ENOTNAM",
    119: "ENAVAIL",
    120: "EISNAM",
    121: "EREMOTEIO",
    122: "EDQUOT",
    123: "ENOMEDIUM",
    124: "EMEDIUMTYPE",
    125: "ECANCELED",
    126: "ENOKEY",
    127: "EKEYEXPIRED",
    128: "EKEYREVOKED",
    129: "EKEYREJECTED",
    130: "EOWNERDEAD",
    131: "ENOTRECOVERABLE",
    132: "ERFKILL",
    133: "EHWPOISON",
}


def main() -> None:
    app = StraceApplication()
    app.run()


class StraceApplication(ConsoleApplication):
    def __init__(self) -> None:
        self._state = "starting"
        self._ready = threading.Event()

        # IMPORTANT: do not read stdin in the reactor UI loop; prompt_toolkit owns stdio.
        super().__init__(self._process_input)

        self._tracer: Optional[SyscallTracer] = None

        self._events: List[SyscallEvent] = []
        self._selected = 0
        self._tailing = True

        # When paused, we render from a frozen snapshot (so new events won't push content away).
        self._paused_events: Optional[List[SyscallEvent]] = None

        # For merging enter/exit into one row:
        # (pid, tid, nr) -> index into self._events of most recent "enter without exit"
        self._pending_by_key: Dict[Tuple[int, int, int], int] = {}

        self._lock = threading.Lock()
        self._limit = 5000

        self._ui_app: Optional[Application] = None
        self._list_win: Optional[Window] = None

        # Filtering
        self._filter_text = ""
        self._filter_editing = False
        self._filter_prev_text = ""

        # Stable fd colors.
        self._fd_color_by_value: Dict[int, str] = {}
        self._fd_color_palette = [
            "ansiblue",
            "ansigreen",
            "ansicyan",
            "ansimagenta",
            "ansiyellow",
            "ansibrightblue",
            "ansibrightgreen",
            "ansibrightcyan",
            "ansibrightmagenta",
            "ansibrightyellow",
        ]
        self._next_fd_color = 0

        # Render cache for list view (avoid rebuilding 5000 lines on every cursor move).
        self._list_model_version = 0
        self._list_cache_key: Optional[Tuple[int, str, bool, int]] = None
        self._list_cache: FormattedText = FormattedText()

        # Filtered view cache
        self._filter_cache_key: Optional[Tuple[int, str, bool, int]] = None
        self._filter_cache: List[SyscallEvent] = []

        # Controls are callables so repaint pulls the latest model.
        self._list_ctl = FormattedTextControl(
            text=self._get_list_text,
            focusable=True,
            get_cursor_position=self._get_list_cursor_position,
        )
        self._detail_ctl = FormattedTextControl(text=self._get_detail_text)
        self._status_ctl = FormattedTextControl(text=self._get_status_text)

        # Filter bar (float; only visible while editing)
        self._filter_bar = TextArea(
            height=1,
            prompt="/",
            multiline=False,
            wrap_lines=False,
        )
        self._filter_bar.buffer.on_text_changed += self._on_filter_text_changed

        self._filter_win: Optional[Window] = None

        # For errno stringification (only for platform == "linux")
        self._platform: Optional[str] = None

    def _needs_target(self) -> bool:
        return False

    def _add_options(self, parser) -> None:
        parser.add_argument("--user", action="append", dest="users", help="Trace processes owned by USER (repeatable)")
        parser.add_argument("--pid", action="append", type=int, dest="pids", help="Trace PID (repeatable)")
        parser.add_argument("--uid", action="append", type=int, dest="uids", help="Trace UID (repeatable)")
        parser.add_argument("--limit", type=int, default=5000, help="Max events kept in UI (default: 5000)")

    def _initialize(self, parser, options, args) -> None:
        self._users = options.users
        self._pids = options.pids
        self._uids = options.uids
        self._limit = options.limit

        if self._users is None and self._pids is None and self._uids is None:
            raise ValueError("At least one target must be specified (use --user, --pid, and/or --uid).")

    def _usage(self) -> str:
        return "%(prog)s [options]"

    def _start(self) -> None:
        # Determine platform once (guaranteed to succeed).
        params = self._device.query_system_parameters()  # type: ignore[union-attr]
        self._platform = params["platform"]

        self._tracer = SyscallTracer(self._reactor)
        self._tracer.set_notify(self._notify_ui)

        targets_req: Dict[str, Any] = {}
        if self._users is not None:
            targets_req["users"] = self._users
        if self._pids is not None:
            targets_req["pids"] = self._pids
        if self._uids is not None:
            targets_req["uids"] = self._uids

        try:
            self._tracer.start(self._device, targets_req=targets_req)  # type: ignore[arg-type]
        except RPCException as e:
            self._log("error", f"Unable to start: {e.args[0]}")
            self._exit(1)
            self._state = "stopping"
            self._ready.set()
            return
        except Exception as e:
            self._log("error", f"Unable to start: {e}")
            self._exit(1)
            self._state = "stopping"
            self._ready.set()
            return

        self._ui_app = self._create_ui()

        self._state = "started"
        self._ready.set()

    def _stop(self) -> None:
        if self._tracer is not None:
            try:
                self._tracer.stop()
            except Exception:
                pass
            self._tracer = None

        if self._ui_app is not None:
            try:
                self._ui_app.exit()
            except Exception:
                pass
            self._ui_app = None

    def _process_input(self, reactor: Reactor) -> None:
        try:
            while self._ready.wait(0.5) != True:
                if not reactor.is_running():
                    return
        except KeyboardInterrupt:
            reactor.cancel_io()
            return

        if self._state != "started":
            return

        self._ui_app.run()

    def _create_ui(self) -> Application:
        kb = KeyBindings()

        @kb.add("q")
        @kb.add("c-c")
        def _(event):
            self._reactor.cancel_io()
            self._exit(0)
            event.app.exit()

        # Only trigger filter hotkey when NOT already editing filter.
        @kb.add("/", filter=~has_focus(self._filter_bar.control))
        def _(event):
            self._begin_filter_edit(event)

        @kb.add("down")
        def _(event):
            with self._lock:
                self._pause_if_tailing()
                view = self._get_filtered_view_locked()
                if self._selected < len(view) - 1:
                    self._selected += 1
            event.app.invalidate()

        @kb.add("up")
        def _(event):
            with self._lock:
                self._pause_if_tailing()
                if self._selected > 0:
                    self._selected -= 1
            event.app.invalidate()

        @kb.add("pageup")
        def _(event):
            with self._lock:
                self._pause_if_tailing()
                height = self._list_win.render_info.window_height
                self._selected = max(0, self._selected - max(1, height - 1))
            event.app.invalidate()

        @kb.add("pagedown")
        def _(event):
            with self._lock:
                self._pause_if_tailing()
                view = self._get_filtered_view_locked()
                height = self._list_win.render_info.window_height
                self._selected = min(len(view) - 1, self._selected + max(1, height - 1))
            event.app.invalidate()

        @kb.add("home")
        def _(event):
            with self._lock:
                self._pause_if_tailing()
                self._selected = 0
            event.app.invalidate()

        @kb.add("t")
        @kb.add("end")
        def _(event):
            with self._lock:
                self._tailing = True
                self._paused_events = None
                self._bump_list_model_version_locked()
                self._invalidate_filter_cache_locked()
                view = self._get_filtered_view_locked()
                self._selected = max(0, len(view) - 1)
            event.app.layout.focus(self._list_win)
            event.app.invalidate()

        @kb.add("enter")
        def _(event):
            # If filter is focused, accept filter; otherwise resolve backtrace.
            if event.app.layout.current_control == self._filter_bar.control:
                self._end_filter_edit(keep=True, event=event)
            else:
                self._on_enter()
            event.app.invalidate()

        @kb.add("escape")
        def _(event):
            if event.app.layout.current_control == self._filter_bar.control:
                self._end_filter_edit(keep=False, event=event)
                event.app.invalidate()

        @kb.add("c-u")
        def _(event):
            if event.app.layout.current_control == self._filter_bar.control:
                self._filter_bar.text = ""
                event.app.invalidate()

        list_win = Window(
            content=self._list_ctl,
            wrap_lines=False,
            cursorline=True,
            always_hide_cursor=False,
        )
        self._list_win = list_win

        detail_win = Window(content=self._detail_ctl, wrap_lines=True, always_hide_cursor=True)
        status_win = Window(height=1, content=self._status_ctl, wrap_lines=False)

        body = HSplit(
            [
                VSplit(
                    [
                        Frame(list_win, title="Syscalls"),
                        Frame(detail_win, title="Details"),
                    ]
                ),
                Frame(status_win, title="Status"),
            ]
        )

        filter_win = Window(height=1, content=self._filter_bar.control, wrap_lines=False)
        self._filter_win = filter_win

        filter_float = ConditionalContainer(
            content=Frame(filter_win, title="Filter"),
            filter=Condition(lambda: self._filter_editing),
        )

        root = FloatContainer(
            content=body,
            floats=[
                Float(
                    content=filter_float,
                    bottom=1,
                    left=0,
                    right=0,
                    height=3,
                )
            ],
        )

        layout = Layout(root, focused_element=list_win)
        app = Application(layout=layout, key_bindings=kb, full_screen=True)
        return app

    def _begin_filter_edit(self, event) -> None:
        with self._lock:
            self._pause_if_tailing()
            self._filter_editing = True
            self._filter_prev_text = self._filter_text
            self._filter_bar.text = self._filter_text
        event.app.layout.focus(self._filter_bar.control)
        event.app.invalidate()

    def _end_filter_edit(self, keep: bool, event) -> None:
        with self._lock:
            if keep:
                self._filter_text = self._filter_bar.text
            else:
                self._filter_text = self._filter_prev_text
                self._filter_bar.text = self._filter_prev_text

            self._filter_editing = False
            self._invalidate_filter_cache_locked()

            view = self._get_filtered_view_locked()
            if self._tailing:
                self._selected = max(0, len(view) - 1)
            else:
                self._selected = min(self._selected, max(0, len(view) - 1)) if view else 0

        event.app.layout.focus(self._list_win)
        event.app.invalidate()

    def _on_filter_text_changed(self, _) -> None:
        if self._ui_app is None:
            return
        with self._lock:
            if not self._filter_editing:
                return
            self._filter_text = self._filter_bar.text
            self._invalidate_filter_cache_locked()
            view = self._get_filtered_view_locked()
            if self._tailing:
                self._selected = max(0, len(view) - 1)
            else:
                self._selected = min(self._selected, max(0, len(view) - 1)) if view else 0
        self._ui_app.invalidate()

    def _pause_if_tailing(self) -> None:
        if self._tailing:
            self._tailing = False
            self._paused_events = list(self._events)
            self._selected = min(self._selected, max(0, len(self._paused_events) - 1)) if self._paused_events else 0
            self._bump_list_model_version_locked()
            self._invalidate_filter_cache_locked()

    def _get_base_view_locked(self) -> List["SyscallEvent"]:
        return self._events if self._tailing else self._paused_events  # type: ignore[return-value]

    def _invalidate_filter_cache_locked(self) -> None:
        self._filter_cache_key = None
        self._list_cache_key = None

    def _get_filtered_view_locked(self) -> List["SyscallEvent"]:
        base = self._get_base_view_locked()
        key = (self._list_model_version, self._filter_text, self._tailing, id(base))
        if self._filter_cache_key == key:
            return self._filter_cache

        f = self._filter_text
        if f == "":
            self._filter_cache = base
            self._filter_cache_key = key
            return self._filter_cache

        f_lc = f.lower()
        out: List[SyscallEvent] = []
        for ev in base:
            if self._event_matches_filter(ev, f_lc):
                out.append(ev)

        self._filter_cache = out
        self._filter_cache_key = key
        return self._filter_cache

    def _event_matches_filter(self, ev: "SyscallEvent", f_lc: str) -> bool:
        if f_lc in ev.name.lower():
            return True
        if f_lc in str(ev.pid) or f_lc in str(ev.tid) or f_lc in str(ev.nr):
            return True
        if ev.enter_args is not None:
            for a in ev.enter_args:
                if f_lc in a.name.lower():
                    return True
                if f_lc in a.text.lower():
                    return True
        if ev.exit_retval is not None and f_lc in str(ev.exit_retval).lower():
            return True
        return False

    def _notify_ui(self) -> None:
        if self._ui_app is None:
            return
        self._ui_app.loop.call_soon_threadsafe(self._drain_and_refresh_on_ui)

    def _drain_and_refresh_on_ui(self) -> None:
        tracer = self._tracer
        if tracer is None:
            return

        new_events = tracer.drain_events(limit=5000)
        updates = tracer.drain_updates(limit=5000)

        changed_list = False

        with self._lock:
            if new_events:
                for ev in new_events:
                    changed_list |= self._append_or_merge_event_locked(ev)

                if len(self._events) > self._limit:
                    overflow = len(self._events) - self._limit

                    if overflow > 0:
                        new_pending: Dict[Tuple[int, int, int], int] = {}
                        for k, idx in self._pending_by_key.items():
                            if idx >= overflow:
                                new_pending[k] = idx - overflow
                        self._pending_by_key = new_pending

                    self._events = self._events[overflow:]
                    changed_list = True

                    if self._tailing:
                        self._selected = max(0, self._selected - overflow)

                if self._tailing:
                    view = self._get_filtered_view_locked()
                    self._selected = max(0, len(view) - 1)

            if updates:
                id_to_event = {e.id: e for e in self._events}
                if self._paused_events is not None:
                    for e in self._paused_events:
                        id_to_event.setdefault(e.id, e)

                for (event_id, stack_or_none, syms_or_exc) in updates:
                    ev = id_to_event.get(event_id)
                    if ev is None:
                        continue
                    ev.resolving = False
                    if stack_or_none is None:
                        ev.resolve_error = str(syms_or_exc)
                    else:
                        ev.stack = stack_or_none
                        ev.symbols = syms_or_exc
                        ev.resolve_error = None

            if changed_list:
                self._bump_list_model_version_locked()
                self._invalidate_filter_cache_locked()

        self._ui_app.invalidate()

    def _bump_list_model_version_locked(self) -> None:
        self._list_model_version += 1

    def _append_or_merge_event_locked(self, ev: "SyscallEvent") -> bool:
        if ev.phase == "exit":
            key = (ev.pid, ev.tid, ev.nr)
            idx = self._pending_by_key.get(key)
            if idx is not None and 0 <= idx < len(self._events):
                prev = self._events[idx]
                if prev.phase == "enter" and prev.nr == ev.nr and prev.pid == ev.pid and prev.tid == ev.tid:
                    prev.set_exit(ev.exit_retval, ev.time_ns)
                    return True

        self._events.append(ev)
        if ev.phase == "enter":
            self._pending_by_key[(ev.pid, ev.tid, ev.nr)] = len(self._events) - 1
        return True

    def _on_enter(self) -> None:
        tracer = self._tracer
        if tracer is None:
            return

        with self._lock:
            view = self._get_filtered_view_locked()
            if not (0 <= self._selected < len(view)):
                return
            ev = view[self._selected]
            if ev.stack_id < 0 or ev.resolving or ev.stack is not None:
                return
            ev.resolving = True

        tracer.resolve_backtrace(ev.id, ev.pid, ev.map_gen, ev.stack_id)

    def _get_list_text(self) -> FormattedText:
        with self._lock:
            base = self._get_base_view_locked()
            view = self._get_filtered_view_locked()

            cache_key = (self._list_model_version, self._filter_text, self._tailing, id(base))
            if self._list_cache_key == cache_key:
                return self._list_cache

            if not view:
                self._list_cache = FormattedText([("", "(no events)")])
                self._list_cache_key = cache_key
                return self._list_cache

            out: FormattedText = []

            prev_ns_by_thread: Dict[Tuple[int, int], int] = {}

            for ev in view:
                thread_key = (ev.pid, ev.tid)
                prev_ns = prev_ns_by_thread.get(thread_key)
                if prev_ns is None:
                    dt = " " * 10
                else:
                    dt = self._format_dt(ev.time_ns - prev_ns)
                prev_ns_by_thread[thread_key] = ev.time_ns

                phase = "→" if ev.phase == "enter" else "←"
                if ev.merged:
                    phase = "↔"

                line_style = "fg:ansired" if ev.failed else ""

                out.append(("", f"{dt} "))
                out.append((line_style, f"[{ev.pid}:{ev.tid}] {phase} {ev.name}("))

                if ev.enter_args is not None:
                    out.extend(self._format_args(ev.enter_args))
                else:
                    out.append((line_style, ev.enter_summary or ""))

                out.append((line_style, ")"))

                if ev.exit_retval is not None:
                    out.append((line_style, " => "))
                    out.extend(self._format_retval(ev.exit_retval, failed=ev.failed))

                out.append(("", "\n"))

            if out and out[-1] == ("", "\n"):
                out.pop()

            self._list_cache = out
            self._list_cache_key = cache_key
            return self._list_cache

    def _format_args(self, args: List["Arg"]) -> FormattedText:
        out: FormattedText = []
        for j, a in enumerate(args):
            if j != 0:
                out.append(("", ", "))

            out.append(("", f"{a.name}="))

            if a.kind == "string":
                # Node-ish vibe (green strings), already double-quoted by json.dumps()
                out.append(("fg:ansigreen", a.text))
            elif a.kind == "bytes":
                out.append(("fg:ansiyellow", a.text))
            elif a.is_fd and isinstance(a.value, int):
                out.append((self._fd_style(a.value), a.text))
            else:
                out.append(("", a.text))
        return out

    def _format_retval(self, v: Any, failed: bool) -> FormattedText:
        # Linux errno stringification only; host-independent table above.
        if failed and isinstance(v, int) and self._platform == "linux":
            eno = -v
            name = LINUX_ERRNO.get(eno)
            if name is not None:
                return FormattedText([("fg:ansired bold", f"-{eno} {name}")])
            return FormattedText([("fg:ansired bold", f"-{eno} errno={eno}")])

        if isinstance(v, int) and failed:
            return FormattedText([("fg:ansired bold", str(v))])

        return FormattedText([("", str(v))])

    def _fd_style(self, fd: int) -> str:
        style = self._fd_color_by_value.get(fd)
        if style is None:
            color = self._fd_color_palette[self._next_fd_color % len(self._fd_color_palette)]
            self._next_fd_color += 1
            style = f"fg:{color} bold"
            self._fd_color_by_value[fd] = style
        return style

    def _format_dt(self, delta_ns: int) -> str:
        # Fixed width: 10 chars (including leading '+', right-aligned)
        if delta_ns < 0:
            delta_ns = 0

        if delta_ns < 1_000:
            s = f"+{delta_ns}ns"
        elif delta_ns < 1_000_000:
            s = f"+{delta_ns / 1_000:.0f}µs"
        elif delta_ns < 1_000_000_000:
            ms = delta_ns / 1_000_000
            s = f"+{ms:.1f}ms" if ms < 10 else f"+{ms:.0f}ms"
        else:
            sec = delta_ns / 1_000_000_000
            s = f"+{sec:.1f}s" if sec < 10 else f"+{sec:.0f}s"

        if len(s) > 10:
            s = s[:10]
        return s.rjust(10)

    def _get_list_cursor_position(self) -> Point:
        with self._lock:
            view = self._get_filtered_view_locked()
            if not view:
                return Point(x=0, y=0)
            y = max(0, min(self._selected, len(view) - 1))
            return Point(x=0, y=y)

    def _get_detail_text(self) -> str:
        with self._lock:
            view = self._get_filtered_view_locked()
            if not view or not (0 <= self._selected < len(view)):
                return ""
            ev = view[self._selected]

            detail = [
                f"id={ev.id}",
                f"pid={ev.pid} tid={ev.tid} abi={ev.abi}",
                f"nr={ev.nr} name={ev.name}",
                f"enter_time_ns={ev.time_ns}",
                f"map_gen={ev.map_gen} stack_id={ev.stack_id}",
                "",
            ]

            if ev.exit_time_ns is not None:
                detail.append(f"exit_time_ns={ev.exit_time_ns}")
                if ev.exit_retval is not None:
                    detail.append(f"retval={ev.exit_retval}")
                detail.append("status=FAILED" if ev.failed else "status=OK")
                detail.append("")

            if ev.stack_id < 0:
                detail.append("(no stack)")
            elif ev.resolving:
                detail.append("Resolving backtrace…")
            elif ev.resolve_error is not None:
                detail.append(f"Resolve failed: {ev.resolve_error}")
            elif ev.stack is None:
                detail.append("Press Enter to resolve backtrace")
            else:
                detail.append("Call stack:")
                detail += self._format_call_stack(ev)

            return "\n".join(detail)

    def _get_status_text(self) -> str:
        with self._lock:
            view = self._get_filtered_view_locked()
            mode = "tail" if self._tailing else "paused (press 't')"
            filt = self._filter_text
            if filt != "":
                return (
                    f"events={len(view)} selected={self._selected+1}/{len(view)}  "
                    f"[{mode}]  filter={json.dumps(filt, ensure_ascii=False)}"
                )
            if not view:
                return f"events=0  [{mode}]"
            return f"events={len(view)} selected={self._selected+1}/{len(view)}  [{mode}]"

    def _format_call_stack(self, ev: "SyscallEvent") -> List[str]:
        modules = ev.symbols["modules"]
        entries = ev.symbols["symbols"]
        stack = ev.stack

        out: List[str] = []
        for addr, (mod_index, offset) in zip(stack, entries):
            if mod_index == 0xFFFFFFFF:
                out.append(f"  0x{addr:x}")
            else:
                path = modules[mod_index]
                base = path.rsplit("/", 1)[-1]
                out.append(f"  {base}+0x{offset:x}")
        for addr in stack[len(entries) :]:
            out.append(f"  0x{addr:x}")
        return out


class SyscallTracer:
    def __init__(self, reactor: Reactor) -> None:
        self._reactor = reactor
        self._service: Optional[frida.core.Service] = None

        self._signatures: Dict[str, Dict[int, Dict[str, Any]]] = {}
        self._abi_by_pid: Dict[int, str] = {}

        self._events_out: "queue.Queue[SyscallEvent]" = queue.Queue()
        self._updates_out: "queue.Queue[tuple[int, Optional[list[int]], Any]]" = queue.Queue()

        self._next_id = 1

        # Read scheduling:
        # - _reading: currently inside _read_events_loop (reactor thread)
        # - _want_read: a sticky "events available" latch. If the service only signals once,
        #   we will still drain everything because _read_events_loop drains until status != "more".
        self._reading = False
        self._want_read = False
        self._stopping = False

        self._schedule_on_message = lambda m: self._reactor.schedule(lambda: self._handle_service_message(m))
        self._notify: Optional[callable] = None

    def set_notify(self, notify: callable) -> None:
        self._notify = notify

    def start(self, device: frida.core.Device, targets_req: Dict[str, Any]) -> None:
        self._service = device.open_service("syscall-trace")

        raw = self._service.request({"type": "get-signatures"})
        sigs: Dict[str, Dict[int, Dict[str, Any]]] = {}
        for abi, entries in raw.items():
            by_nr: Dict[int, Dict[str, Any]] = {}
            for (nr, name, args) in entries:
                by_nr[int(nr)] = {"name": name, "args": args}
            sigs[abi] = by_nr
        self._signatures = sigs

        self._service.on("message", self._schedule_on_message)

        add_req = {"type": "add-targets"}
        add_req.update(targets_req)
        self._service.request(add_req)

    def stop(self) -> None:
        self._stopping = True
        if self._service is not None:
            self._service.off("message", self._schedule_on_message)
            self._service.close()
        self._service = None

    def drain_events(self, limit: int = 2000) -> List["SyscallEvent"]:
        out: List[SyscallEvent] = []
        for _ in range(limit):
            try:
                out.append(self._events_out.get_nowait())
            except queue.Empty:
                break
        return out

    def drain_updates(self, limit: int = 2000) -> List[tuple[int, Optional[list[int]], Any]]:
        out: List[tuple[int, Optional[list[int]], Any]] = []
        for _ in range(limit):
            try:
                out.append(self._updates_out.get_nowait())
            except queue.Empty:
                break
        return out

    def resolve_backtrace(self, event_id: int, pid: int, map_gen: int, stack_id: int) -> None:
        self._reactor.schedule(lambda: self._resolve_backtrace_on_reactor(event_id, pid, map_gen, stack_id))

    def _handle_service_message(self, m) -> None:
        if self._stopping or self._service is None:
            return
        if m["type"] != "events-available":
            return

        # Sticky latch: if the service only emits one "events-available" while there is still
        # unread data, we still drain fully because _read_events_loop drains until status != "more".
        self._want_read = True

        if self._reading:
            return

        self._reading = True
        self._reactor.schedule(self._read_events_loop)

    def _read_events_loop(self) -> None:
        if self._stopping or self._service is None:
            self._reading = False
            self._want_read = False
            return

        try:
            # Consume the latch; if a new events-available comes in later, it will set it again.
            self._want_read = False

            # Drain aggressively until the service says we're caught up.
            while True:
                res = self._service.request({"type": "read-events"})
                events = res["events"]
                processes = res["processes"]
                status = res["status"]

                for pid, abi in processes:
                    self._abi_by_pid[int(pid)] = abi

                for row in events:
                    ev = self._parse_event_row(row)
                    self._events_out.put(ev)

                if events:
                    self._notify_ui()

                if status != "more":
                    break

            # If another events-available arrived after we finished draining (cannot happen while blocked
            # in request, but can happen after), the latch will be True again. We loop once more.
            if self._want_read:
                self._reactor.schedule(self._read_events_loop)
                return

        except Exception as e:
            # If we failed mid-drain, schedule another pass immediately; the latch stays sticky by setting it.
            self._want_read = True
            self._reactor.schedule(self._read_events_loop)
            print("Oh no:", e)
            return
        finally:
            # Only clear _reading once we are fully done scheduling follow-up work.
            self._reading = False

    def _notify_ui(self) -> None:
        if self._notify is not None:
            self._notify()

    def _parse_event_row(self, row) -> "SyscallEvent":
        phase, time_ns, pid, tid, nr, stack_id, map_gen, args_or_retval, attachments = row
        pid = int(pid)
        tid = int(tid)
        nr = int(nr)
        stack_id = int(stack_id)
        map_gen = int(map_gen)

        abi = self._abi_by_pid.get(pid)

        sig = None
        name = "some syscall"
        sig_args = None
        if nr != -1 and abi is not None:
            sig = self._signatures[abi].get(nr)
            if sig is not None:
                name = sig["name"]
                sig_args = sig["args"]
            else:
                name = f"#{nr}"
        elif nr != -1:
            name = f"#{nr}"

        if phase == "enter":
            raw_args = args_or_retval

            args: List[Arg] = []
            if sig_args is not None:
                for i, (atype, aname) in enumerate(sig_args):
                    value = raw_args[i]
                    for (ai, av) in attachments:
                        if int(ai) == i:
                            value = av
                            break
                    args.append(self._make_arg(atype, aname, value))
            else:
                for i, v in enumerate(raw_args):
                    value = v
                    for (ai, av) in attachments:
                        if int(ai) == i:
                            value = av
                            break
                    args.append(self._make_arg("", f"arg{i}", value))

            ev = SyscallEvent(
                id=self._next_id,
                phase="enter",
                time_ns=int(time_ns),
                pid=pid,
                tid=tid,
                nr=nr,
                name=name,
                enter_args=args,
                enter_summary=None,
                stack_id=stack_id,
                map_gen=map_gen,
                abi=abi,
            )
        else:
            retval = args_or_retval
            failed = isinstance(retval, int) and retval < 0
            ev = SyscallEvent(
                id=self._next_id,
                phase="exit",
                time_ns=int(time_ns),
                pid=pid,
                tid=tid,
                nr=nr,
                name=name,
                enter_args=None,
                enter_summary=None,
                stack_id=stack_id,
                map_gen=map_gen,
                abi=abi,
                exit_retval=retval,
                exit_time_ns=int(time_ns),
                failed=failed,
            )

        self._next_id += 1
        return ev

    def _make_arg(self, atype: str, aname: str, value: Any) -> "Arg":
        # Pointers: '*' OR unsigned long
        if (atype.endswith("*") or atype == "unsigned long") and isinstance(value, int):
            if value == 0:
                return Arg(type=atype, name=aname, value=value, text="NULL", is_fd=False, kind="ptr")
            return Arg(type=atype, name=aname, value=value, text=f"0x{value:x}", is_fd=False, kind="ptr")

        # FD-like: type is int/unsigned int and name contains "fd"
        is_fd = (atype in ("int", "unsigned int")) and ("fd" in aname.lower())
        if is_fd and isinstance(value, int):
            fd = to_signed32(value)
            if fd == AT_FDCWD:
                return Arg(type=atype, name=aname, value=fd, text="AT_FDCWD", is_fd=True, kind="fd")
            return Arg(type=atype, name=aname, value=fd, text=str(fd), is_fd=True, kind="fd")

        # Strings: render double-quoted.
        if isinstance(value, str):
            s = value if len(value) <= 140 else (value[:137] + "…")
            return Arg(
                type=atype,
                name=aname,
                value=value,
                text=json.dumps(s, ensure_ascii=False),
                is_fd=is_fd,
                kind="string",
            )

        # Bytes: hex.
        if isinstance(value, (bytes, bytearray)):
            b = bytes(value)
            if len(b) <= 32:
                text = "0x" + b.hex()
            else:
                text = "0x" + b[:32].hex() + f"…({len(b)} bytes)"
            return Arg(type=atype, name=aname, value=value, text=text, is_fd=is_fd, kind="bytes")

        if isinstance(value, (list, tuple)):
            text = f"[{len(value)}]"
        else:
            text = repr(value)

        return Arg(type=atype, name=aname, value=value, text=text, is_fd=is_fd, kind="other")

    def _resolve_backtrace_on_reactor(self, event_id: int, pid: int, map_gen: int, stack_id: int) -> None:
        if self._stopping or self._service is None:
            return
        try:
            stacks_res = self._service.request({"type": "resolve-stacks", "ids": [stack_id]})
            stack = stacks_res["stacks"][0]

            syms = self._service.request(
                {
                    "type": "resolve-symbols",
                    "pid": pid,
                    "gen": map_gen,
                    "addresses": [("uint64", address) for address in stack],
                }
            )

            self._updates_out.put((event_id, stack, syms))
        except Exception as e:
            self._updates_out.put((event_id, None, e))
        finally:
            self._notify_ui()


def to_signed32(v: int) -> int:
    v &= 0xFFFFFFFF
    if v & 0x80000000:
        return v - 0x100000000
    return v


@dataclass
class Arg:
    type: str
    name: str
    value: Any
    text: str
    is_fd: bool
    kind: str  # "string" / "bytes" / "fd" / "ptr" / "other"


@dataclass
class SyscallEvent:
    id: int
    phase: str  # "enter" / "exit"
    time_ns: int
    pid: int
    tid: int
    nr: int
    name: str

    # Enter-side
    enter_args: Optional[List[Arg]] = None
    enter_summary: Optional[str] = None

    # Exit-side (filled on exit or when merged)
    exit_retval: Optional[Any] = None
    exit_time_ns: Optional[int] = None

    # Metadata
    stack_id: int = -1
    map_gen: int = 0
    abi: Optional[str] = None

    # UI flags
    merged: bool = False
    failed: bool = False
    resolving: bool = False
    stack: Optional[List[int]] = None
    symbols: Optional[Any] = None
    resolve_error: Optional[str] = None

    def set_exit(self, retval: Any, exit_time_ns: int) -> None:
        self.exit_retval = retval
        self.exit_time_ns = exit_time_ns
        self.merged = True
        self.failed = isinstance(retval, int) and retval < 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
