"""Rendering of JavaScript values inspected by the REPL agent.

The agent encodes each evaluated value into a bounded tagged tree, so that
serializing cyclic or very large objects can never hang. This module
pretty-prints that tree with syntax highlighting.
"""

from typing import Any, List, Sequence, Tuple

from colorama import Fore, Style

# Tags mirror ValueTag in agents/repl/agent.ts.
NUMBER = 0
STRING = 1
OBJECT = 2
ARRAY = 3
NATIVE_POINTER = 4
NULL = 5
BOOLEAN = 6
BYTES = 7
FUNCTION = 8
ERROR = 9
UNDEFINED = 10
BIGINT = 11
SYMBOL = 12
DATE = 13
REGEXP = 14
MAP = 15
SET = 16
PROMISE = 17
WEAKMAP = 18
WEAKSET = 19
DEPTH_LIMIT = 20
CIRCULAR = 21

_CYAN = Fore.CYAN
_MINT = Fore.GREEN
_KEY = Fore.LIGHTGREEN_EX
_ORANGE = Fore.YELLOW
_PURPLE = Fore.MAGENTA
_RED = Fore.RED
_BLUE = Fore.BLUE
_GRAY = Fore.LIGHTBLACK_EX
_RESET = Style.RESET_ALL

_MAX_ITEMS = 100

_HEX_BYTES_PER_ROW = 16

_CONTAINER_NAMES = {OBJECT: "Object", ARRAY: "Array", MAP: "Map", SET: "Set"}

Node = Sequence[Any]


def render(tree: Node, blob: Sequence[int]) -> str:
    out: List[str] = []
    _append(tree, 0, out, blob)
    return "".join(out)


def render_hexdump(data: bytes) -> str:
    rows = []
    for offset in range(0, len(data), _HEX_BYTES_PER_ROW):
        rows.append(_hex_row(offset, data[offset:offset + _HEX_BYTES_PER_ROW]))
    return "\n".join(rows)


def is_undefined(tree: Node) -> bool:
    return tree[0] == UNDEFINED


def to_string_list(tree: Node) -> List[str]:
    return [element[1] for element in tree[2]]


def _append(node: Node, level: int, out: List[str], blob: Sequence[int]) -> None:
    tag = node[0]

    if tag == NUMBER:
        out.append(_color(_format_number(node[1]), _CYAN))

    elif tag == STRING:
        out.append(_color('"%s"' % node[1], _MINT))

    elif tag == OBJECT:
        _append_object(node, level, out, blob)

    elif tag == ARRAY:
        _append_array(node, level, out, blob)

    elif tag == NATIVE_POINTER:
        out.append(_color(node[1], _ORANGE))

    elif tag == NULL:
        out.append(_color("null", _ORANGE))

    elif tag == BOOLEAN:
        out.append(_color("true" if node[1] else "false", _ORANGE))

    elif tag == BYTES:
        _append_bytes(node, level, out, blob)

    elif tag == FUNCTION:
        out.append(_color(node[1], _PURPLE))

    elif tag == ERROR:
        _append_error(node, level, out)

    elif tag == UNDEFINED:
        out.append(_color("undefined", _ORANGE))

    elif tag == BIGINT:
        out.append(_color(node[1] + "n", _CYAN))

    elif tag == SYMBOL:
        out.append(_color(node[1], _PURPLE))

    elif tag == DATE:
        out.append(_color("Date(", _BLUE))
        out.append(_color(node[1], _MINT))
        out.append(_color(")", _BLUE))

    elif tag == REGEXP:
        _append_regexp(node, out)

    elif tag == MAP:
        _append_map(node, level, out, blob)

    elif tag == SET:
        _append_set(node, level, out, blob)

    elif tag == PROMISE:
        out.append(_color("Promise", _PURPLE))

    elif tag == WEAKMAP:
        out.append(_color("WeakMap", _PURPLE))

    elif tag == WEAKSET:
        out.append(_color("WeakSet", _PURPLE))

    elif tag == DEPTH_LIMIT:
        out.append(_color("%s<depth limit reached>" % _CONTAINER_NAMES[node[1]], _ORANGE))

    elif tag == CIRCULAR:
        out.append(_color("⟳ circular *%d" % node[1], _ORANGE))


def _append_object(node: Node, level: int, out: List[str], blob: Sequence[int]) -> None:
    properties = node[2]
    if not properties:
        out.append(_color("{}", _CYAN))
        return

    out.append(_color("{", _CYAN))
    out.append("\n")
    shown, hidden = _capped(properties)
    for index, (key, value) in enumerate(shown):
        _indent(level + 1, out)
        out.append(_color(key[1], _KEY))
        out.append(": ")
        _append(value, level + 1, out, blob)
        if _has_more(index, shown, hidden):
            out.append(",")
        out.append("\n")
    _append_overflow(hidden, level + 1, out)
    _indent(level, out)
    out.append(_color("}", _CYAN))


def _append_array(node: Node, level: int, out: List[str], blob: Sequence[int]) -> None:
    elements = node[2]
    if not elements:
        out.append("[]")
        return

    out.append("[")
    out.append("\n")
    shown, hidden = _capped(elements)
    for index, element in enumerate(shown):
        _indent(level + 1, out)
        _append(element, level + 1, out, blob)
        if _has_more(index, shown, hidden):
            out.append(",")
        out.append("\n")
    _append_overflow(hidden, level + 1, out)
    _indent(level, out)
    out.append("]")


def _append_bytes(node: Node, level: int, out: List[str], blob: Sequence[int]) -> None:
    offset, length, kind = node[1], node[2], node[3]
    out.append(_color("Bytes(", _MINT))
    out.append(_color(kind, _CYAN))
    out.append(_color("[%d])" % length, _MINT))
    data = bytes(blob[offset:offset + length])
    for start in range(0, len(data), _HEX_BYTES_PER_ROW):
        out.append("\n")
        _indent(level + 1, out)
        out.append(_hex_row(start, data[start:start + _HEX_BYTES_PER_ROW]))


def _append_error(node: Node, level: int, out: List[str]) -> None:
    name, message, stack = node[1], node[2], node[3]
    out.append(_color(name if not message else "%s: %s" % (name, message), _RED))
    if not stack:
        return
    for line in stack.split("\n"):
        out.append("\n")
        _indent(level + 1, out)
        out.append(Style.DIM + line + _RESET)


def _append_regexp(node: Node, out: List[str]) -> None:
    pattern, flags = node[1], node[2]
    out.append(_color("/", _PURPLE))
    out.append(_color(pattern, _MINT))
    out.append(_color("/", _PURPLE))
    if flags:
        out.append(_color(flags, _PURPLE))


def _append_map(node: Node, level: int, out: List[str], blob: Sequence[int]) -> None:
    entries = node[2]
    if not entries:
        out.append(_color("Map{}", _CYAN))
        return

    out.append(_color("Map{", _CYAN))
    out.append("\n")
    shown, hidden = _capped(entries)
    for index, (key, value) in enumerate(shown):
        _indent(level + 1, out)
        _append(key, level + 1, out, blob)
        out.append(" => ")
        _append(value, level + 1, out, blob)
        if _has_more(index, shown, hidden):
            out.append(",")
        out.append("\n")
    _append_overflow(hidden, level + 1, out)
    _indent(level, out)
    out.append(_color("}", _CYAN))


def _append_set(node: Node, level: int, out: List[str], blob: Sequence[int]) -> None:
    elements = node[2]
    if not elements:
        out.append(_color("Set[]", _CYAN))
        return

    out.append(_color("Set[", _CYAN))
    out.append("\n")
    shown, hidden = _capped(elements)
    for element in shown:
        _indent(level + 1, out)
        out.append(_color("• ", _CYAN))
        _append(element, level + 1, out, blob)
        out.append("\n")
    _append_overflow(hidden, level + 1, out)
    _indent(level, out)
    out.append(_color("]", _CYAN))


def _capped(items: Sequence[Any]) -> Tuple[Sequence[Any], int]:
    shown = items[:_MAX_ITEMS]
    return shown, len(items) - len(shown)


def _has_more(index: int, shown: Sequence[Any], hidden: int) -> bool:
    return index < len(shown) - 1 or hidden > 0


def _append_overflow(hidden: int, level: int, out: List[str]) -> None:
    if not hidden:
        return
    _indent(level, out)
    out.append(_color("… %d more" % hidden, _ORANGE))
    out.append("\n")


def _hex_row(offset: int, chunk: bytes) -> str:
    cells = " ".join(_color("%02X" % byte, _byte_color(byte)) for byte in chunk)
    padding = "   " * (_HEX_BYTES_PER_ROW - len(chunk))
    glyphs = "".join(_color(_ascii_glyph(byte), _GRAY) for byte in chunk)
    return "%s  %s%s  %s" % (_color("%08X" % offset, _KEY), cells, padding, glyphs)


def _byte_color(byte: int) -> str:
    if byte == 0x00:
        return _GRAY
    if 0x20 <= byte <= 0x7E:
        return _MINT
    if byte <= 0x1F or byte == 0x7F:
        return _ORANGE
    return _CYAN


def _ascii_glyph(byte: int) -> str:
    return chr(byte) if 0x20 <= byte <= 0x7E else "."


def _format_number(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    return str(value)


def _color(text: str, color: str) -> str:
    return color + text + _RESET


def _indent(level: int, out: List[str]) -> None:
    if level > 0:
        out.append("  " * level)
