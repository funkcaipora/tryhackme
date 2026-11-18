"""A small YAML reader and writer for the files this skill owns.

Python has no YAML parser in its standard library, and the scripts promise to
need nothing else. This module handles the subset those files use:

  - comments and blank lines
  - block mappings, nested by indentation (spaces only)
  - block sequences of scalars
  - flow sequences of scalars on one line, such as [a, "b", 3], and the
    empty collections [] and {}
  - scalars: "double quoted", 'single quoted', plain text, integers, floats,
    true/false, null/~

Anything else (multi-line scalars, anchors, tags, sequences of mappings,
several documents) raises YamlError instead of being guessed at. A file this
module cannot read exactly should fail loudly.
"""
import json
import re

__all__ = ["YamlError", "loads", "load", "dumps", "dump"]


class YamlError(ValueError):
    """The text uses YAML this module does not support, or is malformed."""


_INT = re.compile(r"^[-+]?[0-9]+$")
_FLOAT = re.compile(r"^[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?$")
_PLAIN_SAFE = re.compile(r"^[A-Za-z_/~.][A-Za-z0-9_./~@+\- ]*$")
_RESERVED = {"null", "true", "false", "yes", "no", "on", "off", "~"}
_UNSUPPORTED_START = "|>&*!%@`"


def _strip_comment(text):
    """Remove a trailing comment that is outside quotes."""
    out = []
    quote = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if quote == '"' and c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                if quote == "'" and i + 1 < n and text[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                quote = None
        elif c in "\"'":
            quote = c
            out.append(c)
        elif c == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        else:
            out.append(c)
        i += 1
    return "".join(out).rstrip()


def _lines(text):
    out = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        stripped = raw.lstrip(" ")
        if stripped.startswith("\t"):
            raise YamlError("line %d: tabs are not allowed for indentation" % number)
        indent = len(raw) - len(stripped)
        content = _strip_comment(stripped)
        if not content:
            continue
        if content == "---":
            if out:
                raise YamlError("line %d: several documents are not supported" % number)
            continue
        out.append((indent, content, number))
    return out


def _split_key(content):
    """Split 'key: value' at the first colon that ends a key. None if there is none."""
    quote = None
    i = 0
    n = len(content)
    while i < n:
        c = content[i]
        if quote:
            if quote == '"' and c == "\\":
                i += 2
                continue
            if c == quote:
                if quote == "'" and i + 1 < n and content[i + 1] == "'":
                    i += 2
                    continue
                quote = None
        elif c in "\"'" and i == 0:
            quote = c
        elif c == ":" and (i + 1 == n or content[i + 1] == " "):
            return content[:i].strip(), content[i + 1:].strip()
        i += 1
    return None


def _is_item(content):
    return content == "-" or content.startswith("- ")


def _quoted(text, number):
    quote = text[0]
    if len(text) < 2 or text[-1] != quote:
        raise YamlError("line %d: unterminated or trailing text after a quoted value" % number)
    if quote == "'":
        inner = text[1:-1]
        if "'" in inner.replace("''", ""):
            raise YamlError("line %d: stray quote inside a single-quoted value" % number)
        return inner.replace("''", "'")
    try:
        value = json.loads(text)
    except ValueError:
        raise YamlError("line %d: unsupported escape in a double-quoted value" % number)
    if not isinstance(value, str):
        raise YamlError("line %d: malformed quoted value" % number)
    return value


def _split_flow(inner, number):
    parts = []
    current = []
    quote = None
    i = 0
    n = len(inner)
    while i < n:
        c = inner[i]
        if quote:
            current.append(c)
            if quote == '"' and c == "\\" and i + 1 < n:
                current.append(inner[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
            current.append(c)
        elif c in "[]{}":
            raise YamlError("line %d: nested flow collections are not supported" % number)
        elif c == ",":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(c)
        i += 1
    if quote:
        raise YamlError("line %d: unterminated quote in a flow sequence" % number)
    last = "".join(current).strip()
    if last or parts:
        parts.append(last)
    return parts


def _scalar(text, number, allow_flow=True):
    if text == "":
        return None
    first = text[0]
    if first in "\"'":
        return _quoted(text, number)
    if first == "[":
        if not allow_flow or not text.endswith("]"):
            raise YamlError("line %d: malformed flow sequence" % number)
        return [_scalar(part, number, allow_flow=False) for part in _split_flow(text[1:-1], number)]
    if first == "{":
        if text == "{}":
            return {}
        raise YamlError("line %d: flow mappings are not supported" % number)
    if first in _UNSUPPORTED_START:
        raise YamlError("line %d: unsupported YAML syntax starting with %r; quote the value" % (number, first))
    if ": " in text or text.endswith(":"):
        raise YamlError("line %d: a plain value cannot contain ': '; quote it" % number)
    lowered = text.lower()
    if lowered in ("null", "~"):
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if _INT.match(text):
        return int(text)
    if _FLOAT.match(text):
        return float(text)
    return text


def _key(raw, number):
    if not raw:
        raise YamlError("line %d: empty key" % number)
    if raw[0] in "\"'":
        return _quoted(raw, number)
    return raw


def _block(lines, i, indent):
    if _is_item(lines[i][1]):
        return _sequence(lines, i, indent)
    return _mapping(lines, i, indent)


def _mapping(lines, i, indent):
    result = {}
    n = len(lines)
    while i < n:
        line_indent, content, number = lines[i]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise YamlError("line %d: unexpected indentation" % number)
        if _is_item(content):
            raise YamlError("line %d: a sequence item where a key was expected" % number)
        split = _split_key(content)
        if split is None:
            raise YamlError("line %d: expected 'key: value'" % number)
        key = _key(split[0], number)
        rest = split[1]
        if key in result:
            raise YamlError("line %d: duplicate key %r" % (number, key))
        i += 1
        if rest == "":
            if i < n and lines[i][0] > indent:
                value, i = _block(lines, i, lines[i][0])
            elif i < n and lines[i][0] == indent and _is_item(lines[i][1]):
                value, i = _sequence(lines, i, indent)
            else:
                value = None
        else:
            value = _scalar(rest, number)
        result[key] = value
    return result, i


def _sequence(lines, i, indent):
    result = []
    n = len(lines)
    while i < n:
        line_indent, content, number = lines[i]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise YamlError("line %d: unexpected indentation" % number)
        if not _is_item(content):
            break
        item = content[1:].strip()
        if item == "":
            raise YamlError("line %d: nested sequence items are not supported" % number)
        if item[0] not in "\"'[" and _split_key(item) is not None:
            raise YamlError("line %d: sequences of mappings are not supported" % number)
        result.append(_scalar(item, number))
        i += 1
    return result, i


def loads(text):
    """Parse YAML text. Returns None for an empty document."""
    lines = _lines(text)
    if not lines:
        return None
    value, i = _block(lines, 0, lines[0][0])
    if i != len(lines):
        raise YamlError("line %d: content outside the document structure" % lines[i][2])
    return value


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return loads(handle.read())


def _format_scalar(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if not isinstance(value, str):
        raise YamlError("cannot write a value of type %s" % type(value).__name__)
    plain = (
        _PLAIN_SAFE.match(value)
        and value == value.strip()
        and value.lower() not in _RESERVED
        and not _INT.match(value)
        and not _FLOAT.match(value)
    )
    return value if plain else json.dumps(value, ensure_ascii=False)


def _format_key(key):
    if not isinstance(key, str):
        key = str(key)
    return key if re.match(r"^[A-Za-z0-9_.\-]+$", key) else json.dumps(key, ensure_ascii=False)


def _emit(value, level, indent, out):
    pad = " " * (level * indent)
    for key, item in value.items():
        name = _format_key(key)
        if isinstance(item, dict):
            if item:
                out.append("%s%s:" % (pad, name))
                _emit(item, level + 1, indent, out)
            else:
                out.append("%s%s: {}" % (pad, name))
        elif isinstance(item, (list, tuple)):
            if not item:
                out.append("%s%s: []" % (pad, name))
                continue
            out.append("%s%s:" % (pad, name))
            for element in item:
                if isinstance(element, (dict, list, tuple)):
                    raise YamlError("a sequence may only hold scalars (key %r)" % key)
                out.append("%s%s- %s" % (pad, " " * indent, _format_scalar(element)))
        else:
            out.append("%s%s: %s" % (pad, name, _format_scalar(item)))


def dumps(value, indent=2, header=None):
    """Write a mapping as block YAML. `header` becomes leading comment lines."""
    if not isinstance(value, dict):
        raise YamlError("the top level must be a mapping")
    out = []
    if header:
        out.extend("# " + line if line else "#" for line in header.splitlines())
    _emit(value, 0, indent, out)
    return "\n".join(out) + "\n"


def dump(value, path, indent=2, header=None):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(dumps(value, indent=indent, header=header))
