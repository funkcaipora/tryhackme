"""A validator for the part of JSON Schema that the skill's schemas use.

The standard library has no JSON Schema validator. The schemas in
assets/schemas/ stay the single description of the run's data, and this module
checks data against them. Supported keywords: type, enum, const, pattern,
minimum, maximum, minItems, uniqueItems, items, required, properties,
additionalProperties (false), $ref to a sibling schema file, and if/then.
Annotations (title, description, default, format, $schema, $id) are ignored.
"""
import json
import os
import re

__all__ = ["validate", "load_schema", "SCHEMA_DIR"]

SCHEMA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets", "schemas")
)

_CACHE = {}


def load_schema(name):
    """Load a schema from assets/schemas/ by file name."""
    if name not in _CACHE:
        with open(os.path.join(SCHEMA_DIR, name), "r", encoding="utf-8") as handle:
            _CACHE[name] = json.load(handle)
    return _CACHE[name]


def _type_ok(value, name):
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    return False


def _check(value, schema, path, errors):
    if "$ref" in schema:
        _check(value, load_schema(schema["$ref"]), path, errors)
        return

    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, name) for name in names):
            errors.append("%s: expected %s" % (path, " or ".join(names)))
            return

    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: %r is not one of %s" % (path, value, schema["enum"]))
    if "const" in schema and value != schema["const"]:
        errors.append("%s: must be %r" % (path, schema["const"]))

    if isinstance(value, str) and "pattern" in schema:
        if not re.search(schema["pattern"], value):
            errors.append("%s: %r does not match %s" % (path, value, schema["pattern"]))

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append("%s: %r is below the minimum %r" % (path, value, schema["minimum"]))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append("%s: %r is above the maximum %r" % (path, value, schema["maximum"]))

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append("%s: needs at least %d item(s)" % (path, schema["minItems"]))
        if schema.get("uniqueItems"):
            seen = []
            for element in value:
                if element in seen:
                    errors.append("%s: items must be unique" % path)
                    break
                seen.append(element)
        if "items" in schema:
            for index, element in enumerate(value):
                _check(element, schema["items"], "%s[%d]" % (path, index), errors)

    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                errors.append("%s: missing %r" % (path, name))
        properties = schema.get("properties", {})
        for name, item in value.items():
            if name in properties:
                _check(item, properties[name], "%s.%s" % (path, name), errors)
            elif schema.get("additionalProperties") is False:
                errors.append("%s: unknown field %r" % (path, name))

    if "if" in schema and "then" in schema:
        probe = []
        _check(value, schema["if"], path, probe)
        if not probe:
            _check(value, schema["then"], path, errors)


def validate(value, schema, path="$"):
    """Return a list of problems; an empty list means the value is valid."""
    errors = []
    _check(value, schema, path, errors)
    return errors
