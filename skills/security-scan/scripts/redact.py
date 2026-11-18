#!/usr/bin/env python3
"""Strip secret values from any output.

A filter. It finds secret values in text or JSON and replaces each with a
marker that keeps the type and a fingerprint:

    [redacted:<type>:<first 8 hex characters of the value's SHA-256>]

The fingerprint lets the same secret be recognised in two places (the same key
in a repository and in a pipeline) without revealing it.

Usage:
    some-command | redact.py > evidence/02/x.txt
    redact.py --in raw.json --out evidence/02/x.json
    redact.py --check <file-or-dir> [...]     exit 1 if anything secret-like remains
    redact.py --self-test

What it recognises:
  - provider key and token formats (cloud, source control, chat, payment, AI)
  - private key blocks and JSON Web Tokens
  - passwords inside connection URLs, authorization headers, signed URL signatures
  - values assigned to names that look like a secret (password, token, api_key...)

Safety: the original value is never written anywhere, including logs and error
messages. In --check mode only the location and the type are reported.
"""
import argparse
import hashlib
import json
import os
import re
import sys

MARKER = re.compile(r"\[redacted:[a-z0-9\-]+:[0-9a-f]{8}\]")

# (type, pattern, group that holds the secret). Order matters: specific formats
# first, the generic name-based rule last.
_SPECIFIC = [
    ("private-key", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", 0),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", 0),
    ("aws-secret-access-key", r"(?i)aws_?secret_?access_?key[\"'\s:=]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", 0),
    ("github-token", r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b", 0),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", 0),
    ("slack-token", r"\bxox[abeprs]-[A-Za-z0-9\-]{10,}\b", 0),
    ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,}", 0),
    ("stripe-key", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b", 0),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),
    ("google-oauth-token", r"\bya29\.[A-Za-z0-9_\-]{20,}", 0),
    ("google-oauth-secret", r"\bGOCSPX-[A-Za-z0-9_\-]{20,}", 0),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", 0),
    ("openai-key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}", 0),
    ("huggingface-token", r"\bhf_[A-Za-z0-9]{30,}\b", 0),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b", 0),
    ("pypi-token", r"\bpypi-[A-Za-z0-9_\-]{40,}", 0),
    ("sendgrid-key", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", 0),
    ("digitalocean-token", r"\bdo[por]_v1_[a-f0-9]{64}\b", 0),
    ("shopify-token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", 0),
    ("telegram-bot-token", r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b", 0),
    ("azure-client-secret", r"\b[A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{31,34}\b", 0),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", 0),
    ("url-password", r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@\"']+:([^@\s/\"']{3,})@", 1),
    ("authorization-header", r"(?i)\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=\-]{12,})", 1),
    ("signed-url-signature", r"(?i)[?&](?:sig|signature|x-amz-signature|x-goog-signature)=([A-Za-z0-9%+/=_\-]{16,})", 1),
    ("connection-string-key", r"(?i)\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)=([A-Za-z0-9+/=%&_\-]{16,})", 1),
]
SPECIFIC = [(kind, re.compile(pattern, re.S), group) for kind, pattern, group in _SPECIFIC]

_SECRET_WORDS = (
    r"password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|client[_\-]?secret|credential|passphrase|master[_\-]?key"
)
SECRET_NAME = re.compile(r"(?i)(?:%s)" % _SECRET_WORDS)
ASSIGNMENT = re.compile(
    r"(?i)(?P<key>[A-Za-z0-9_.\-]*(?:%s)[A-Za-z0-9_.\-]*)"
    r"(?P<sep>[\"']?\s*[:=]\s*[\"']?)"
    r"(?P<value>[^\s\"',;}{]{6,})" % _SECRET_WORDS
)

# A name that contains a secret word but ends like this describes the secret
# instead of holding it: password_policy, token_type, SecretName, AccessKeyId.
_DESCRIPTIVE_ENDINGS = (
    "name", "names", "arn", "id", "ids", "type", "types", "url", "uri", "endpoint",
    "path", "file", "version", "versions", "count", "length", "ttl", "policy",
    "enabled", "required", "expiry", "expires", "expiresin", "expiration", "scope",
    "scopes", "algorithm", "header", "field", "hint", "format", "prefix", "suffix",
    "status", "rotation", "lastused", "lastrotated", "lastchanged", "created",
    "createdat", "updated", "updatedat", "date", "age", "days", "exists", "present",
    "configured", "requirements", "minlength", "maxlength", "complexity", "maxage",
    "reuseprevention", "resetrequired", "reset", "keyid", "metadata", "label", "labels",
    "description", "location", "provider", "source", "kind", "store", "manager", "ref",
)
_ALWAYS_SECRET_NAMES = {"secretid"}
_NOT_SECRET_VALUES = {
    "", "null", "none", "nil", "true", "false", "required", "optional", "enabled",
    "disabled", "hidden", "redacted", "masked", "changeme", "example", "undefined",
    "string", "securestring", "yes", "no", "unknown", "notset", "empty",
}


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def marker(kind, value):
    return "[redacted:%s:%s]" % (kind, fingerprint(value))


def _descriptive(name):
    flat = re.sub(r"[^a-z0-9]", "", name.lower())
    if flat in _ALWAYS_SECRET_NAMES:
        return False
    return any(flat.endswith(ending) for ending in _DESCRIPTIVE_ENDINGS)


def _reference_or_placeholder(value):
    """True for values that point at a secret or stand in for one."""
    if MARKER.search(value):
        return True
    stripped = value.strip("\"'`")
    if stripped.lower() in _NOT_SECRET_VALUES:
        return True
    # Source code, not a value: an identifier followed by a call or an index.
    if re.match(r"^[A-Za-z_][A-Za-z0-9_.]*[\(\[]", stripped):
        return True
    if re.match(r"^(\$\{?[A-Za-z_]|%[A-Za-z_]|\{\{|<[A-Za-z_ \-]+>|\(.*\)$|\[.*\]$)", stripped):
        return True
    if re.match(r"^(https?://|arn:|/|~/|\./|[A-Za-z]:\\)", stripped) and "@" not in stripped:
        return True
    if re.match(r"^[*xX.\-_#]+$", stripped):
        return True
    if re.match(r"^[0-9.,:\-]+$", stripped):
        return True
    return False


def _looks_secret_in_prose(value):
    """In free text, require some evidence beyond the name: a digit, or length."""
    stripped = value.strip("\"'`")
    return bool(re.search(r"[0-9]", stripped)) or len(stripped) >= 20


def redact_text(text, counts=None):
    """Return the text with every recognised secret replaced by a marker.

    Markers already in the text are left alone, so a second pass changes nothing.
    """
    if counts is None:
        counts = {}

    def note(kind):
        counts[kind] = counts.get(kind, 0) + 1

    # Each rule runs only on the stretches that are not markers yet, so a rule
    # can never match inside a marker written by an earlier rule or pass.
    for kind, pattern, group in SPECIFIC:
        def replace(match, kind=kind, group=group):
            secret = match.group(group)
            note(kind)
            if group == 0:
                return marker(kind, secret)
            start, end = match.span(group)
            offset = match.start(0)
            whole = match.group(0)
            return whole[: start - offset] + marker(kind, secret) + whole[end - offset:]

        text = _outside_markers(text, lambda piece, pattern=pattern, replace=replace: pattern.sub(replace, piece))

    def replace_assignment(match):
        key = match.group("key")
        value = match.group("value")
        if _descriptive(key) or _reference_or_placeholder(value) or not _looks_secret_in_prose(value):
            return match.group(0)
        note("named-secret")
        return match.group("key") + match.group("sep") + marker("named-secret", value)

    return _outside_markers(text, lambda piece: ASSIGNMENT.sub(replace_assignment, piece))


def _outside_markers(text, transform):
    """Apply `transform` to the stretches of text that are not already markers."""
    pieces = re.split("(%s)" % MARKER.pattern, text)
    for index in range(0, len(pieces), 2):
        if pieces[index]:
            pieces[index] = transform(pieces[index])
    return "".join(pieces)


def redact_json(value, counts=None, key=None):
    """Walk parsed JSON. Redact string values under secret-looking keys, then scan every string."""
    if counts is None:
        counts = {}
    if isinstance(value, dict):
        return {name: redact_json(item, counts, key=name) for name, item in value.items()}
    if isinstance(value, list):
        return [redact_json(item, counts, key=key) for item in value]
    if isinstance(value, str):
        cleaned = redact_text(value, counts)
        named = (
            key is not None
            and SECRET_NAME.search(str(key))
            and not _descriptive(str(key))
            and not _reference_or_placeholder(cleaned)
            and not MARKER.fullmatch(cleaned)
        )
        if named:
            counts["named-secret"] = counts.get("named-secret", 0) + 1
            return marker("named-secret", value)
        return cleaned
    return value


def redact(text, counts=None):
    """Redact text. JSON is walked structurally and re-serialised."""
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if parsed is not None:
            return json.dumps(redact_json(parsed, counts), indent=2, ensure_ascii=False) + "\n"
    return redact_text(text, counts)


def scan(text):
    """Find what redact() would change. Returns (line, type) pairs, never values."""
    # Like redact_text, look only at the stretches that are not markers already.
    hits = []
    offset = 0
    for index, piece in enumerate(re.split("(%s)" % MARKER.pattern, text)):
        if index % 2 == 0 and piece:
            for kind, pattern, group in SPECIFIC:
                for match in pattern.finditer(piece):
                    hits.append((text.count("\n", 0, offset + match.start(group)) + 1, kind))
            for match in ASSIGNMENT.finditer(piece):
                value = match.group("value")
                if _descriptive(match.group("key")) or _reference_or_placeholder(value):
                    continue
                if not _looks_secret_in_prose(value):
                    continue
                hits.append((text.count("\n", 0, offset + match.start("value")) + 1, "named-secret"))
        offset += len(piece)
    return sorted(set(hits))


def _files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
                for name in sorted(names):
                    yield os.path.join(root, name)
        else:
            yield path


def check(paths, out=sys.stdout):
    """Report secret-like content in files. Returns the number of hits."""
    total = 0
    for path in _files(paths):
        try:
            if os.path.getsize(path) > 5 * 1024 * 1024:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        if "\x00" in text[:2048]:
            continue
        for line, kind in scan(text):
            total += 1
            out.write("%s:%d: %s\n" % (path, line, kind))
    return total


def self_test():
    """Built-in cases. Secrets are assembled at run time so none sits in the file."""
    fake_aws = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    fake_gh = "ghp_" + "a1B2c3D4e5" * 3 + "F6g7H8"
    fake_jwt = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0", "SflKxwRJSMeKKF2QT4fwpM"])
    fake_pem = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow" + "IBAAKCAQEA\n-----END RSA " + "PRIVATE KEY-----"
    cases = [
        ("aws key id", "key is %s here" % fake_aws, fake_aws),
        ("github token", "token %s" % fake_gh, fake_gh),
        ("jwt", "cookie=%s" % fake_jwt, fake_jwt),
        ("private key", fake_pem, "MIIEow"),
        ("url password", "postgres://app:" + "s3cr3t" + "Pw@db.internal:5432/x", "s3cr3tPw"),
        ("env assignment", "DB_PASSWORD=" + "Summer" + "2026!", "Summer2026!"),
        ("json field", json.dumps({"client_secret": "hunter" + "two"}), "huntertwo"),
        ("bearer", "Authorization: Bearer " + "abcDEF123456" + "ghiJKL", "abcDEF123456ghiJKL"),
    ]
    untouched = [
        "password_policy: required",
        "token_type: Bearer",
        '{"SecretName": "prod/db", "AccessKeyId_age_days": 412}',
        "DB_PASSWORD=${DB_PASSWORD}",
        "api_key_path: /etc/app/key",
        "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ]
    failures = []
    for name, text, secret in cases:
        cleaned = redact(text)
        if secret in cleaned:
            failures.append("not redacted: %s" % name)
        if not MARKER.search(cleaned):
            failures.append("no marker: %s" % name)
        if redact(cleaned) != cleaned:
            failures.append("not stable on a second pass: %s" % name)
        if scan(cleaned):
            failures.append("scan still flags the redacted text: %s" % name)
    for text in untouched:
        if redact_text(text) != text:
            failures.append("changed a non-secret: %r" % text)
    same = redact("a %s b" % fake_aws)
    again = redact("c %s d" % fake_aws)
    if MARKER.search(same).group(0) != MARKER.search(again).group(0):
        failures.append("the same secret gave two different fingerprints")
    return failures


def main(argv):
    parser = argparse.ArgumentParser(description="Strip secret values from text or JSON.")
    parser.add_argument("--in", dest="source", help="read from this file instead of stdin")
    parser.add_argument("--out", dest="target", help="write to this file instead of stdout")
    parser.add_argument("--check", nargs="+", metavar="PATH", help="report secret-like content; exit 1 if any")
    parser.add_argument("--self-test", action="store_true", help="run the built-in cases")
    args = parser.parse_args(argv)

    if args.self_test:
        failures = self_test()
        for failure in failures:
            print("FAIL " + failure)
        print("redact.py self-test: %s" % ("%d failure(s)" % len(failures) if failures else "ok"))
        return 1 if failures else 0

    if args.check:
        hits = check(args.check)
        if hits:
            sys.stderr.write("redact.py: %d secret-like value(s) found\n" % hits)
            return 1
        return 0

    if args.source:
        with open(args.source, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    else:
        text = sys.stdin.read()
    counts = {}
    cleaned = redact(text, counts)
    if args.target:
        with open(args.target, "w", encoding="utf-8") as handle:
            handle.write(cleaned)
    else:
        sys.stdout.write(cleaned)
    if counts:
        summary = ", ".join("%s x%d" % item for item in sorted(counts.items()))
        sys.stderr.write("redact.py: redacted %s\n" % summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
