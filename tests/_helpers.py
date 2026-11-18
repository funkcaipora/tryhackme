"""Shared by the tests: where the scripts are, how to run one, and fake secrets.

Fake secrets are assembled at run time so that no secret-looking literal sits
in the repository.
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "security-scan")
SCRIPTS = os.path.join(SKILL, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)


def run_script(name, *arguments, **options):
    """Run one of the skill's scripts with the Python that runs the tests."""
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.update(options.get("env") or {})
    return subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, name)] + [str(argument) for argument in arguments],
        capture_output=True, text=True, env=environment, cwd=options.get("cwd"), input=options.get("stdin"),
    )


def fake_aws_key():
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def fake_github_token():
    return "ghp_" + "a1B2c3D4e5" * 3 + "F6g7H8"


def fake_password():
    return "Sup3r" + "Secret" + "Pw"


class TempDir(object):
    """A temporary folder that is removed afterwards."""

    def __enter__(self):
        self.path = os.path.realpath(tempfile.mkdtemp(prefix="security-scan-test-"))
        return self.path

    def __exit__(self, *_):
        shutil.rmtree(self.path, ignore_errors=True)


def write(path, text):
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        os.makedirs(folder)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
