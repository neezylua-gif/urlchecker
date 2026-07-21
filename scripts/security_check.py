#!/usr/bin/env python3
"""Run reproducible defensive checks for the project."""

from __future__ import annotations

import compileall
import json
import re
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "security_reports" / "security_check.json"


def run(command: list[str]) -> dict[str, object]:
    proc = subprocess.run(  # noqa: S603  # nosec B603
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-12000:],
        "stderr": proc.stderr[-12000:],
    }


def main() -> int:
    findings: list[str] = []
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "url_guard_bot").glob("*.py")
    )
    forbidden_patterns = {
        "dynamic_eval": r"\beval\s*\(",
        "dynamic_exec": r"\bexec\s*\(",
        "shell_true": r"shell\s*=\s*True",
        "unsafe_pickle": r"\bpickle\.",
        "ssl_disabled": r"ssl\s*=\s*False|verify_ssl\s*=\s*False",
    }
    for name, pattern in forbidden_patterns.items():
        if re.search(pattern, source):
            findings.append(name)

    checks: dict[str, object] = {
        "python": sys.version,
        "compileall": compileall.compile_dir(
            ROOT / "url_guard_bot", quiet=1, force=True
        ),
        "forbidden_patterns": findings,
        "env_file_present": (ROOT / ".env").exists(),
        "gitignore_blocks_env": ".env"
        in (ROOT / ".gitignore").read_text(encoding="utf-8"),
        "docker_hardening": {
            "read_only": "read_only: true" in (ROOT / "docker-compose.yml").read_text(),
            "cap_drop_all": "- ALL" in (ROOT / "docker-compose.yml").read_text(),
            "no_new_privileges": "no-new-privileges:true"
            in (ROOT / "docker-compose.yml").read_text(),
            "non_root_user": "USER app" in (ROOT / "Dockerfile").read_text(),
        },
    }

    checks["pytest"] = run([sys.executable, "-m", "pytest", "-q"])
    checks["ruff"] = run([sys.executable, "-m", "ruff", "check", "."])
    checks["ruff_format"] = run(
        [sys.executable, "-m", "ruff", "format", "--check", "."]
    )
    try:
        import bandit  # noqa: F401
    except ImportError:
        checks["bandit"] = {"skipped": "not installed"}
    else:
        checks["bandit"] = run(
            [sys.executable, "-m", "bandit", "-q", "-r", "url_guard_bot", "scripts"]
        )

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(checks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(REPORT)

    success = bool(checks["compileall"]) and not findings
    for name in ("pytest", "ruff", "ruff_format", "bandit"):
        item = checks.get(name, {})
        if isinstance(item, dict) and "returncode" in item and item["returncode"] != 0:
            success = False
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
