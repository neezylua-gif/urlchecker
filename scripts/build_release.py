#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT.parent / "url_guard_bot_v1.2.1_ready.zip"
EXCLUDE_PARTS = {".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".git"}
EXCLUDE_NAMES = {".env"}


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return not (set(relative.parts) & EXCLUDE_PARTS or path.name in EXCLUDE_NAMES)


def main() -> None:
    with zipfile.ZipFile(
        OUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in sorted(ROOT.rglob("*")):
            if path.is_file() and included(path):
                archive.write(path, Path(ROOT.name) / path.relative_to(ROOT))
    digest = hashlib.sha256(OUT.read_bytes()).hexdigest()
    sha_file = OUT.with_suffix(OUT.suffix + ".sha256")
    sha_file.write_text(f"{digest}  {OUT.name}\n", encoding="ascii")
    print(OUT)
    print(sha_file)


if __name__ == "__main__":
    main()
