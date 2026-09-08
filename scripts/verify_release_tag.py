#!/usr/bin/env python3
"""Fail closed unless a stable release tag exactly matches Cargo package.version."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

VERSION_PATTERN = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)


def verify_release_tag(manifest_path: Path, tag: str) -> None:
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise ValueError("Cargo.toml must contain [package]")

    version = package.get("version")
    if not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("package.version must be an exact stable X.Y.Z version")
    if tag != f"v{version}":
        raise ValueError(f"release tag {tag!r} does not equal package version tag v{version}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    args = parser.parse_args()
    verify_release_tag(args.manifest, args.tag)


if __name__ == "__main__":
    main()
