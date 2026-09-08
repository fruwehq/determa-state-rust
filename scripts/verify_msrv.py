#!/usr/bin/env python3
"""Validate the declared Rust MSRV and the checked-in Cargo lockfile."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path

MSRV_PATTERN = re.compile(r"1\.(0|[1-9][0-9]*)\Z")


def verify_msrv(manifest_path: Path, lockfile_path: Path, expected: str) -> None:
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = manifest.get("package")
    if not isinstance(package, dict):
        raise ValueError("Cargo.toml must contain [package]")

    declared = package.get("rust-version")
    if not isinstance(declared, str) or MSRV_PATTERN.fullmatch(declared) is None:
        raise ValueError("package.rust-version must use exact stable 1.MINOR syntax")
    if declared != expected:
        raise ValueError(f"declared MSRV {declared!r} does not equal expected {expected!r}")

    lockfile = tomllib.loads(lockfile_path.read_text(encoding="utf-8"))
    if lockfile.get("version") != 4:
        raise ValueError("Cargo.lock must use lockfile format 4")
    packages = lockfile.get("package")
    if not isinstance(packages, list) or not packages:
        raise ValueError("Cargo.lock must contain at least one package")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", required=True)
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    args = parser.parse_args()
    verify_msrv(args.manifest, args.lockfile, args.expected)


if __name__ == "__main__":
    main()
