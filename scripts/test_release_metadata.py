#!/usr/bin/env python3
"""Adversarial tests for release and MSRV metadata validation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from verify_msrv import verify_msrv
from verify_release_tag import verify_release_tag


class MetadataChecksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)
        self.manifest = self.directory / "Cargo.toml"
        self.lockfile = self.directory / "Cargo.lock"
        self.lockfile.write_text(
            'version = 4\n\n[[package]]\nname = "example"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write_manifest(self, version: str = "0.2.0", msrv: str = "1.86") -> None:
        self.manifest.write_text(
            f'[package]\nname = "example"\nversion = "{version}"\n'
            f'edition = "2021"\nrust-version = "{msrv}"\n',
            encoding="utf-8",
        )

    def test_exact_release_tag_is_accepted(self) -> None:
        self.write_manifest()
        verify_release_tag(self.manifest, "v0.2.0")

    def test_noncanonical_or_mismatched_release_tags_are_rejected(self) -> None:
        self.write_manifest()
        for tag in ("0.1.0", "v0.1", "v0.1.1", "v00.1.0", "v0.1.0-rc.1", " v0.1.0"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                verify_release_tag(self.manifest, tag)

    def test_prerelease_and_noncanonical_package_versions_are_rejected(self) -> None:
        for version in ("0.1.0-rc.1", "00.1.0", "0.1"):
            self.write_manifest(version=version)
            with self.subTest(version=version), self.assertRaises(ValueError):
                verify_release_tag(self.manifest, f"v{version}")

    def test_exact_msrv_and_lockfile_are_accepted(self) -> None:
        self.write_manifest()
        verify_msrv(self.manifest, self.lockfile, "1.86")

    def test_missing_mismatched_or_noncanonical_msrv_is_rejected(self) -> None:
        for msrv in ("1.85", "1.086", "1.86.0", "stable"):
            self.write_manifest(msrv=msrv)
            with self.subTest(msrv=msrv), self.assertRaises(ValueError):
                verify_msrv(self.manifest, self.lockfile, "1.86")

    def test_invalid_lockfile_is_rejected(self) -> None:
        self.write_manifest()
        self.lockfile.write_text("version = 3\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_msrv(self.manifest, self.lockfile, "1.86")


if __name__ == "__main__":
    unittest.main()
