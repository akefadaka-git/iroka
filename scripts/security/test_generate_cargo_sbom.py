#!/usr/bin/env python3
"""Regression tests for Cargo-to-SPDX package and dependency reconciliation."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("generate_cargo_sbom.py")


class SbomGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.root_id = "path+file:///workspace/kernel#0.1.0"
        self.dep_id = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0"
        self.metadata = {
            "version": 1,
            "packages": [
                {
                    "id": self.root_id,
                    "name": "iroka-kernel",
                    "version": "0.1.0",
                    "source": None,
                    "license": "LicenseRef-Proprietary",
                },
                {
                    "id": self.dep_id,
                    "name": "serde",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "license": "MIT OR Apache-2.0",
                },
            ],
            "workspace_members": [self.root_id],
            "resolve": {
                "nodes": [
                    {"id": self.root_id, "deps": [{"pkg": self.dep_id}]},
                    {"id": self.dep_id, "deps": []},
                ]
            },
        }
        self.lock = """version = 4

[[package]]
name = "iroka-kernel"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"""
        self.metadata_path = self.root / "metadata.json"
        self.lock_path = self.root / "Cargo.lock"
        self.output_path = self.root / "sbom.json"
        self.write_inputs()

    def tearDown(self):
        self.temp.cleanup()

    def write_inputs(self):
        self.metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")
        self.lock_path.write_text(self.lock, encoding="utf-8")

    def run_generator(self):
        return subprocess.run(
            [
                sys.executable, str(SCRIPT),
                "--metadata", str(self.metadata_path),
                "--lockfile", str(self.lock_path),
                "--output", str(self.output_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_emits_all_locked_packages_and_resolved_edges(self):
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(self.output_path.read_text(encoding="utf-8"))
        self.assertEqual(document["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(document["packages"]), 2)
        self.assertEqual(
            sum(item["relationshipType"] == "DEPENDS_ON" for item in document["relationships"]),
            1,
        )
        self.assertEqual(
            sum(item["relationshipType"] == "DESCRIBES" for item in document["relationships"]),
            1,
        )
        self.assertEqual(len({item["SPDXID"] for item in document["packages"]}), 2)
        self.assertEqual(document["packages"][0]["licenseDeclared"], "NOASSERTION")

    def test_rejects_lockfile_package_missing_from_metadata(self):
        self.lock += """
[[package]]
name = "orphan"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"""
        self.write_inputs()
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("package-set mismatch", result.stderr)

    def test_rejects_metadata_package_missing_from_lockfile(self):
        self.metadata["packages"].append({
            "id": "registry+https://github.com/rust-lang/crates.io-index#other@1.0.0",
            "name": "other",
            "version": "1.0.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "license": "MIT",
        })
        self.metadata["resolve"]["nodes"].append({
            "id": "registry+https://github.com/rust-lang/crates.io-index#other@1.0.0",
            "deps": [],
        })
        self.write_inputs()
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("package-set mismatch", result.stderr)

    def test_rejects_missing_resolved_graph(self):
        self.metadata["resolve"] = None
        self.write_inputs()
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resolved dependency graph", result.stderr)


if __name__ == "__main__":
    unittest.main()
