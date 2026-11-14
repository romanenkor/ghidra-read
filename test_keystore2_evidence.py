import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "ghidra-read/evidence"
VARIANTS = ((14, 1), (14, 3), (15, 4), (16, 5), (17, 6))
METHODS = ("readFromParcel", "writeToParcel")


def binary_path(android, version):
    name = f"android.system.keystore2-V{version}-ndk.so"
    return ROOT / f"images/{android}/system/system/lib64" / name


def evidence_path(android, version, method):
    return EVIDENCE / f"keystore2-keydescriptor/android-{android}-v{version}/{method}.json"


class AndroidEvidenceTests(unittest.TestCase):
    """Check saved Keystore2 method and lifecycle evidence against the local firmware."""

    def test_saved_keydescriptor_evidence_matches_local_elfs(self):
        for android, version in VARIANTS:
            binary = binary_path(android, version)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            for method in METHODS:
                with self.subTest(android=android, version=version, method=method):
                    report = json.loads(evidence_path(android, version, method).read_text())
                    self.assertEqual(report["program"]["sha256"], digest)
                    self.assertTrue(report["program"]["language_id"].startswith("AARCH64:LE:64:"))
                    self.assertEqual(report["status"], "ok")
                    self.assertEqual(report["function"]["name"], method)
                    self.assertTrue(report["sections"]["assembly"]["data"])
                    self.assertTrue(report["sections"]["decompile"]["data"])

    def test_lifecycle_inventory_covers_every_android_version(self):
        inventory = json.loads((EVIDENCE / "keystore2-operation-map.json").read_text())
        rows = inventory["firmware_libraries"]
        self.assertEqual([(row["android"], row["ndk_version"]) for row in rows], list(VARIANTS))
        for row in rows:
            binary = binary_path(row["android"], row["ndk_version"])
            self.assertEqual(row["sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            methods = row["exported_proxy_methods"]
            self.assertIn("createOperation", methods["IKeystoreSecurityLevel"])
            self.assertLessEqual({"update", "finish", "abort"}, set(methods["IKeystoreOperation"]))

    @unittest.skipUnless(os.environ.get("KEYSTORE_LIVE_GHIDRA") == "1", "optional headless check")
    def test_live_ghidra_confirms_saved_method_identity(self):
        runner = ROOT / "ghidra-read/scripts/read_binary.py"
        with tempfile.TemporaryDirectory(prefix="keystore-evidence-test-") as temp:
            def inspect(case):
                android, version, method = case
                saved = json.loads(evidence_path(android, version, method).read_text())
                output = Path(temp) / f"{android}-{version}-{method}.json"
                result = subprocess.run(
                    [sys.executable, runner, "inspect", binary_path(android, version),
                     "--symbol", saved["selector"]["value"], "--output", output],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                actual = json.loads(output.read_text())
                self.assertEqual(actual["program"]["sha256"], saved["program"]["sha256"])
                self.assertEqual(actual["function"]["entry_va"], saved["function"]["entry_va"])
                self.assertEqual(actual["function"]["name"], method)
                self.assertEqual(actual["sections"]["assembly"]["data"],
                                 saved["sections"]["assembly"]["data"])

            cases = [(a, v, method) for a, v in VARIANTS for method in METHODS]
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(inspect, cases))


if __name__ == "__main__":
    unittest.main()
