#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import armory
import paths
from tests.helpers import Isolate


class TestArmory(unittest.TestCase):
    def test_seal_verify_checkout_and_wipe(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with Isolate(tmp):
                manifest = armory.seal_sources(actor="test")
                self.assertEqual(manifest["round_count"], len(armory._iter_source_files()))
                _f, h_key = armory.load_keys()
                self.assertTrue(armory.verify_signature(manifest, h_key))
                verified = armory.verify_armory()
                self.assertEqual(verified["round_count"], manifest["round_count"])
                dest = tmp / "checkout"
                written = armory.checkout(
                    ["ns-01", "lg-01"], dest, drill_id="test-1", actor="test"
                )
                self.assertEqual(len(written), 2)
                for path in written:
                    self.assertTrue(path.is_file())
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    source = next(paths.SOURCE_ROUNDS.rglob(path.name))
                    self.assertEqual(path.read_bytes(), source.read_bytes())
                armory.wipe_dir(dest)
                self.assertFalse(dest.exists())
                self.assertEqual(paths.key_dir().stat().st_mode & 0o777, 0o700)
                self.assertEqual(armory.armory_key_path().stat().st_mode & 0o777, 0o600)
                self.assertEqual(armory.hmac_key_path().stat().st_mode & 0o777, 0o600)

    def test_tampered_ciphertext_fails_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            with Isolate(Path(raw)):
                armory.seal_sources(actor="test")
                blob = armory.ciphertext_path("ci-01")
                data = bytearray(blob.read_bytes())
                data[-5] ^= 0xFF
                blob.write_bytes(bytes(data))
                with self.assertRaises(armory.ArmoryError) as ctx:
                    armory.verify_armory()
                self.assertRegex(str(ctx.exception), "integrity check failed|mismatch")

    def test_tampered_manifest_signature_fails(self):
        with tempfile.TemporaryDirectory() as raw:
            with Isolate(Path(raw)):
                armory.seal_sources(actor="test")
                path = armory.manifest_path()
                manifest = json.loads(path.read_text(encoding="utf-8"))
                manifest["rounds"][0]["sha256"] = "0" * 64
                path.write_text(json.dumps(manifest), encoding="utf-8")
                os.chmod(path, 0o600)
                with self.assertRaises(armory.ArmoryError) as ctx:
                    armory.verify_armory()
                self.assertIn("signature", str(ctx.exception).lower())

    def test_unknown_round_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with Isolate(tmp):
                armory.seal_sources(actor="test")
                with self.assertRaises(armory.ArmoryError) as ctx:
                    armory.checkout(["no-such-round"], tmp / "co", drill_id="x", actor="test")
                self.assertIn("Unknown round", str(ctx.exception))

    def test_sniff_refuses_scripts_and_elf(self):
        with tempfile.TemporaryDirectory() as raw:
            folder = Path(raw)
            script = folder / "evil.py"
            script.write_text("print('nope')\n", encoding="utf-8")
            self.assertTrue(armory.sniff_forbidden(script))
            sh = folder / "evil.sh"
            sh.write_text("#!/bin/sh\necho no\n", encoding="utf-8")
            self.assertTrue(armory.sniff_forbidden(sh))
            elf = folder / "payload.bin"
            elf.write_bytes(b"\x7fELF" + b"\x00" * 16)
            self.assertIn("ELF", armory.sniff_forbidden(elf) or "")
            eml = folder / "ok.eml"
            eml.write_text("From: a@example.com\n\nHi\n", encoding="utf-8")
            self.assertIsNone(armory.sniff_forbidden(eml))

    def test_audit_log_written(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with Isolate(tmp):
                armory.seal_sources(actor="test")
                armory.checkout(["sf-02"], tmp / "co", drill_id="audit-1", actor="test")
                text = paths.armory_audit_path().read_text(encoding="utf-8")
                self.assertIn("seal", text)
                self.assertIn("checkout", text)
                self.assertIn("audit-1", text)


if __name__ == "__main__":
    unittest.main()
