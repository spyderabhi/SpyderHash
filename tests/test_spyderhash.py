"""Offline tests for SpyderHash using only the Python standard library."""
import contextlib
import io
import json
import tempfile
from pathlib import Path
import unittest

from spyderhash import inspect_hash, main


class Digests(unittest.TestCase):
    def test_md5_has_multiple_candidates(self):
        item = inspect_hash("5f4dcc3b5aa765d61d8327deb882cf99")
        self.assertEqual(item.kind, "hex-digest")
        self.assertEqual(item.confidence, "possible")
        self.assertIn("MD5", item.candidates)
        self.assertIn("NTLM", item.candidates)

    def test_sha1(self):
        self.assertIn("SHA-1", inspect_hash("a" * 40).candidates)

    def test_sha224(self):
        self.assertIn("SHA-224", inspect_hash("b" * 56).candidates)

    def test_sha256_is_ambiguous(self):
        item = inspect_hash("a" * 64)
        self.assertIn("SHA-256", item.candidates)
        self.assertIn("SHA3-256", item.candidates)
        self.assertEqual(item.confidence, "possible")

    def test_sha384(self):
        self.assertIn("SHA-384", inspect_hash("C" * 96).candidates)

    def test_sha512(self):
        self.assertIn("SHA-512", inspect_hash("f" * 128).candidates)

    def test_hex_other_length(self):
        self.assertEqual(inspect_hash("abc123").kind, "unrecognized-hex")

    def test_non_hex(self):
        self.assertEqual(inspect_hash("Not a hash!").kind, "unrecognized")

    def test_trim_spaces(self):
        self.assertEqual(inspect_hash("  " + "c" * 40 + "  ").input_length, 40)

    def test_zero_length(self):
        with self.assertRaises(ValueError):
            inspect_hash("  ")

    def test_too_long(self):
        with self.assertRaises(ValueError):
            inspect_hash("x" * 4097)

    def test_type_error(self):
        with self.assertRaises(TypeError):
            inspect_hash(None)


class PasswordHashFormats(unittest.TestCase):
    def test_bcrypt_2b(self):
        value = "$2b$12$" + "a" * 53
        self.assertEqual(inspect_hash(value).candidates, ("bcrypt",))

    def test_bcrypt_2a(self):
        self.assertEqual(inspect_hash("$2a$04$" + "a" * 53).kind, "modular-crypt")

    def test_bcrypt_2y(self):
        self.assertEqual(inspect_hash("$2y$31$" + "a" * 53).kind, "modular-crypt")

    def test_reject_invalid_bcrypt_cost(self):
        self.assertEqual(inspect_hash("$2b$99$" + "a" * 53).kind, "unrecognized")

    def test_reject_short_bcrypt(self):
        self.assertEqual(inspect_hash("$2b$12$abc").kind, "unrecognized")

    def test_argon2id(self):
        value = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
        self.assertEqual(inspect_hash(value).candidates, ("argon2id",))

    def test_argon2i(self):
        value = "$argon2i$v=16$m=1024,t=2,p=1$c2FsdA$aGFzaA"
        self.assertEqual(inspect_hash(value).candidates, ("argon2i",))

    def test_argon2d(self):
        value = "$argon2d$m=1024,t=2,p=1$c2FsdA$aGFzaA"
        self.assertEqual(inspect_hash(value).candidates, ("argon2d",))

    def test_reject_argon2_zero_iterations(self):
        value = "$argon2id$v=19$m=65536,t=0,p=4$c2FsdA$aGFzaA"
        self.assertEqual(inspect_hash(value).kind, "unrecognized")

    def test_scrypt(self):
        value = "$scrypt$ln=14,r=8,p=1$c2FsdA$aGFzaA"
        self.assertEqual(inspect_hash(value).candidates, ("scrypt",))

    def test_django_sha256(self):
        value = "pbkdf2_sha256$720000$NaCl$YWJjZA=="
        self.assertEqual(inspect_hash(value).candidates, ("PBKDF2-HMAC-SHA256",))

    def test_django_sha512(self):
        self.assertEqual(inspect_hash("pbkdf2_sha512$1000$salt$YWJjZA==").kind, "django-encoded")

    def test_django_reject_zero_iterations(self):
        self.assertEqual(inspect_hash("pbkdf2_sha1$0$salt$YWJjZA==").kind, "unrecognized")


class CLI(unittest.TestCase):
    def _run(self, argv):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            status = main(argv)
        return status, stream.getvalue()

    def test_single_text(self):
        status, output = self._run(["a" * 32])
        self.assertEqual(status, 0)
        self.assertIn("MD5", output)

    def test_single_json(self):
        status, output = self._run(["a" * 64, "--format", "json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output)["confidence"], "possible")
        self.assertNotIn("a" * 64, output)

    def test_batch_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "hashes.txt"
            path.write_text("# comment\n" + "a" * 32 + "\n" + "b" * 40 + "\n", encoding="utf-8")
            status, output = self._run(["--file", str(path), "--format", "json"])
            self.assertEqual(status, 0)
            items = json.loads(output)
            self.assertEqual(len(items), 2)
            self.assertEqual(items[0]["kind"], "hex-digest")

    def test_invalid_batch_item(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "hashes.txt"
            path.write_text(("x" * 4100) + "\n", encoding="utf-8")
            status, output = self._run(["--file", str(path), "--format", "json"])
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(output)[0]["kind"], "invalid")

    def test_missing_file(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = main(["--file", "/unlikely/to/exist/hashes.txt"])
        self.assertEqual(status, 2)

    def test_only_input_length_leaks(self):
        item = inspect_hash("secret-example-token")
        self.assertNotIn("secret-example-token", json.dumps(item.to_dict()))

    def test_dict_serialization(self):
        item = inspect_hash("b" * 32)
        self.assertIsInstance(item.to_dict()["candidates"], list)


if __name__ == "__main__":
    unittest.main()
