#!/usr/bin/env python3
"""SpyderHash: identify potential hash encodings without cracking passwords.

This implementation is independently authored for the new project; no third-party
source files or code snippets are incorporated.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sys
from typing import Iterator

MAX_VALUE_LENGTH = 4096
MAX_BATCH_ITEMS = 1000
_HEX = re.compile(r"^[0-9a-fA-F]+$", re.ASCII)
_BCRYPT = re.compile(r"^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$", re.ASCII)
_PHC64 = r"[A-Za-z0-9+/]+={0,2}"
_ARGON2 = re.compile(
    rf"^\$(argon2(?:id|i|d))\$(?:v=(16|19)\$)?m=(\d+),t=(\d+),p=(\d+)\$({_PHC64})\$({_PHC64})$",
    re.ASCII,
)
_SCRYPT = re.compile(
    rf"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$({_PHC64})\$({_PHC64})$",
    re.ASCII,
)
_DJANGO_PBKDF2 = re.compile(
    r"^pbkdf2_(sha1|sha256|sha512)\$(\d+)\$([^$\s]+)\$([A-Za-z0-9+/]+={0,2})$",
    re.ASCII,
)

# A bare hexadecimal digest is inherently ambiguous: length is not proof of
# which algorithm produced it. These are plausible candidates, not diagnoses.
_HEX_CANDIDATES = {
    32: ("MD5", "MD4", "NTLM"),
    40: ("SHA-1", "RIPEMD-160"),
    56: ("SHA-224", "SHA3-224"),
    64: ("SHA-256", "SHA3-256", "BLAKE2s-256", "Keccak-256"),
    96: ("SHA-384", "SHA3-384"),
    128: ("SHA-512", "SHA3-512", "BLAKE2b-512"),
}


@dataclass(frozen=True)
class Inspection:
    """Result excluding the original input, to avoid exposing sensitive values."""

    kind: str
    confidence: str
    candidates: tuple[str, ...]
    explanation: str
    input_length: int

    def to_dict(self) -> dict:
        result = asdict(self)
        result["candidates"] = list(self.candidates)
        return result


def inspect_hash(value: str) -> Inspection:
    """Return format candidates based only on safely observed syntax.

    The function does not authenticate, decrypt, recover, or submit data.
    """
    if not isinstance(value, str):
        raise TypeError("hash value must be a string")
    value = value.strip()
    if not value:
        raise ValueError("hash value cannot be empty")
    if len(value) > MAX_VALUE_LENGTH:
        raise ValueError(f"hash value exceeds {MAX_VALUE_LENGTH} characters")

    if _BCRYPT.fullmatch(value):
        return Inspection(
            "modular-crypt", "high", ("bcrypt",),
            "Recognized bcrypt modular-crypt format, version and work factor. This does not validate the password.",
            len(value),
        )

    argon = _ARGON2.fullmatch(value)
    if argon and all(int(argon.group(i)) > 0 for i in (3, 4, 5)):
        return Inspection(
            "PHC-string", "high", (argon.group(1),),
            "Recognized an Argon2 PHC encoded string with numeric parameters, salt and output fields.",
            len(value),
        )

    scrypt = _SCRYPT.fullmatch(value)
    if scrypt and all(int(scrypt.group(i)) > 0 for i in (1, 2, 3)):
        return Inspection(
            "PHC-string", "high", ("scrypt",),
            "Recognized a scrypt PHC-style encoded string with parameters, salt and output fields.",
            len(value),
        )

    pbkdf2 = _DJANGO_PBKDF2.fullmatch(value)
    if pbkdf2 and int(pbkdf2.group(2)) > 0:
        return Inspection(
            "django-encoded", "high", (f"PBKDF2-HMAC-{pbkdf2.group(1).upper()}",),
            "Recognized Django's PBKDF2 encoded-hash field structure.",
            len(value),
        )

    if _HEX.fullmatch(value):
        candidates = _HEX_CANDIDATES.get(len(value))
        if candidates:
            return Inspection(
                "hex-digest", "possible", candidates,
                "The input is hexadecimal and matches a common digest length; the algorithm cannot be determined from length alone.",
                len(value),
            )
        return Inspection(
            "unrecognized-hex", "unknown", (),
            "Hexadecimal input, but its length does not match supported common digest sizes.",
            len(value),
        )

    return Inspection(
        "unrecognized", "unknown", (),
        "Does not match a supported encoding. Input may be malformed, encoded differently, or not a hash.",
        len(value),
    )


def _read_values(args: argparse.Namespace) -> Iterator[str]:
    if args.file is not None:
        with args.file.open("r", encoding="utf-8-sig") as stream:
            for index, line in enumerate(stream, 1):
                if index > MAX_BATCH_ITEMS:
                    raise ValueError(f"batch limit of {MAX_BATCH_ITEMS} lines exceeded")
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    yield stripped
    elif args.stdin:
        for index, line in enumerate(sys.stdin, 1):
            if index > MAX_BATCH_ITEMS:
                raise ValueError(f"batch limit of {MAX_BATCH_ITEMS} lines exceeded")
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield stripped
    else:
        assert args.value is not None
        yield args.value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect possible hash formats offline (identification only; no cracking)."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("value", nargs="?", help="single hash or encoded value")
    source.add_argument("--file", type=Path, help="UTF-8 text file with one value per line")
    source.add_argument("--stdin", action="store_true", help="read one value per line from standard input")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    args = parser.parse_args(argv)

    results: list[dict] = []
    try:
        for index, raw in enumerate(_read_values(args), 1):
            try:
                result = inspect_hash(raw).to_dict()
                result["entry"] = index
            except (TypeError, ValueError) as exc:
                result = {"entry": index, "kind": "invalid", "confidence": "unknown", "candidates": [], "explanation": str(exc), "input_length": len(raw)}
            results.append(result)
        if not results:
            raise ValueError("no input values found")
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(results[0] if args.value is not None else results, indent=2))
    else:
        for item in results:
            names = ", ".join(item["candidates"]) or "None"
            print(f"Entry {item['entry']} | {item['kind']} | confidence: {item['confidence']}")
            print(f"  Candidates: {names}")
            print(f"  Note: {item['explanation']}")
    return 0 if all(item["kind"] != "invalid" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
