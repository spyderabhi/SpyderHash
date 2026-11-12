# SpyderHash — Validation Record

## Windows functional test — 12 November 2026

Environment: Windows PowerShell 5.1, Python 3.14.7. This result is based on the terminal output supplied by the maintainer.

| Check | Result |
|---|---|
| Python version | `Python 3.14.7` |
| `py -3.14 spyderhash.py "5f4dcc3b5aa765d61d8327deb882cf99"` | Exit/output successful; `MD5, MD4, NTLM` as possible candidates |
| `py -3.14 -m unittest discover -s tests -v` | **32 tests passed**, `Ran 32 tests in 0.029s`, `OK` |
| Dependencies | Standard library only |

Sample classification is *not* proof of hash origin. The tool provides candidate formats and does not recover passwords.

## Additional previous checks

- Linux Python 3.13: 32/32 tests passed in the initial build.
- Python syntax and CLI demonstrations passed in the initial build environment.

## Release status

The Windows CLI demonstration and automated test suite passed. GitHub Actions CI will run after the repository is pushed. No real-world forensic accuracy benchmark or security audit has been performed.
