
# 🔐 SpyderHash

### Python-Based Hash Format Identification & Analysis Tool

**Developed by Abhinav Saini | Cybersecurity & Digital Forensics**

---

## 📌 Overview

**SpyderHash** is a Python-based cybersecurity utility designed to identify potential cryptographic hash formats through structural and pattern-based analysis.

The tool examines hash characteristics, including hexadecimal length, recognizable prefixes, and encoding structures, to determine possible hashing algorithms.

Built for cybersecurity research, digital forensics, and security analysis, SpyderHash operates offline without requiring external services or third-party Python packages.

---

## 🚀 What It Does

SpyderHash analyzes hash-like strings and identifies potential formats using predefined structural patterns.

### Core Capabilities

- **Hash Format Identification:** Identifies possible algorithms based on hexadecimal length and structure.
- **Password Hash Recognition:** Recognizes supported bcrypt, Argon2, scrypt, and Django PBKDF2 encodings.
- **Multiple Algorithm Detection:** Returns possible candidates when different algorithms share similar characteristics.
- **Confidence Classification:** Distinguishes high-confidence format recognition from ambiguous hash identification.
- **Batch Processing:** Analyzes multiple hash values from a text file.
- **JSON Output:** Provides structured results for further processing.
- **Offline Execution:** Operates without internet connectivity.
- **Input Privacy:** Does not display the complete supplied hash in normal results.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| Regular Expressions | Hash pattern recognition |
| Argparse | Command-line interface |
| JSON | Structured output |
| Unittest | Automated testing |
| GitHub Actions | Continuous integration |

The application uses Python's standard library without additional runtime dependencies.

---

## 🔍 Supported Hash Formats

### Hexadecimal Digest Candidates

| Hash Length | Possible Algorithms |
|---|---|
| 32 characters | MD5, MD4, NTLM |
| 40 characters | SHA-1, RIPEMD-160 |
| 56 characters | SHA-224, SHA3-224 |
| 64 characters | SHA-256, SHA3-256, BLAKE2s-256, Keccak-256 |
| 96 characters | SHA-384, SHA3-384 |
| 128 characters | SHA-512, SHA3-512, BLAKE2b-512 |

### Structured Password Hash Formats

- bcrypt
- Argon2id
- Argon2i
- Argon2d
- scrypt PHC-style encoding
- Django PBKDF2-HMAC-SHA1
- Django PBKDF2-HMAC-SHA256
- Django PBKDF2-HMAC-SHA512

**Note:** Hash length alone cannot reliably establish which algorithm generated a value. SpyderHash reports possible candidates rather than claiming definitive identification.

---

## ⚙️ Installation & Setup

### Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- No external Python packages required

### Run on Windows PowerShell

Open PowerShell inside the project directory.

```powershell
py -3.14 spyderhash.py "5f4dcc3b5aa765d61d8327deb882cf99"
```

### Run on Linux / macOS

```bash
python3 spyderhash.py "5f4dcc3b5aa765d61d8327deb882cf99"
```

---

## 💻 Example Execution

### Input

```text
5f4dcc3b5aa765d61d8327deb882cf99
```

### Output

```text
Entry 1 | hex-digest | confidence: possible
  Candidates: MD5, MD4, NTLM
  Note: The input is hexadecimal and matches a common digest length; the algorithm cannot be determined from length alone.
```

The result identifies potential algorithms without attempting to crack or reverse the hash.

---

## 📂 Batch Hash Analysis

SpyderHash supports processing multiple hash values from a file.

```powershell
py -3.14 spyderhash.py --file examples/sample_hashes.txt
```

### JSON Output

```powershell
py -3.14 spyderhash.py --file examples/sample_hashes.txt --format json
```

### Standard Input

```bash
python3 spyderhash.py --stdin
```

Input limitations:

- Maximum 4,096 characters per hash value.
- Maximum 1,000 input lines per batch.
- Blank lines and comment lines are ignored.

---

## 🧪 Testing & Validation

SpyderHash has undergone automated unit testing and functional command-line verification.

### Windows Testing Environment

| Parameter | Result |
|---|---|
| Operating System | Windows |
| Terminal | PowerShell 5.1 |
| Python Version | 3.14.7 |
| Automated Tests | 32 |
| Passed Tests | 32 |
| Failed Tests | 0 |
| CLI Execution | Passed |

### Run Automated Tests

```powershell
py -3.14 -m unittest discover -s tests -v
```

### Recorded Test Results

```text
----------------------------------------------------------------------
Ran 32 tests in 0.029s

OK
```

### Python Syntax Verification

```powershell
py -3.14 -m compileall -q spyderhash.py tests
```

### Test Coverage Areas

- Hexadecimal digest classification
- Password hash encoding recognition
- Invalid input handling
- JSON output generation
- Batch file processing
- Command-line execution
- Input length validation
- Format ambiguity handling

**Validation Status:** All 32 automated tests passed on Windows with Python 3.14.7.

These results confirm the tested functionality but do not constitute a complete security audit or real-world forensic accuracy assessment.

---

## 📁 Project Structure

```text
SpyderHash/
│
├── spyderhash.py
│
├── tests/
│   └── test_spyderhash.py
│
├── examples/
│   └── sample_hashes.txt
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── README.md
├── TEST_REPORT.md
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE
```

---

## 🔐 Security & Limitations

SpyderHash is designed for hash format identification and defensive security analysis.

The application:

- Does not crack or recover passwords.
- Does not decrypt cryptographic hashes.
- Does not transmit input to external servers.
- Does not guarantee identification of ambiguous hexadecimal digests.
- Does not verify that a password matches a stored hash.

Use the tool only in authorized cybersecurity environments.

---

## 🎯 Project Objectives

- Develop a lightweight Python utility for hash format analysis.
- Explore structural differences among common cryptographic hash representations.
- Improve reliability through input validation and automated testing.
- Provide readable and machine-processable output.
- Support cybersecurity education, investigation workflows, and security research.

---

## 👨‍💻 Developer

**Abhinav Saini**

Cybersecurity | Digital Forensics | Ethical Hacking | Security Research

**GitHub:** spyderabhi

**Email:** Abhinavsaini0905@gmail.com

---

## 📄 License

This project is distributed under the MIT License.

See the `LICENSE` file for details.

---

**SpyderHash — Identify the Format. Understand the Structure. Analyze with Confidence.**
