# 🔐 Password Strength Analyzer & Cryptography Toolkit

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/tests-31%20passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-OWASP%20PBKDF2--HMAC--SHA256-blueviolet.svg)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> Developed for the **Thiranex Internship Program**.  
> A cybersecurity tool and educational suite designed to evaluate password quality, compute Shannon entropy, simulate realistic brute-force attacks across attacker tiers, enforce zero-plaintext password reuse prevention, and generate high-entropy passwords and passphrases.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Security & Cryptography Highlights](#-security--cryptography-highlights)
- [Architecture & Project Structure](#-architecture--project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation (Windows PowerShell)](#installation-windows-powershell)
  - [Installation (macOS / Linux)](#installation-macos--linux)
- [Running the Application](#-running-the-application)
  - [Web Interface (Flask)](#web-interface-flask)
  - [Command-Line Interface (CLI)](#command-line-interface-cli)
- [API Reference](#-api-reference)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [Design Decisions](#-design-decisions)
- [License & Acknowledgments](#-license--acknowledgments)

---

## 🌟 Overview

Weak, predictable, and reused passwords remain one of the most exploited attack vectors in security breaches. The **Password Strength Analyzer** goes far beyond rudimentary character-counting checkers. It provides:

1. **Deterministic Multi-Factor Scoring (0–100)**: Evaluates length, 4-class complexity (uppercase, lowercase, digits, symbols), character set pool sizes, and dictionary occurrences.
2. **Shannon Entropy Estimation**: Computes empirical information entropy (in bits) with statistical non-uniformity penalties.
3. **Multi-Tier Brute-Force Resistance Modeling**: Calculates estimated cracking time across realistic threat models:
   - **Online throttled attacks** (1,000 guesses/sec)
   - **Fast offline single GPU** (1 billion guesses/sec)
   - **Distributed GPU cluster** (1 trillion guesses/sec)
4. **Zero-Plaintext Password History (Reuse Prevention)**: Persists password history using **PBKDF2-HMAC-SHA256** with **600,000 iterations** (OWASP recommendation) and unique 128-bit cryptographic salts. Plaintext passwords are never saved.
5. **CSPRNG Generation**: Employs Python's `secrets` module (cryptographically secure pseudo-random number generator) to generate 12–64 character passwords and multi-word Diceware-style passphrases.

---

## 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **Real-Time Analysis** | Instant evaluation of length, character variety, dictionary match, and character repetition. |
| **Shannon Entropy** | Calculates bits of entropy ($H = -\sum p_i \log_2 p_i$) and penalizes keyboard patterns (`qwerty`, `123456`) and runs (`aaaa`). |
| **Brute-Force Benchmarking** | Directly compares cracking difficulty against offline hash-cracking clusters. |
| **Reuse Prevention** | SQLite-backed hashed history blocks employees/users from cycling previously compromised passwords. |
| **Crypto Showcase** | Side-by-side comparison of SHA-256, SHA-512, MD5, HMAC-SHA-256, and PBKDF2 with salt & iteration parameters. |
| **Dual Interfaces** | Web interface (clean HTML5/CSS3/JavaScript) and a CLI (`cli.py`) for terminal workflows. |

---

## 🔒 Security & Cryptography Highlights

### 1. OWASP-Compliant PBKDF2-HMAC-SHA256
Fast hashing algorithms (e.g., MD5, raw SHA-256) can be computed billions of times per second by modern GPUs, making them dangerous for password storage. This project implements **PBKDF2-HMAC-SHA256** with **600,000 iterations** and a fresh 16-byte random salt per entry:
$$K = \text{PBKDF2}(\text{HMAC-SHA256}, \text{password}, \text{salt}, 600\,000, 32)$$
This enforces a computational cost that makes offline dictionary attacks computationally prohibitive.

### 2. Timing-Attack Safe Comparison
Password hashes in the database are validated using `hmac.compare_digest(candidate, digest)`, avoiding standard short-circuit string comparison vulnerabilities.

### 3. Cryptographically Secure Randomness
All password and passphrase generation utilizes `secrets.choice` and `secrets.SystemRandom` backed by OS-level entropy (`/dev/urandom` or `CryptGenRandom`), avoiding predictable PRNG seeds from `random`.

---

## 📂 Architecture & Project Structure

```text
thiranex-INTERNSHIP/
├── app.py                   # Flask web server and REST API endpoints
├── cli.py                   # Interactive and scriptable command-line interface
├── database.py              # SQLite storage with PBKDF2 hashing and reuse checks
├── password_analyzer.py     # Pure-Python core logic (entropy, scoring, generation)
├── requirements.txt         # Minimal dependency definition (Flask >= 2.0)
├── test_analyzer.py         # Unit tests for core password analyzer logic (20 tests)
├── test_app.py              # Unit tests for Flask API and endpoints (11 tests)
├── README.md                # Comprehensive documentation
├── static/
│   ├── app.js               # Frontend JavaScript (DOM updates, API fetch, UI states)
│   └── style.css            # Responsive, modern styling and score indicators
└── templates/
    └── index.html           # Accessible semantic HTML template
```

---

## 🛠️ Getting Started

### Prerequisites

- **Python 3.10+** (Python 3.10, 3.11, or 3.12 recommended)
- `pip` (Python package manager)
- Git

### Installation (Windows PowerShell)

```powershell
# 1. Clone repository
git clone https://github.com/rabigupta-123/thiranex-INTERNSHIP.git
cd thiranex-INTERNSHIP

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

### Installation (macOS / Linux)

```bash
# 1. Clone repository
git clone https://github.com/rabigupta-123/thiranex-INTERNSHIP.git
cd thiranex-INTERNSHIP

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 💻 Running the Application

### Web Interface (Flask)

Start the local server:
```powershell
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

#### Using the Web App:
1. **Analyze**: Enter any password and click **Analyze** to inspect score, criteria breakdown, entropy, and crack time scenarios.
2. **Save to History**: Click **Save to history** to store a PBKDF2 hash of the password. Typing it again will trigger a reuse warning.
3. **Generate**: Choose a length (12–64 characters) and click **Generate** to get a random high-entropy password and passphrase.
4. **Hash Preview**: Click **Show hashes of current input** to inspect SHA-256, SHA-512, PBKDF2, and HMAC output.

---

### Command-Line Interface (CLI)

The CLI supports both direct command-line arguments and an interactive masked prompt:

#### 1. Interactive Mode (Hidden Input)
```powershell
python cli.py
```
```text
Enter a password to analyse (hidden input): 

============================================================
PASSWORD STRENGTH REPORT
============================================================
Password:         K7$mZx9#QpWl2@DfR-Xx9!
Strength:         Very Strong (95/100)
Entropy:          102.4 bits
Est. crack time:  centuries
Brute-force scenarios:
  - Online attack (10^3 guesses/sec): centuries
  - Fast offline: 1 billion guesses/sec: centuries
  - GPU cluster: 1 trillion guesses/sec: centuries
Checks:
  - [Length] PASS (25/25) Good length (22 characters).
  - [Complexity] PASS (40/40) +1 points for each character type (total 4 types)
  - [Uniqueness] PASS (25/25) No known common-password matches found.
Suggestions:
  - Great password! Consider using a passphrase of several random words.

Strong alternative: j9@XpL#4vWm1$Qz8K2&B7!DfR4*N9+Ty
Passphrase idea:    Cobalt-Signal-Velvet-Comet-Harbor-Pixel-Saffron482
```

#### 2. Direct Argument Mode
```powershell
python cli.py "SuperSecret123!"
```

---

## 📡 API Reference

The Flask application exposes clean, JSON-based REST endpoints:

### `POST /api/analyze`
Evaluates password strength and checks database reuse history.

**Request Body:**
```json
{
  "password": "CorrectHorse=Battery-Staple1!"
}
```

**Response (200 OK):**
```json
{
  "score": 92,
  "label": "Very Strong",
  "entropy": 88.5,
  "crack_time": "centuries",
  "reused": false,
  "history_count": 3,
  "checks": [
    {
      "name": "Length",
      "score": 25,
      "max": 25,
      "passed": true,
      "message": "Good length (29 characters)."
    },
    {
      "name": "Complexity",
      "score": 40,
      "max": 40,
      "passed": true,
      "message": "+1 points for each character type (total 4 types)"
    },
    {
      "name": "Uniqueness",
      "score": 25,
      "max": 25,
      "passed": true,
      "message": "No known common-password matches found."
    }
  ],
  "suggestions": [
    "Great password! Consider using a passphrase of several random words."
  ],
  "brute_force": {
    "recommended": true,
    "minimum_recommended_bits": 60,
    "scenarios": {
      "Online attack (10^3 guesses/sec)": "centuries",
      "Fast offline: 1 billion guesses/sec": "centuries",
      "GPU cluster: 1 trillion guesses/sec": "centuries"
    }
  }
}
```

---

### `POST /api/save`
Hashes and records a password into SQLite history using PBKDF2.

**Request Body:**
```json
{
  "password": "MyNewPassword123!"
}
```

**Response (200 OK):**
```json
{
  "status": "saved",
  "history_count": 4
}
```

---

### `POST /api/generate`
Generates cryptographically secure passwords and passphrases.

**Request Body:**
```json
{
  "length": 32
}
```

**Response (200 OK):**
```json
{
  "strong": "k8$Mv2#Lp9!Qw4@Zx7^Tc1&Bn5*Yd6%F",
  "passphrase": "Acorn-Falcon-Granite-Meadow-Saffron-Willow-Zephyr342",
  "entropy_estimate": 208.8
}
```

---

### `POST /api/hash`
Generates one-way hashes for cryptographic education.

**Request Body:**
```json
{
  "password": "DemoPassword123"
}
```

**Response (200 OK):**
```json
{
  "sha256": "4b98c3e806124...",
  "sha512": "87f2a1b9c...",
  "md5": "098f6bcd4621d373cade4e832627b4f6",
  "hmac_sha256": "a3b98...",
  "pbkdf2_600k": "7c4e2...",
  "iterations": 600000,
  "salt_used": "demo-salt"
}
```

---

### `GET /api/stats`
Returns total number of recorded password hashes.

**Response (200 OK):**
```json
{
  "history_count": 4
}
```

---

## 🧪 Testing & Quality Assurance

The project comes with a comprehensive suite of **31 automated unit tests** covering edge cases, boundary inputs, security policies, and API routing.

### Run All Unit Tests:

```powershell
python -m unittest test_analyzer test_app -v
```

### Test Suite Summary:

```text
test_character_pool_sizes (test_analyzer.TestAnalyzer) ... ok
test_common_password_is_weak (test_analyzer.TestAnalyzer) ... ok
test_crack_time_estimates (test_analyzer.TestAnalyzer) ... ok
test_empty_password_is_very_weak (test_analyzer.TestAnalyzer) ... ok
test_entropy_is_positive_and_monotonic (test_analyzer.TestAnalyzer) ... ok
test_generators_produce_expected_chars (test_analyzer.TestAnalyzer) ... ok
test_hash_password_structure (test_analyzer.TestAnalyzer) ... ok
test_history_new_password (test_analyzer.TestAnalyzer) ... ok
test_history_reuse (test_analyzer.TestAnalyzer) ... ok
test_medium_length_password_scores_moderate (test_analyzer.TestAnalyzer) ... ok
test_none_password_is_handled_gracefully (test_analyzer.TestAnalyzer) ... ok
test_repeated_characters_detected (test_analyzer.TestAnalyzer) ... ok
test_sequence_detected (test_analyzer.TestAnalyzer) ... ok
test_short_password_scored_low_on_length (test_analyzer.TestAnalyzer) ... ok
test_strong_password_has_brute_force_data (test_analyzer.TestAnalyzer) ... ok
test_strong_password_scores_high (test_analyzer.TestAnalyzer) ... ok
test_suggest_passphrase_custom_lengths (test_analyzer.TestAnalyzer) ... ok
test_suggest_strong_password_clamping (test_analyzer.TestAnalyzer) ... ok
test_suggest_strong_password_max_length_no_symbols (test_analyzer.TestAnalyzer) ... ok
test_various_strength_labels (test_analyzer.TestAnalyzer) ... ok
test_analyze_rejects_password_too_long (test_app.TestApp) ... ok
test_analyze_requires_a_password (test_app.TestApp) ... ok
test_analyze_valid_password (test_app.TestApp) ... ok
test_generate_clamps_length (test_app.TestApp) ... ok
test_generate_rejects_invalid_length (test_app.TestApp) ... ok
test_generate_success (test_app.TestApp) ... ok
test_hash_endpoint (test_app.TestApp) ... ok
test_index_route (test_app.TestApp) ... ok
test_save_and_reuse_flow (test_app.TestApp) ... ok
test_save_validation (test_app.TestApp) ... ok
test_stats_endpoint (test_app.TestApp) ... ok

----------------------------------------------------------------------
Ran 31 tests in 8.114s

OK
```

---

## 📐 Design Decisions

1. **Pure Python Standard Library for Core Logic**:
   `password_analyzer.py` requires zero third-party packages. It relies exclusively on Python standard modules (`secrets`, `hashlib`, `hmac`, `math`, `re`, `dataclasses`). This ensures cross-platform portability across microservices, CLI tools, and servers.

2. **Isolated Database Testing**:
   The test suite utilizes an environment variable (`PASSWORDS_DB_PATH`) to execute tests against a temporary database without mutating the production or local `passwords.db`.

3. **Defensive Length Boundaries**:
   API payloads cap candidate password length at 256 characters to defend against regex and entropy calculation Denial-of-Service (DoS) attacks.

4. **Guaranteed Character Class Generation**:
   The random password generator guarantees at least one character from each active character set, preventing rare random edge cases where a generated password might omit a digit or uppercase character.

---

## 📄 License & Acknowledgments

- **Author**: Rabi Kumar Gupta ([@rabigupta-123](https://github.com/rabigupta-123))
- **Program**: Thiranex Internship
- **License**: MIT License