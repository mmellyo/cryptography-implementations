<p align="center">
  <h1 align="center">Crypto</h1>
  <p align="center">A reference cryptography lab covering classical ciphers, symmetric/asymmetric primitives, hash functions, digital signatures, and secure communication applications — with CLI, TUI and desktop GUI.</p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.9+-3776AB.svg?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/tests-118%20passing-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-NIST%20%E2%9C%93%20RFC%20%E2%9C%93-success.svg" alt="Coverage">
  <img src="https://img.shields.io/badge/algorithms-25+-orange.svg" alt="Algorithms">
</p>

---

## Installation

```sh
# Clone
git clone x
cd crypto

# Virtualenv (recommande)
python3 -m venv .venv
source .venv/bin/activate

# Dependencies
pip install -r requirements.txt

# Run any of the three interfaces
python main.py        # CLI menu
python tui.py         # Terminal UI (Textual)
python gui.py         # Desktop GUI (Qt / PySide6)
```

---

## Architecture

Each cryptographic algorithm is exposed as a pure-Python module with a public
API (`chiffrer`, `dechiffrer`, `signer`, `verifier`, `chiffrer_bloc`, …) and a
non-interactive `demo()` function. Three independent front-ends consume those
modules without duplicating any cryptographic code.

```
              ┌────────────────────────────────────────────┐
              │              user-facing layer             │
              │  ┌────────┐   ┌────────┐   ┌──────────┐   │
              │  │  CLI   │   │  TUI   │   │   GUI    │   │
              │  │main.py │   │tui.py  │   │ gui.py   │   │
              │  └────┬───┘   └────┬───┘   └─────┬────┘   │
              └───────┴────────────┴─────────────┴────────┘
                            │ importlib + demo()
              ┌─────────────┴───────────────────────────────┐
              │            cryptographic modules            │
              │                                             │
              │  classical/   symmetric/   asymmetric/      │
              │  hashing/     signatures/  applications/    │
              └─────────────┬───────────────────────────────┘
                            │
              ┌─────────────┴───────────────────────────────┐
              │       libraries (audited primitives)        │
              │  pycryptodome · cryptography · hashlib      │
              │  twofish · sympy · matplotlib               │
              └─────────────────────────────────────────────┘
```

### Validation Layers

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| Algorithm correctness | Vecteurs officiels (NIST FIPS 180-4, 197, SP 800-38A, RFC 1321/4231/6229) | Implementations from-scratch validees byte-for-byte |
| Property tests | Round-trip, avalanche, malleabilite, non-determinisme | Comportements crypto attendus verifies |
| Integration tests | TCP/UDP echo serveur, vote homomorphe end-to-end | Composition complete des primitives |
| Static checks | `pytest --strict-markers`, `py_compile` | Erreurs de typage et imports detectes a froid |

### Educational vs Production primitives

| Module | Style | Notes |
|--------|-------|-------|
| AES, DES/3DES, RSA-OAEP, RSA-PSS, ECDSA, DSA, ECDH, MD5/SHA-256/SHA-512 (hashlib) | Library-backed | `pycryptodome` / `cryptography` / stdlib — production-grade |
| Caesar, Vigenere, Hill, OTP | From scratch | Toy ciphers, pedagogical |
| RC4, RC6, Serpent | From scratch | Validated against published vectors |
| SHA-256, HMAC | From scratch | Validated against NIST FIPS 180-4 / RFC 4231 |
| Diffie-Hellman, ElGamal (cipher + signature), ECC arithmetic | From scratch | Pure-Python — **not constant-time**, educational only |

---

## Requirements

| Dependency | Version |
|-----------|---------|
| Python | 3.9+ |
| pycryptodome | 3.20+ |
| cryptography | 42+ |
| sympy | 1.12+ |
| matplotlib | 3.8+ |
| Pillow | 10+ |
| twofish | 0.3+ |
| pytest | 8+ |
| textual (TUI) | 0.50+ |
| PySide6 (GUI) | 6.5+ |

---

## Features

### Completed

- **TP1 — Classical ciphers** — Caesar, Vigenere, Hill (2x2/3x3), OTP with frequency analysis, Kasiski, IC, known-plaintext attack, crib dragging
- **TP2 — Symmetric crypto** — RC4 (KSA/PRGA + WEP/FMS attack + bias), DES/3DES (ECB/CBC + image leakage), AES-128/192/256 (ECB/CBC/CTR + avalanche + nonce reuse), AES finalists (Rijndael, Serpent, Twofish, RC6) with matplotlib bar chart
- **TP3 — Asymmetric crypto** — Diffie-Hellman (≥ 512 bits + ECDSA-authenticated countermeasure), RSA-OAEP (512/1024/2048/3072/4096), ElGamal (with malleability + size comparison), ECC over a custom curve + ECDH P-256 + ECIES
- **TP4 — Hashing** — MD5 (5-message pipeline + avalanche), SHA-256 from scratch (10 NIST vectors + file integrity), SHA-512 (cross-comparison + 100 MB benchmark), HMAC from scratch (RFC 4231 vectors)
- **TP5 — Digital signatures** — RSA PKCS#1 v1.5 + PSS, ElGamal signature, DSA + ECDSA on P-256/384/521
- **TP6 — Secure communications** — RSA-OAEP + AES-CTR + HMAC-SHA256 channel; TCP/IP server-client, UDP authenticated chat, Bluetooth RFCOMM transport (pluggable), homomorphic e-voting (additive ElGamal)
- **Three front-ends sharing the same UX** — CLI menu, Textual TUI, PySide6 desktop GUI. All three offer the **same two views per module** (pre-baked `Scenario` + `Tester avec mes valeurs` form) driven by a single `gui_specs.SPECS` table, and use the same Honeydew / Cool Sky / French Blue palette.
- **118 tests** — `pytest` suite with NIST/RFC vectors, network round-trip, tampering rejection, vote tally
- **Image visualisation** — PGM read/write helper (`common/pgm.py`) used by AES/DES to expose ECB pattern leakage

## Build Targets

| Module | Entry point | Description |
|--------|-------------|-------------|
| `main` | `python main.py` | Branded CLI menu — `Scenario` or interactive `Tester avec mes valeurs` |
| `tui` | `python tui.py` | Textual TUI — sidebar tree + tabs (`Mes valeurs` / `Scenario`) + status bar |
| `gui` | `python gui.py` | PySide6 desktop — branded toolbar, custom per-module panels, threaded workers |
| `applications.tcp_secure` | `python -m applications.tcp_secure` | Standalone TCP secure echo server |
| `applications.udp_chat` | `python -m applications.udp_chat` | Standalone UDP secure chat |
| `applications.voting` | `python -m applications.voting` | Standalone homomorphic voting demo |

---

## Usage

### CLI

```sh
python main.py                       # interactive menu (branded header, themed sections)
python main.py classical.caesar      # one demo by name (non-interactive)
python main.py 2.3                   # by course exercise alias
python main.py all                   # run every demo sequentially
python main.py --help                # usage
python -m classical.caesar           # bypass the menu entirely
```

Interactive mode shows a French-Blue branded header and lists every module by
theme. After picking one, you can choose:

| Key | Action |
|-----|--------|
| `s` | run the pre-baked `Scenario` (`demo()` output) |
| `i` | open the form (`Tester avec mes valeurs`) — same fields as GUI/TUI |
| `q` | back to the menu |

ANSI colors auto-disable when stdout is not a TTY, so piping/redirecting stays clean.

### TUI

```sh
python tui.py
```

Layout mirrors the GUI: branded top bar, sidebar tree of modules, two right-side
tabs (`Tester avec mes valeurs` default + `Scenario`), status bar at the bottom.

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` | Lancer scenario |
| `Ctrl+L` | Effacer la sortie |
| `i` / `s` | switch to `Mes valeurs` / `Scenario` tab |
| `q` | Quitter |
| `Enter` on a tree node | run that module |

### GUI

```sh
python gui.py
```

Branded toolbar in French Blue with `Lancer scenario` (Ctrl+R) and `Effacer`
(Ctrl+L). Default tab is `Tester avec mes valeurs` (interactive form or custom
panel — symmetric/asymmetric encrypt-decrypt, hash, signatures, network chats,
e-voting). Status bar shows `Pret` / `En cours` with a progress indicator while
the demo runs in a `QThread`.

### Direct API

```python
from classical.caesar import chiffrer, attaque_force_brute
from symmetric.block.aes_finalists import RC6, Serpent
from hashing.sha256 import sha256_manuel
from applications.voting import generer_election, chiffrer_vote, decompter

# Caesar
chiffre = chiffrer("Bonjour", k=7)
attaque_force_brute(chiffre)

# Serpent block encryption (pure-Python, validated against AES-original vectors)
ct = Serpent(b"\x00" * 16).chiffrer_bloc(b"\x00" * 16)

# SHA-256 from scratch
digest = sha256_manuel(b"abc")

# Homomorphic voting
p, g, y, x = generer_election(64)
ballots = [chiffrer_vote(p, g, y, v) for v in (1, 0, 1, 1, 0)]
total = decompter(p, g, x, ballots, max_votants=5)  # -> 3
```

---

## Modules

### Classical (TP1)

| Module | Functions |
|--------|-----------|
| `classical.caesar` | `chiffrer`, `dechiffrer`, `attaque_force_brute`, `calculer_ic`, `analyse_frequences` |
| `classical.vigenere` | `chiffrer`, `dechiffrer`, `kasiski`, `trouver_longueur_cle_ic`, `retrouver_cle` |
| `classical.hill` | `chiffrer`, `dechiffrer`, `attaque_clair_connu`, `inverse_mat_mod`, `matrice_valide` |
| `classical.otp` | `generer_cle`, `chiffrer`, `dechiffrer`, `crib_drag` |

### Symmetric (TP2)

| Module | Description |
|--------|-------------|
| `symmetric.stream.rc4` | KSA + PRGA, WEP/FMS attack, 2nd-byte bias |
| `symmetric.block.des` | DES/3DES CBC, ECB pattern leakage on PGM, benchmark 1 Mo |
| `symmetric.block.aes` | AES-128/192/256, image visualisation, avalanche, nonce reuse |
| `symmetric.block.aes_finalists` | RC6 + Serpent from scratch, AES + Twofish via libs, matplotlib bench |

### Asymmetric (TP3)

| Module | Description |
|--------|-------------|
| `asymmetric.diffie_hellman` | DH ≥ 512 bits, MITM, ECDSA-authenticated exchange |
| `asymmetric.rsa` | RSA-OAEP 512/1024/2048/3072/4096, hybrid RSA + AES |
| `asymmetric.elgamal` | ElGamal cipher, malleability, RSA-2048 vs ElGamal-2048 size comparison |
| `asymmetric.ecc` | y²=x³+7 mod 97 arithmetic, ECDH P-256, ECIES |

### Hashing (TP4)

| Module | Description |
|--------|-------------|
| `hashing.md5` | MD5 5-message pipeline, avalanche |
| `hashing.sha256` | SHA-256 from scratch, 10 NIST vectors, file integrity verification |
| `hashing.sha512` | MD5/SHA-256/SHA-512 comparison, 100 MB benchmark |
| `hashing.hmac` | HMAC from scratch, RFC 4231 validation, constant-time compare |

### Signatures (TP5)

| Module | Description |
|--------|-------------|
| `signatures.rsa_signature` | RSA PKCS#1 v1.5 (deterministic) + PSS (probabilistic) |
| `signatures.elgamal_sig` | ElGamal signature with strict (r, s) range checks |
| `signatures.dsa_ecdsa` | DSA-2048, ECDSA on P-256/384/521, benchmark |

### Applications (TP6)

| Module | Description |
|--------|-------------|
| `applications.secure_channel` | RSA-OAEP handshake + AES-CTR + HMAC-SHA256 frames |
| `applications.tcp_secure` | TCP server / client + threaded echo server |
| `applications.udp_chat` | Authenticated UDP packets + threaded echo |
| `applications.bluetooth_secure` | RFCOMM transport (pybluez optional) |
| `applications.voting` | Additive-homomorphic ElGamal e-voting |

---

## Project Structure

```
crypto/
├── main.py                       # CLI menu + interactive form mode
├── tui.py                        # Textual TUI (mirrors GUI layout)
├── gui.py                        # PySide6 desktop GUI
├── gui_specs.py                  # Shared form descriptors + runners (used by CLI/TUI/GUI)
├── gui_widgets.py                # Reusable Qt widgets (FormatField, LabeledDropdown, ...)
├── gui_panels.py                 # Per-algorithm Qt panels (symmetric, asymmetric, hash, sig)
├── gui_apps.py                   # Application panels (TCP/UDP/Bluetooth chat, voting)
├── requirements.txt
├── pyproject.toml                # pytest configuration
├── classical/                    # TP1
│   ├── caesar.py
│   ├── vigenere.py
│   ├── hill.py
│   └── otp.py
├── symmetric/                    # TP2
│   ├── stream/rc4.py
│   └── block/
│       ├── des.py
│       ├── aes.py
│       ├── _serpent.py           # bitslice column-lookup Serpent
│       └── aes_finalists.py
├── asymmetric/                   # TP3
│   ├── diffie_hellman.py
│   ├── rsa.py
│   ├── elgamal.py
│   └── ecc.py
├── hashing/                      # TP4
│   ├── md5.py
│   ├── sha256.py
│   ├── sha512.py
│   └── hmac.py
├── signatures/                   # TP5
│   ├── rsa_signature.py
│   ├── elgamal_sig.py
│   └── dsa_ecdsa.py
├── applications/                 # TP6
│   ├── secure_channel.py
│   ├── tcp_secure.py
│   ├── udp_chat.py
│   ├── bluetooth_secure.py
│   └── voting.py
├── common/
│   └── pgm.py                    # PGM image reader/writer
├── assets/                       # PGM inputs and AES/DES outputs
├── docs/
│   └── document.pdf              # Course brief
└── tests/
    ├── test_classical.py
    ├── test_symmetric.py
    ├── test_asymmetric.py
    ├── test_hashing.py
    ├── test_signatures.py
    └── test_applications.py
```

---

## Testing

```sh
# Run the full suite (118 tests, < 2 s)
pytest

# Skip the slow tests (DH/ElGamal at full 512 bits)
pytest -m "not slow"

# Single TP
pytest tests/test_hashing.py

# By name
pytest -k "TestRC6 or TestSerpent"

# Verbose with timings
pytest -v --durations=10
```

| TP | File | Tests | Vectors |
|----|------|-------|---------|
| TP1 | `test_classical.py` | 21 | Wikipedia (Vigenere LEMON, Hill ACT→POH), round-trips |
| TP2 | `test_symmetric.py` | 24 | RC4 Wikipedia, AES NIST FIPS 197 + SP 800-38A, RC6 RFC, Serpent AES-original |
| TP3 | `test_asymmetric.py` | 22 | DH/MITM, RSA OAEP round-trip, ElGamal malleability, ECC group laws |
| TP4 | `test_hashing.py` | 24 | MD5 RFC 1321, SHA-256 NIST FIPS 180-4, HMAC RFC 4231 |
| TP5 | `test_signatures.py` | 13 | PKCS#1 v1.5 / PSS / ElGamal sig / ECDSA round-trip + tamper |
| TP6 | `test_applications.py` | 14 | TCP/UDP echo round-trip, HMAC tampering, voting tally |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHONIOENCODING` | — | Set to `utf-8` on Windows if accented characters are mangled |
| `MPLBACKEND` | `Agg` (forced in code) | Matplotlib runs headless for benchmarks |

Test markers (`pyproject.toml`):

| Marker | Use |
|--------|-----|
| `slow` | Tests that generate ≥ 512-bit primes via `sympy.primitive_root` |
