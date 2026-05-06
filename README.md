# Travaux Pratiques — Cryptographie Appliquée

**Niveau** : Ing3 — Cybersécurité  
**Langage** : Python 3.9+  
**Bibliothèques** : pycryptodome · cryptography · sympy · hashlib · matplotlib

---

## Installation

```bash
pip install -r requirements.txt
```

## Exécution

### Menu interactif
```bash
python main.py
```

### Exercice individuel
```bash
# Sur Windows, définir l'encodage UTF-8 si nécessaire :
set PYTHONIOENCODING=utf-8

# Lancer un exercice spécifique :
python -m TP1_Chiffrement_Classique.ex1_1_cesar
python -m TP2_Crypto_Symetrique.ex2_1_rc4
python -m TP3_Crypto_Asymetrique.ex3_1_diffie_hellman
python -m TP4_Hachage.ex4_2_sha256
python -m TP5_Signatures.ex5_1_signature_rsa

# Ou via le menu avec numéro :
python main.py 1.1
python main.py all  # lancer tous les exercices
```

---

## Structure du projet

| TP | Thème | Exercices |
|---|---|---|
| **TP1** | Chiffrement Classique | César, Vigenère, Hill, OTP |
| **TP2** | Crypto Symétrique | RC4, DES/3DES, AES modes, 5 finalistes NIST |
| **TP3** | Crypto Asymétrique | Diffie-Hellman, RSA, ElGamal, ECC |
| **TP4** | Fonctions de Hachage | MD5, SHA-256 (from scratch), SHA-512 |
| **TP5** | Signatures Numériques | RSA-PSS, ElGamal, DSA, ECDSA |

### Approche d'implémentation

- **From scratch** (pur Python) : César, Vigenère, Hill, OTP, RC4, Diffie-Hellman, ElGamal, ECC (addition de points), SHA-256
- **Avec bibliothèques** : DES/AES (pycryptodome), RSA/ECDH (cryptography), MD5/SHA-512 (hashlib), 5 finalistes AES

---

## Contenu de chaque script

Chaque exercice contient :
1. **Code Python** complet, modulaire et commenté (en français)
2. **Réponses théoriques** aux questions du TP
3. **Démonstrations** exécutables avec résultats vérifiés

---

## Arborescence

```
cryptography-implementations/
├── main.py                              # Menu principal
├── requirements.txt                     # Dépendances
├── README.md
├── TP1_Chiffrement_Classique/
│   ├── ex1_1_cesar.py                   # César + force brute + IC
│   ├── ex1_2_vigenere.py                # Vigenère + Kasiski + IC
│   ├── ex1_3_hill.py                    # Hill 2×2/3×3 + attaque clair connu
│   └── ex1_4_otp.py                     # OTP + réutilisation + crib dragging
├── TP2_Crypto_Symetrique/
│   ├── ex2_1_rc4.py                     # RC4 KSA/PRGA + WEP + biais
│   ├── ex2_2_des.py                     # DES/3DES ECB/CBC + benchmark
│   ├── ex2_3_aes.py                     # AES ECB/CBC/CTR + avalanche + nonce
│   └── ex2_4_finalistes_aes.py          # 5 finalistes NIST + benchmark
├── TP3_Crypto_Asymetrique/
│   ├── ex3_1_diffie_hellman.py          # DH + MITM + contre-mesure ECDSA
│   ├── ex3_2_rsa.py                     # RSA + hybride RSA+AES + OAEP
│   ├── ex3_3_elgamal.py                 # ElGamal + malléabilité + comparaison
│   └── ex3_4_ecc.py                     # ECC from scratch + ECDH + ECIES
├── TP4_Hachage/
│   ├── ex4_1_md5.py                     # MD5 + effet avalanche
│   ├── ex4_2_sha256.py                  # SHA-256 FROM SCRATCH (64 tours)
│   └── ex4_3_sha512_compare.py          # Comparaison + benchmark 100 Mo
└── TP5_Signatures/
    ├── ex5_1_signature_rsa.py           # RSA-PSS signature
    ├── ex5_2_signature_elgamal.py       # ElGamal signature from scratch
    └── ex5_3_dsa_ecdsa.py               # DSA + ECDSA multi-courbes
```