# 🔗 Merkle Tree CLI — Applied Cryptography & Blockchain Foundations

This project demonstrates my hands-on experience in **blockchain data structures** and **applied cryptography**, by building a fully operational **Merkle Tree system** with support for **inclusion proofs** and **RSA digital signatures**.

Developed as part of my personal exploration and specialization in **Merkle-based proof systems**, this project focuses on designing secure, verifiable, and cryptographically sound mechanisms for data integrity.

---

## 🔍 Project Overview

This Python-based CLI allows you to:

- 🌿 Dynamically construct a **Merkle Tree** from arbitrary leaf inputs.
- 🔗 Generate **Proof of Inclusion (PoI)** for any leaf.
- ✅ **Verify** Merkle proofs against the root hash.
- 🔐 Generate RSA **key pairs** for signing data.
- ✍️ **Sign** the Merkle root using private keys.
- 🧾 **Verify** RSA-based digital signatures on hashed data.

All components are implemented **from scratch**, with a focus on transparency, correctness, and modular cryptographic design.

---

## 💡 Why This Project?

As a researcher in **cryptography and blockchain systems**, I built this tool to deepen my understanding of:

- Binary hash trees and minimal height construction
- Real-world applications of **RSA-based digital signatures**
- Parsing and verifying **PEM-formatted keys**
- Safely managing inclusion proofs within decentralized systems

By reimplementing core logic without external Merkle libraries, I aimed to strengthen my theoretical and practical understanding of the cryptographic integrity layer that powers blockchain networks, zero-knowledge proofs, and distributed systems.

---

## 🧪 Example CLI Session

```bash
$ python merkle.py

1 a                      # Add leaf "a"
1 b                      # Add leaf "b"
2                        # Compute Merkle root
3 0                      # Get PoI for leaf at index 0
4 a <root> <proof...>    # Verify PoI
5                        # Generate RSA key pair
6 -----BEGIN RSA...       # Sign current Merkle root
7 -----BEGIN PUB... sig root  # Verify signature
```

---

## 🔐 Cryptography Stack

- `hashlib` — SHA256 hashing for all Merkle operations
- `cryptography` — RSA key generation, signature, and verification (PSS padding, SHA256)
- `base64`, `re`, `math` — for proof encoding, input validation, and tree balancing

All cryptographic functions are implemented **in compliance with best practices** using standard Python libraries.

---

## ✅ Testing and Validation

Includes a **comprehensive unittest suite** (>150 tests) that covers:

- Command validation & input structure
- Proof construction and verification correctness
- RSA signing and signature checks
- Full E2E flow from tree creation to proof and signature validation

```bash
$ python -m unittest test_merkle.py
```

---

## 📁 File Structure

```
.
├── merkle.py         # Core implementation: tree logic, RSA, CLI
├── test_merkle.py    # Full coverage unit tests
└── README.md         # You're here!
```

---

## 🚀 Possible Extensions

- 🧱 Add tree export/import (for persistent blockchains)
- 🔄 Swap SHA256 with pluggable hash functions (e.g. Keccak for Ethereum)
- 📈 Performance benchmarking on large-scale trees
- 🌐 Web-based Merkle visualizer with proof validation

---

## 👨‍💻 Author

This project reflects my deeper dive into **blockchain cryptographic infrastructure**, and showcases the **intersection between data structures and digital security**.

If you're working on cryptographic protocols, verifiable computation, or blockchain infrastructure and want to collaborate—feel free to connect.
