# 🦉 OKerberang

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Attack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OKerberang** — Kerberos AS-REP/Kerberoast analyzer (offline; hashcat 18200/13100/19700) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OKerberang — Kerberos AS-REP/Kerberoast analyzer (offline; hashcat 18200/13100/19700). Kerberos AS-REP/Kerberoast Analyzer OWL Batch-3 offensive security toolkit. AUTHORIZED TESTING ONLY.

---

## ✨ Features

- Offline Kerberos AS-REP and Kerberoast material analyzer
- Prepare hashcat modes 18200 / 13100 / 19700 oriented outputs
- Identify ticket/hash shapes and common encoding issues
- Lab-focused workflow with no live domain dependency required
- Structured triage for AD purple-team exercises
- Export crack-ready and analysis reports

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OKerberang OKerberang.go
./OKerberang --help
./OKerberang --input asrep.txt
./OKerberang --input tgs.txt --format hashcat
./OKerberang --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled.s.Haddad
