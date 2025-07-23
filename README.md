# 📱 ms_tool - Mobile Static Testing Tool

> Created by: **Mayur Patil**

## 🚀 Overview

`ms_tool` is an automated **Android static analysis scanner** that identifies common security issues in decompiled Android apps. It is designed to assist penetration testers, security researchers, and developers by scanning source code or APKs for well-known insecure coding patterns.

---

## 🎯 Features

- Supports both **APK files** and **decompiled directories**
- Detects 12+ vulnerability categories
- Outputs findings in `.txt` or `.json` format
- Lightweight and fast
- Works with `.smali`, `.xml`, `.java`, `.kt`, `.txt` files
- Uses `apktool` for decompilation

---

## 🐞 Vulnerability Modules

| Flag                    | Description                                |
|-------------------------|--------------------------------------------|
| `--reverse_engineering` | Detects native libs or smali signs         |
| `--webview_js`          | Detects JS interface exposure in WebView   |
| `--logging_issues`      | Looks for `Log.*`, `printStackTrace`       |
| `--root_detection`      | Looks for root checks                      |
| `--firebase_misconfig`  | Detects open Firebase endpoints            |
| `--ssl_pinning`         | Looks for custom TrustManager logic        |
| `--insecure_data_storage` | Checks for insecure file storage modes  |
| `--insecure_credentials`| Finds hardcoded secrets / tokens           |
| `--insufficient_crypto` | Looks for weak or improper cryptography    |
| `--poor_code_quality`   | Dangerous methods like `eval`, `exec`      |
| `--extraneous_functionality` | Debug/test-only logic in release builds |
| `--deep_linking_abuse`  | Detects unprotected deep links             |

---

## 🛠️ Requirements

- Python 3.x
- `apktool` (must be installed and in PATH)
- `colorama` (Python lib)

```bash
pip install colorama
