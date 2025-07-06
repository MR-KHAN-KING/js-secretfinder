# 🔐 JS SecretFinder

A lightweight, domain-aware JavaScript secret scanner that detects:

- 🔑 API keys (AWS, Google, Slack, Facebook, etc.)
- 🔁 JWT tokens (decoded)
- 🔍 Inline secrets in comments
- 🧠 Fuzzy logic for passwords, tokens, keys
- 🔓 Base64-encoded secrets (decoded)

## 🚀 Features

- ✅ CLI-friendly with `--silent` mode
- ✅ Deduplication of findings
- ✅ Structured output per domain
- ✅ HTML & JSON report generation
- ✅ LinkFinder integration to extract JS links from target pages

## 📦 Install Dependencies

```bash
pip install -r requirements.txt


Usage

bash jsrecon.sh
# OR
python3 lite_secretfinder.py -u https://target.com/script.js
