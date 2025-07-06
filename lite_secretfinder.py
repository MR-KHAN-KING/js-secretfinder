import re
import requests
import json
import base64
import sys
import os
import time
import argparse
from datetime import datetime
from urllib.parse import urlparse

# === CLI Setup ===
parser = argparse.ArgumentParser(description="🔐 Lightweight Secret Finder")
parser.add_argument("-u", "--url", required=True, help="URL of JavaScript file to scan")
parser.add_argument("--silent", action="store_true", help="Suppress output")
args = parser.parse_args()

url = args.url.strip()
silent_mode = args.silent

# === Retry Fetch Logic ===
def fetch_url(url, retries=3, delay=2):
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=10)
            return response.text
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                print(f"[!] Failed to fetch after {retries} attempts: {e}")
                return None

js_code = fetch_url(url)
if not js_code:
    sys.exit()

# === Domain-aware output path ===
parsed = urlparse(url)
domain = parsed.hostname.replace("www.", "")
output_dir = os.path.join("output", domain)
os.makedirs(output_dir, exist_ok=True)
json_path = os.path.join(output_dir, "all_secrets.json")
html_path = os.path.join(output_dir, "all_secrets.html")

timestamp = datetime.now().isoformat()
results = {
    "url": url,
    "timestamp": timestamp,
    "findings": []
}

# === Regex Patterns ===
patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Authorization Bearer": r"Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    "Basic Auth": r"Basic\s+[a-zA-Z0-9=:_\+\/-]{5,100}",
    "Private Key": r"-----BEGIN(.*?)PRIVATE KEY-----",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Generic Secret/Token/Password": r"(?i)(secret|password|token|apikey|key)[\"'\s:=>]+[\"']?[a-zA-Z0-9\-_]{4,}",
    "Heroku-style UUID": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Hardcoded URL": r"https?://[^\s\"']+",
    "Base64 Encoded String": r"[A-Za-z0-9+/]{20,}={0,2}",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "Suspicious Variable Names": r"(var|let|const)\s+([a-zA-Z0-9_]*(token|secret|api|key)[a-zA-Z0-9_]*)",
    "Inline Comments with Secrets": r"(?://|#).*?(apikey|token|auth|key|secret)[^\n]*",
    "possible_Creds Fuzzy": r"(?i)(password|pwd|passwd|secret)\s*[:=]\s*[^\s,;\)]+"
}

# === Match Handling ===
for name, pattern in patterns.items():
    matches = re.findall(pattern, js_code)
    cleaned = list(set([m if isinstance(m, str) else m[0] for m in matches]))

    for match in cleaned:
        # Decode base64
        if name == "Base64 Encoded String":
            try:
                decoded = base64.b64decode(match).decode("utf-8")
                match = f"{match} → {decoded}"
            except:
                continue
        # Decode JWT
        elif name == "JWT Token":
            parts = match.split('.')
            try:
                header = base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
                payload = base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
                match = f"{match} → header: {header} | payload: {payload}"
            except:
                continue

        results["findings"].append({"type": name, "value": match})

# === Output Filter (Deduplication) ===
def append_json(path, new_entry):
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except:
        data = []

    for f in new_entry["findings"][:]:
        if any(f in d["findings"] for d in data):
            new_entry["findings"].remove(f)

    if new_entry["findings"]:
        data.append(new_entry)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        if not silent_mode:
            print(f"[📂] Saved to {path}")

def append_html(path, entry):
    try:
        with open(path, "r") as f:
            html = f.read()
            body = html.split("</ul>")[0]
    except:
        body = "<html><body><h2>🔐 Secret Finder Report</h2><ul>"

    if entry["findings"]:
        body += f"<li><b>{entry['url']}</b> ({entry['timestamp']})<ul>"
        for item in entry['findings']:
            body += f"<li><b>{item['type']}:</b> {item['value']}</li>"
        body += "</ul></li>"

        with open(path, "w") as f:
            f.write(body + "</ul></body></html>")
        if not silent_mode:
            print(f"[📂] HTML updated at {path}")

# === Print & Save
if results["findings"] and not silent_mode:
    print(f"\n[+] {len(results['findings'])} finding(s) in {url}")
    for f in results["findings"]:
        print(f"  - {f['type']}: {f['value']}")
elif not results["findings"] and not silent_mode:
    print("[-] No secrets or keys found.")

append_json(json_path, results)
append_html(html_path, results)
