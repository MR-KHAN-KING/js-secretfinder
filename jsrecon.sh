#!/bin/bash

# === CONFIG ===
LINKFINDER_PATH="/data/data/com.termux/files/home/LinkFinder/linkfinder.py"
SECRETFINDER_PATH="./lite_secretfinder.py"

# === INPUT ===
read -p "🔗 Enter Target URL (e.g. https://example.com/page): " TARGET

# === SETUP ===
DOMAIN=$(echo $TARGET | awk -F/ '{print $3}')
OUTPUT_DIR="output/$DOMAIN"
mkdir -p "$OUTPUT_DIR"

echo -e "\n[🔍] Running LinkFinder on $TARGET ..."
python3 "$LINKFINDER_PATH" -i "$TARGET" -o cli > "$OUTPUT_DIR/linkfinder_output.txt"

echo -e "[📄] Extracting JS URLs..."
grep -Eo 'https?://[^ ]+\.js' "$OUTPUT_DIR/linkfinder_output.txt" | sort -u > "$OUTPUT_DIR/js_list.txt"
JS_COUNT=$(wc -l < "$OUTPUT_DIR/js_list.txt")
echo "[✓] Found $JS_COUNT JS files"

# === SCAN ALL JS FILES ===
echo -e "\n[🔐] Scanning all JS files for secrets..."
while read -r js_url; do
  echo -e "\n[*] Scanning: $js_url"
  python3 "$SECRETFINDER_PATH" -u "$js_url" --silent
done < "$OUTPUT_DIR/js_list.txt"

# === ZIP REPORTS ===
cd output && zip -r "${DOMAIN}_secret_report.zip" "$DOMAIN" > /dev/null && cd ..
echo -e "\n[📦] Zipped report saved at: output/${DOMAIN}_secret_report.zip"
echo "[✅] Recon complete. Happy hunting!"
