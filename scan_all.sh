#!/bin/bash
echo "=== Running SecretFinder on all JS files ==="
while read url; do
    echo -e "\n[*] Scanning: $url"
    python3 lite_secretfinder.py <<< "$url"
done < js_list.txt
