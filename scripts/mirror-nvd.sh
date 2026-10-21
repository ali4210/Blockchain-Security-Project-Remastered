#!/usr/bin/env bash
set -uo pipefail
mkdir -p ~/.local/state/nvd-mirror
start=0
total=1

while [ "$start" -lt "$total" ]; do
  outfile=~/.local/state/nvd-mirror/page_$start.json

  # resume: skip pages we already fetched and validated
  if [ -s "$outfile" ] && jq empty "$outfile" >/dev/null 2>&1; then
    total=$(jq -r '.totalResults' "$outfile")
    start=$((start + 2000))
    continue
  fi

  attempt=0
  ok=0
  delay=3

  while [ "$attempt" -lt 6 ]; do
    attempt=$((attempt + 1))
    curl -sS --http1.1 --retry 3 --retry-delay 2 -f \
      "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=$start&resultsPerPage=2000" \
      -H "apiKey: $NVD_API_KEY" -o "$outfile.tmp"

    if [ $? -eq 0 ] && jq empty "$outfile.tmp" >/dev/null 2>&1; then
      mv "$outfile.tmp" "$outfile"
      ok=1
      break
    fi
    echo "[!] startIndex=$start attempt=$attempt failed, backing off ${delay}s..."
    sleep "$delay"
    delay=$((delay * 2))
  done

  if [ "$ok" -ne 1 ]; then
    echo "[x] startIndex=$start still failing after 6 attempts -- skipping for now, will retry on next run"
    start=$((start + 2000))
    continue
  fi

  total=$(jq -r '.totalResults' "$outfile")
  echo "[+] fetched startIndex=$start / total=$total"
  start=$((start + 2000))
  sleep 1
done

echo "[+] NVD mirror run finished: $(ls ~/.local/state/nvd-mirror/page_*.json 2>/dev/null | wc -l) pages present"