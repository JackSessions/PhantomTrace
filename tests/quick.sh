#!/usr/bin/env bash
# Quick check on Linux: unit tests, then the clean vs tampered demo. Needs: python3, ntfs-3g (sudo apt install ntfs-3g)
set -e
cd "$(dirname "$0")/.."
command -v mkntfs >/dev/null || { echo "Install ntfs-3g first: sudo apt install ntfs-3g"; exit 2; }
echo "== unit tests"; python3 -m unittest discover -s tests
echo; echo "== building demo images"; (cd tests && python3 make_demo.py)
echo; echo "== clean image (expect: no findings, exit 0)"; python3 phantom_trace.py tests/demo/clean.img -q || true
echo; echo "== tampered image (expect: findings, exit 1)"; python3 phantom_trace.py tests/demo/tampered.img || true
echo; echo "Optional: python3 phantom_trace.py tests/demo/tampered.img --html report.html && xdg-open report.html"
