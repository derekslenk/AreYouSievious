#!/bin/sh
set -eu
if grep -E 'mail\.slenk\.email|derek@slenk\.com' backend/fetch_grak_script.py; then
    echo "PII still committed" >&2
    exit 1
fi
echo "OK"
