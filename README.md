# Security Advisories & CVEs — Lyris Vale

Vulnerabilities I've discovered and disclosed through coordinated disclosure. Each entry lists the assigned CVE and metadata; once any embargo lifts it also carries a full writeup, a reproducible proof of concept, and references.

CVE identifiers are added as the relevant CNA assigns them. Some entries publish in two stages — the CVE and metadata go up first, and the full technical details / PoC follow on the coordinated-disclosure date noted in the entry.

## Index

| # | CVE | Product | Type | Severity | Status | Details |
|---|-----|---------|------|----------|--------|---------|
| 1 | *pending* · [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r) | [ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus) | Unauth path traversal (CWE-22) | Critical | Fixed in `2026-07-23-r1`; CVE requested | [→](./NPMplus-nginx-alias-path-traversal/) |
| 2 | [CVE-2026-14300](https://www.cve.org/CVERecord?id=CVE-2026-14300) | miniOrange Social Login and Register | Unauth account takeover (CWE-287) | High · 8.1 | Fixed in 7.8.0; PoC embargoed to 2026-08-08 | [→](./CVE-2026-14300-miniOrange-social-login-ato/) |
| 3 | [CVE-2026-14313](https://www.cve.org/CVERecord?id=CVE-2026-14313) | PeproDev WooCommerce Receipt Uploader | Unauth IDOR (CWE-639/862) | Medium · 5.3 | No fix yet; PoC embargoed to 2026-08-12 | [→](./CVE-2026-14313-peprodev-receipt-uploader-idor/) |

## Disclosure approach

I report privately to a maintainer or a CNA first and hold public exploitation detail until a fix is available (or until the platform's coordinated-disclosure date), whichever the program requires. Proof-of-concept code is for reproducing a finding against an instance you own.

---

Maintained by Lyris Vale · GitHub [@ValeLyris](https://github.com/ValeLyris)
