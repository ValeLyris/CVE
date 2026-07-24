# Security Advisories & CVEs — Lyris Vale

Vulnerabilities I've discovered and disclosed through coordinated disclosure.

Each entry lists the CVE — or the vendor advisory ID, where a CVE is still pending — plus the metadata for the finding. Entries still under a coordinated-disclosure embargo publish metadata first, and the full write-up and proof of concept on the date noted in the entry. Entries whose details are already public upstream carry the full write-up, PoC, and evidence here too.

## Index

| # | CVE | Product | Type | Severity | Status | Details |
|---|-----|---------|------|----------|--------|---------|
| 1 | *pending* · [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r) | [ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus) | Unauth path traversal (CWE-22) | Critical · 10.0 (advisory) / 9.3 (mine) | Fixed in `2026-07-23-r1`; CVE requested | [→](./NPMplus-nginx-alias-path-traversal/) |
| 2 | [CVE-2026-14300](https://www.cve.org/CVERecord?id=CVE-2026-14300) | WordPress · miniOrange Social Login and Register | Unauth account takeover (CWE-287) | High · 8.1 | Fixed in 7.8.0; PoC embargoed to 2026-08-08 | [→](./CVE-2026-14300-miniOrange-social-login-ato/) |
| 3 | [CVE-2026-14313](https://www.cve.org/CVERecord?id=CVE-2026-14313) | WordPress · PeproDev WooCommerce Receipt Uploader | Unauth IDOR (CWE-639/862) | Medium · 5.3 | No fix as of 2026-07-23; PoC embargoed to 2026-08-12 | [→](./CVE-2026-14313-peprodev-receipt-uploader-idor/) |

Both WordPress CVEs were assigned by the WPScan CNA and their cve.org records were still awaiting publication as of 2026-07-23; the WPScan entries linked from each page are authoritative in the meantime.

## Disclosure approach

I report privately to a maintainer or a CNA first and hold public exploitation detail until a fix is available (or until the platform's coordinated-disclosure date), whichever the program requires. Proof-of-concept code here is for reproducing a finding against an instance you own or are authorised to test; it is provided as-is, with no warranty.

## Licence

- **Code** — everything under `*/poc/` is [MIT](./LICENSE).
- **Write-ups and evidence** — the prose, analysis, and screenshots are [CC BY 4.0](./LICENSE-docs).

Copyright © 2026 Lyris Vale. Both licences require the attribution to stay with the material: credit Lyris Vale ([@ValeLyris](https://github.com/ValeLyris)) and link back.

---

Maintained by Lyris Vale · GitHub [@ValeLyris](https://github.com/ValeLyris)
