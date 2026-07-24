# Security advisories and CVEs — Lyris Vale

Vulnerabilities I have found and reported. Each one is published here with its write-up, proof of concept and evidence once the fix is out — or with metadata only while it is still under coordinated disclosure.

## Findings

Newest first.

| Disclosed | Identifier | Product | Class | Severity | Status |
|---|---|---|---|---|---|
| 2026-07-23 | [GHSA-wj85-328x-ww6r][ghsa] · CVE pending | [ZoeyVid/NPMplus](./npmplus-nginx-alias-path-traversal/) | Unauthenticated path traversal | 10.0 Critical · 9.3 mine | Fixed `2026-07-23-r1` |
| 2026-07-22 | [CVE-2026-14313][cve-14313] | WordPress · [PeproDev Receipt Uploader](./wp-peprodev-receipt-uploader-idor/) | Unauthenticated IDOR | 5.3 Medium | No fix · plugin closed 2026-07-21 · detail 2026-08-12 |
| 2026-07-08 | [CVE-2026-14300][cve-14300] | WordPress · [miniOrange Social Login](./wp-miniorange-social-login-account-takeover/) | Unauthenticated account takeover | 8.1 High | Fixed `7.8.0` · detail 2026-08-08 |

*Both WordPress CVEs were assigned by the WPScan CNA; their cve.org records were still awaiting publication on 2026-07-23, so the WPScan entry linked from each page is authoritative in the meantime.*

[ghsa]: https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r
[cve-14300]: https://www.cve.org/CVERecord?id=CVE-2026-14300
[cve-14313]: https://www.cve.org/CVERecord?id=CVE-2026-14313

## Disclosure approach

I report privately to the maintainer or to a CNA first, and hold the exploitation detail until a fix is available or until the programme's coordinated-disclosure date, whichever it requires. Where a vendor never ships a fix, the entry says so and carries the date the status was last checked.

Proof-of-concept code here is for reproducing a finding against an instance you own or are authorised to test. It is provided as-is, with no warranty.

To reach me about any of this, open an issue here or contact [@ValeLyris](https://github.com/ValeLyris) on GitHub.

## Conventions

- **Folders are named for the product and the bug, never for an identifier.** CVE IDs arrive weeks after disclosure and sometimes never — GHSA-wj85-328x-ww6r still has none. A folder name is chosen once and never changed; identifiers live in the table above and in each entry's metadata.
- **Severity is the published score**, with my own CVSS 3.1 alongside it where the two differ. Both vectors and the reasoning are in the entry.
- **`detail YYYY-MM-DD`** marks a finding still under coordinated disclosure: identifiers, affected versions and fix status only until that date. Any claim about a current fix state carries the date it was checked.

## Licence

- **Code** — everything under `*/poc/` is [MIT](./LICENSE).
- **Write-ups and evidence** — the prose, analysis and screenshots are [CC BY 4.0](./LICENSE-docs).

Copyright © 2026 Lyris Vale ([@ValeLyris](https://github.com/ValeLyris)). Both licences require the attribution to stay with the material.
