# Security advisories and CVEs — Lyris Vale

Vulnerabilities I have found and reported. Each one is published here with its write-up, proof of concept and evidence once the fix is out — or with metadata only while it is still under coordinated disclosure.

## Findings

*Newest first.*

<table width="100%">
<tbody>
<tr><td>
<h3><a href="./npmplus-nginx-alias-path-traversal/">ZoeyVid/NPMplus</a> · <a href="https://www.cve.org/CVERecord?id=CVE-2026-102738">CVE-2026-102738</a></h3>
<p><strong>10.0 Critical</strong> · Unauthenticated path traversal<br>
Disclosed 2026-07-23 · Fixed in <code>2026-07-23-r1</code> · <a href="https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r">GHSA-wj85-328x-ww6r</a></p>
</td></tr>
<tr><td>
<h3><a href="./wp-peprodev-receipt-uploader-idor/">PeproDev Receipt Uploader</a> · <a href="https://www.cve.org/CVERecord?id=CVE-2026-14313">CVE-2026-14313</a></h3>
<p><strong>5.3 Medium</strong> · WordPress · Unauthenticated IDOR<br>
Disclosed 2026-07-22 · No fix; plugin closed 2026-07-21 · detail 2026-08-12</p>
</td></tr>
<tr><td>
<h3><a href="./wp-miniorange-social-login-account-takeover/">miniOrange Social Login</a> · <a href="https://www.cve.org/CVERecord?id=CVE-2026-14300">CVE-2026-14300</a></h3>
<p><strong>8.1 High</strong> · WordPress · Unauthenticated account takeover<br>
Disclosed 2026-07-08 · Fixed in <code>7.8.0</code> · detail 2026-08-08</p>
<p><em>Both WordPress CVEs were assigned by the WPScan CNA; their cve.org records were still awaiting publication on 2026-07-23, so the WPScan entry linked from each page is authoritative in the meantime.</em></p>
</td></tr>
</tbody>
</table>

## Disclosure approach

I report privately to the maintainer or to a CNA first, and hold the exploitation detail until a fix is available or until the programme's coordinated-disclosure date, whichever it requires. Where a vendor never ships a fix, the entry says so and carries the date the status was last checked.

Proof-of-concept code here is for reproducing a finding against an instance you own or are authorised to test. It is provided as-is, with no warranty.

To reach me about any of this, open an issue here or contact [@ValeLyris](https://github.com/ValeLyris) on GitHub.

## Conventions

- **Folders are named for the product and the bug, never for an identifier.** CVE IDs can arrive after disclosure — NPMplus's July advisory was confirmed as CVE-2026-102738 in September. A folder name is chosen once and never changed; identifiers live in the list above and in each entry's metadata.
- **Severity follows the published advisory.** The CVSS vector and source are in each entry.
- **`detail YYYY-MM-DD`** marks a finding still under coordinated disclosure: identifiers, affected versions and fix status only until that date. Any claim about a current fix state carries the date it was checked.

## Licence

- **Code** — everything under `*/poc/` is [MIT](./LICENSE).
- **Write-ups and evidence** — the prose, analysis and screenshots are [CC BY 4.0](./LICENSE-docs).

Copyright © 2026 Lyris Vale ([@ValeLyris](https://github.com/ValeLyris)). Both licences require the attribution to stay with the material.
