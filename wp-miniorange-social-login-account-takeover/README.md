# miniOrange Social Login and Register < 7.8.0 — unauthenticated account takeover

|  |  |
|---|---|
| **CVE ID** | [CVE-2026-14300](https://www.cve.org/CVERecord?id=CVE-2026-14300) — assigned by the WPScan CNA, not yet published on cve.org as of 2026-07-23 |
| **Advisory** | [WPScan entry](https://wpscan.com/vulnerability/7ecf657b-b059-4420-8c36-f38d58960d2b) (published 2026-07-08) |
| **Product** | WordPress · [miniOrange Social Login and Register](https://wordpress.org/plugins/miniorange-login-openid/) (`miniorange-login-openid`) |
| **Type** | CWE-287 — Improper Authentication |
| **Affected** | `< 7.8.0` |
| **Fixed in** | `7.8.0` |
| **Severity** | High — CVSS 3.1 **8.1** (`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`), as published by WPScan |
| **Disclosed** | 2026-07-08 (WPScan) |
| **Reporter** | Lyris Vale ([@ValeLyris](https://github.com/ValeLyris)) |

> [!IMPORTANT]
> **Held under coordinated disclosure.** Technical detail and proof of concept are embargoed until **2026-08-08**. Until then this page carries the assigned CVE and public metadata only.

## Summary

An authentication-bypass flaw in miniOrange Social Login and Register before `7.8.0` lets an **unauthenticated** attacker take over existing user accounts on an affected site.

Update to `7.8.0` or later. Exploitation detail is withheld until the disclosure date above.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-07-01 | Reported to WPScan (CNA); review started the same day. |
| 2026-07-08 | Published by WPScan. |
| 2026-08-08 | Full write-up and proof of concept to be published here. |

## References

- [WPScan entry](https://wpscan.com/vulnerability/7ecf657b-b059-4420-8c36-f38d58960d2b) — authoritative while the CVE record is pending
- [CVE-2026-14300](https://www.cve.org/CVERecord?id=CVE-2026-14300)
- [Plugin on wordpress.org](https://wordpress.org/plugins/miniorange-login-openid/)

---
[← All advisories](../README.md) · Lyris Vale ([@ValeLyris](https://github.com/ValeLyris))
