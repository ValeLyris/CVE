# PeproDev WooCommerce Receipt Uploader ≤ 2.8.0 — unauthenticated order-receipt tampering

|  |  |
|---|---|
| **CVE ID** | [CVE-2026-14313](https://www.cve.org/CVERecord?id=CVE-2026-14313) — assigned by the WPScan CNA, not yet published on cve.org as of 2026-07-23 |
| **Advisory** | [WPScan entry](https://wpscan.com/vulnerability/61d6aab4-7753-4a86-8b7e-81daa61654e8) (published 2026-07-22) |
| **Product** | WordPress · [PeproDev WooCommerce Receipt Uploader](https://wordpress.org/plugins/pepro-bacs-receipt-upload-for-woocommerce/) (`pepro-bacs-receipt-upload-for-woocommerce`) |
| **Type** | CWE-639 — Authorization Bypass Through User-Controlled Key; CWE-862 — Missing Authorization |
| **Affected** | `<= 2.8.0` (every released version) |
| **Fixed in** | No fix as of 2026-07-23 |
| **Severity** | Medium — CVSS 3.1 **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`), as published by WPScan |
| **Disclosed** | 2026-07-22 (WPScan) |
| **Reporter** | Lyris Vale ([@ValeLyris](https://github.com/ValeLyris)) |

> [!WARNING]
> **No vendor fix as of 2026-07-23, and the plugin has been closed on wordpress.org.** The latest release is `2.8.0` and it is affected. wordpress.org closed the plugin on 2026-07-21 pending a full review, so it can no longer be downloaded or updated from the directory — an installation already on a site stays installed, and stays affected. Until a fixed release appears the realistic choices are to deactivate and remove it, or to carry the risk knowingly.
>
> Technical detail and proof of concept are held under coordinated disclosure until **2026-08-12**. Until then this page carries the assigned CVE and public metadata only.

## Summary

An **unauthenticated** insecure-direct-object-reference / missing-authorisation flaw in PeproDev WooCommerce Receipt Uploader, in every release up to and including `2.8.0`, lets an attacker tamper with order receipts belonging to other customers. No authentication is required.

Exploitation detail is withheld until the disclosure date above.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-07-01 | Reported to WPScan (CNA); review started the same day. |
| 2026-07-21 | Plugin closed on wordpress.org, pending a full review. |
| 2026-07-22 | Published by WPScan. |
| 2026-07-23 | No fix shipped; latest release still `2.8.0`. |
| 2026-08-12 | Full write-up and proof of concept to be published here. |

## References

- [WPScan entry](https://wpscan.com/vulnerability/61d6aab4-7753-4a86-8b7e-81daa61654e8) — authoritative while the CVE record is pending
- [CVE-2026-14313](https://www.cve.org/CVERecord?id=CVE-2026-14313)
- [Plugin on wordpress.org](https://wordpress.org/plugins/pepro-bacs-receipt-upload-for-woocommerce/) — currently closed

---
[← All advisories](../README.md) · Lyris Vale ([@ValeLyris](https://github.com/ValeLyris))
