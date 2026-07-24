# Security Advisories & CVEs — Lyris Vale

Vulnerabilities I've discovered and disclosed through coordinated disclosure. Each entry has a full writeup, a reproducible proof of concept, and links to the upstream advisory and — once assigned — the CVE record.

CVE identifiers are added as the relevant CNA assigns them. Entries that have been reported and fixed but not yet numbered are marked **CVE pending**.

## Index

| # | Identifier | Product | Type | Severity | Status | Details |
|---|------------|---------|------|----------|--------|---------|
| 1 | **CVE pending** · [GHSA-wj85-328x-ww6r](https://github.com/ZoeyVid/NPMplus/security/advisories/GHSA-wj85-328x-ww6r) | [ZoeyVid/NPMplus](https://github.com/ZoeyVid/NPMplus) | Unauthenticated path traversal (CWE-22) | Critical | Fixed in `2026-07-23-r1`; CVE requested | [→](./NPMplus-nginx-alias-path-traversal/) |

## Disclosure approach

I report privately to maintainers first and hold public detail until a fix is available (or up to 90 days, whichever comes first). Everything published here covers already-patched, already-public issues. Proof-of-concept code is for reproducing the finding against an instance you own.

---

Maintained by Lyris Vale · GitHub [@ValeLyris](https://github.com/ValeLyris)
