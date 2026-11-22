# 2026 Indie SaaS Email Deliverability Benchmark (60 Custom Domains Audited)

**Passive Public DNS Study using [InboxShield v7.0](https://inbox-checker.appwrite.network/)**

- **Audit Date:** 2026-11-22
- **Sample Size:** **60 live custom domains** of recently active public GitHub indie SaaS & AI web app repositories (`.com`, `.dev`, `.io`, `.ai`, `.app`, `.xyz`, `.org`, `.tech`)
- **Methodology:** 100% passive public DNS queries (`NS`/`SOA`, `MX` redundancy, recursive `SPF` RFC 7208 lookup & IPv4/IPv6 CIDR expansion, 24-selector `DKIM`, strict RFC 7489 `DMARC` syntax linter, `MTA-STS`, `TLS-RPT`, `BIMI`). Strictly anonymized aggregate statistics — zero HTTP probing, zero naming-and-shaming.

---

## Executive Findings

| Metric | Affected Domains | Percentage (N = 60) | Deliverability Impact |
| :--- | :---: | :---: | :--- |
| **Average Deliverability Score** | **60.3 / 100** | — | 53.3% score below 70/100; 66.7% below 85/100 |
| **No Enforced DMARC (`missing` or `p=none`)** | **43 / 60** | **71.7%** | Vulnerable to domain spoofing & Gmail/Yahoo bulk-sender spam filtering |
| **Completely Missing `_dmarc` TXT Record** | **21 / 60** | **35.0%** | Fails Google, Yahoo & Microsoft 2024–2026 sender requirements |
| **DMARC Stuck on Monitor-Only (`p=none`)** | **22 / 60** | **36.7%** | Zero spoofing enforcement; attackers can send as `ceo@yourdomain` |
| **Missing `v=spf1` Record Entirely** | **20 / 60** | **33.3%** | Transactional password resets & onboarding emails risk spam folder |
| **No Active DKIM Selector (24 Standard Selectors)** | **27 / 60** | **45.0%** | Unauthenticated mail headers fail alignment checks |
| **Duplicate Conflicting SPF or RFC 7489 DMARC Syntax Errors** | **2 / 60** | **3.3%** | Triggers silent RFC 7208 `PermError` or malformed policy fallback |
| **SPF Near Hard Limit (8–10 Recursive Lookups)** | **1 / 60** | **1.7%** | Adding a single SaaS tool (HubSpot/Zendesk/SendGrid) breaks SPF |
| **Missing MTA-STS & TLS-RPT** | **60 / 60** | **100.0%** | No enforced TLS encryption policy for inbound SMTP transport |
| **Missing BIMI Brand Logo Record** | **59 / 60** | **98.3%** | Missed verified brand logo trust signal in Gmail/Apple Mail inboxes |

---

## Real Indie SaaS Mail Provider Mix (N = 60)

| Detected Mail / MX Setup | Count | Share |
| :--- | :---: | :---: |
| **No MX Configured (Replies Dropped!)** | 18 | 30.0% |
| **Cloudflare Email Routing** | 13 | 21.7% |
| **Google Workspace** | 12 | 20.0% |
| **Custom / Self-Hosted Mail Server** | 11 | 18.3% |
| **Zoho Mail** | 2 | 3.3% |
| **Microsoft 365** | 2 | 3.3% |
| **Tencent Exmail / QQ Mail** | 1 | 1.7% |
| **Feishu / Lark Mail** | 1 | 1.7% |

---

## Deliverability by TLD Cohort

| TLD | Domains | Average Score | Missing DMARC |
| :--- | :---: | :---: | :---: |
| `.com` | 28 | 58.5 / 100 | 32.1% |
| `.dev` | 7 | 54.4 / 100 | 57.1% |
| `.io` | 5 | 69.8 / 100 | 40.0% |
| `.ai` | 5 | 68.8 / 100 | 20.0% |
| `.app` | 4 | 69.5 / 100 | 0.0% |
| `.xyz` | 4 | 60.5 / 100 | 25.0% |
| `.org` | 2 | 33.0 / 100 | 100.0% |
| `.tech` | 2 | 46.0 / 100 | 50.0% |

---

## How to Fix Your Own Domain in 3 Minutes

1. **Run a Free 6-Phase Live Audit:** Check your exact NS/SOA, MX redundancy, SPF CIDR layers, 24 DKIM selectors, and strict RFC 7489 DMARC syntax at **[inbox-checker.appwrite.network](https://inbox-checker.appwrite.network/)**.
2. **Collapse `>10` SPF Lookups Free:** Use the free online **[SPF Flattener](https://inbox-checker.appwrite.network/spf-flattener)** to resolve nested `include:` chains before they hit RFC 7208 `PermError`.
3. **Unlock Copy-Paste 5-Registrar DNS Records ($2 Launch Special, reg. $9, $0/mo):** Get merged SPF, enforced DMARC (`p=quarantine` -> `p=reject`), active DKIM host alignment, MTA-STS, and TLS-RPT formatted for Cloudflare, GoDaddy, Namecheap, Aliyun, and DNSPod — **[Unlock Single-Domain Emergency Fix ($2 Launch Special)](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield)** (vs. `$432+/yr` DMARC SaaS subscriptions).
4. **Also Launching a Web App?** Run a free 6-phase secret, Supabase RLS, Firebase, and CSP audit on **[VibeShield v7.0](https://vibe-checker.appwrite.network/)** or check 78 TLDs + 17 aftermarket marketplaces free on **[BrandShield v6.2](https://brand-checker.appwrite.network/)**.
