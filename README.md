# InboxShield — Online Email Deliverability, SPF Flattener & DMARC Auditor (`v5.0` Web App + OSS CLI & GitHub Action)

**Audit SPF 10-lookup limits (RFC 7208), 24 DKIM selectors, DMARC enforcement, MX/ESP detection, MTA-STS, BIMI, and 5 DNSBL blacklists in under 2 seconds — directly in your browser with zero install, or in CI via `zColdWater/inboxshield-cli@v1`.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](./package.json)
[![Email Security](https://inbox-checker.appwrite.network/badge/inbox/stripe.com.svg)](https://inbox-checker.appwrite.network/?domain=stripe.com)
[![AI CiteReady](https://citeready-checker.appwrite.network/badge/citeready/zcoldwater.github.io.svg)](https://citeready-checker.appwrite.network/?url=https://zcoldwater.github.io/inboxshield-cli/)
[![BrandShield](https://brand-checker.appwrite.network/badge/brand/InboxShield.svg)](https://brand-checker.appwrite.network/report/InboxShield)

- **Flagship v5.0 Online Web App (Zero Signup, 2-Second Audit):** [https://inbox-checker.appwrite.network](https://inbox-checker.appwrite.network)
- **Free Online SPF Flattener (Collapse `>10`-Lookup PermError -> `1/10`):** [https://inbox-checker.appwrite.network/spf-flattener](https://inbox-checker.appwrite.network/spf-flattener)
- **Docs & EasyDMARC / MxToolbox Comparison:** [https://zcoldwater.github.io/inboxshield-cli/](https://zcoldwater.github.io/inboxshield-cli/) · [Comparison Guide](https://zcoldwater.github.io/inboxshield-cli/mxtoolbox-easydmarc-alternative.html)
- **InboxShield Web Pro ($15 One-Time — Instant In-Browser Unlock, 14-Day Refund):** [Gumroad Checkout](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield) · [Direct 7-Chain Checkout](https://omnipulse-x402.appwrite.network/checkout/inboxshield)
- **4-in-1 OmniForge Web Pro Suite ($29 One-Time — Unlocks VibeShield + BrandShield + CiteReady + InboxShield, Save $19):** [Gumroad Bundle](https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack) · [Direct Checkout](https://omnipulse-x402.appwrite.network/checkout/launch-stack)

---

## Why Sending Domains Silently Drop Into Spam

1. **Silent SPF `>10` Lookup `PermError` (RFC 7208):** Stacking `include:_spf.google.com`, `sendgrid.net`, `spf.protection.outlook.com`, HubSpot, or Zendesk quickly pushes recursive DNS lookups past **10**, causing instant SPF failure.
2. **Missing or Unenforced DMARC (`p=none`) & Weak DKIM Keys:** Google, Yahoo, and Microsoft bulk-sender requirements reject or spam-folder unaligned mail. InboxShield checks **24 standard DKIM selectors**, RSA bit strength, MX providers (Google Workspace, Microsoft 365, Tencent Exmail, Aliyun, Feishu, Resend, Fastmail), and **5 DNSBL blacklists** live.
3. **Zero Subscriptions & Zero CNAME Delegation:** InboxShield v5.0 is an on-demand diagnostic and DNS remediation workbench (`$15` one-time vs. `$432+/yr` hosted DMARC SaaS platforms) — no CNAME lock-in, no mandatory accounts.

---

## Free Online Web App vs. InboxShield Web Pro (`$15` One-Time)

Unlock Web Pro directly inside [inbox-checker.appwrite.network](https://inbox-checker.appwrite.network) with one-time payment (Gumroad or 7-chain USDT/USDC) and a **14-day refund guarantee**:

| Capability | Free Online Scanner & OSS CLI | InboxShield Web Pro ($15 Once) | 4-in-1 Web Pro Suite ($29 Once) |
| :--- | :---: | :---: | :---: |
| **Recursive SPF `<=10` Audit + Online Flattener** | Unlimited 1-by-1 | **Unlimited + TXT / BIND / Cloudflare JSON** | **All 4 v5.0 Web Apps Included** |
| **24-Selector DKIM, DMARC, MX & 5 DNSBLs** | Live scan + score | **Full breakdown & provider detection** | **InboxShield + VibeShield ($9)** |
| **5-Registrar DNS Fix Wizard** | Step 1 preview | **Unmasked Cloudflare, GoDaddy, Namecheap, Aliyun & DNSPod records** | **+ BrandShield Naming ($12)** |
| **Online Batch Scanner + Excel/CSV Export** | Preview 3 domains | **Up to 50 domains / batch + UTF-8 CSV** | **+ CiteReady AI Search ($12)** |
| **Printable A4 Client Deliverability PDF** | Summary only | **Custom-header A4 PDF (`@media print`)** | **Branded A4 PDF on all 4 apps** |

> **Honest Scope:** InboxShield is an on-demand live DNS diagnostic & copy-paste remediation workbench. It does not operate a hosted 24/7 inbound DMARC XML mailbox server (so you never have to delegate DNS or pay `$432+/yr`).

**[Unlock InboxShield Web Pro ($15 Once)](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield)** · **[Unlock 4-in-1 Suite ($29 Once — Save $19)](https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack)** · **[Direct Multi-Chain Checkout](https://omnipulse-x402.appwrite.network/checkout/inboxshield)**

---

## Optional Open-Source CLI & GitHub Action (`uses: zColdWater/inboxshield-cli@v1`)

Requires **Node.js 18+** (uses native `node:dns/promises`, zero external packages):

```bash
# Audit any sending domain in ~1.5 seconds
npx github:zColdWater/inboxshield-cli check stripe.com
npx github:zColdWater/inboxshield-cli check linear.app --json
```

```yaml
name: Email Deliverability Gate
on:
  schedule:
    - cron: "0 8 * * *"
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
      - uses: zColdWater/inboxshield-cli@v1
        with:
          domain: yourdomain.com
          min-score: "80"
          fail-on-spf-permerror: "true"
```

## Live Badge Embed

```markdown
[![Email Security](https://inbox-checker.appwrite.network/badge/inbox/yourdomain.com.svg)](https://inbox-checker.appwrite.network/?domain=yourdomain.com)
```

## Support & Contact

OmniForge · Agent Arena Studio — `agentarenastudio@proton.me` · [@agentarenastudi](https://x.com/agentarenastudi) · [Support Portal](https://omnipulse-x402.appwrite.network/support) · [14-Day Refund Policy](https://omnipulse-x402.appwrite.network/refund-policy)

## License

MIT © OmniForge · Agent Arena Studio
