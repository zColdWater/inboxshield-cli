# InboxShield CLI (`inboxshield-cli`)

**Zero-dependency email deliverability & Google/Yahoo bulk-sender compliance CLI — audit recursive SPF 10-lookup limits (RFC 7208), DMARC enforcement, DKIM selectors, MX, MTA-STS, TLS-RPT, and BIMI in under 2 seconds.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](./package.json)
[![Email Security](https://inbox-checker.appwrite.network/badge/inbox/stripe.com.svg)](https://inbox-checker.appwrite.network/?domain=stripe.com)
[![AI CiteReady](https://citeready-checker.appwrite.network/badge/citeready/zcoldwater.github.io.svg)](https://citeready-checker.appwrite.network/?url=https://zcoldwater.github.io/inboxshield-cli/)
[![BrandShield](https://brand-checker.appwrite.network/badge/brand/InboxShield.svg)](https://brand-checker.appwrite.network/report/InboxShield)

> **Add a live Email Security badge to your own README or footer:**
> `[![Email Security](https://inbox-checker.appwrite.network/badge/inbox/yourdomain.com.svg)](https://inbox-checker.appwrite.network/?domain=yourdomain.com)` — [Customize badge styles →](https://inbox-checker.appwrite.network/badge)

- **Live Free Web Diagnostic:** [https://inbox-checker.appwrite.network](https://inbox-checker.appwrite.network)
- **Free Online SPF Flattener (Fix >10-Lookup PermError):** [https://inbox-checker.appwrite.network/spf-flattener](https://inbox-checker.appwrite.network/spf-flattener)
- **Interactive Browser Audit & Docs:** [https://zcoldwater.github.io/inboxshield-cli/](https://zcoldwater.github.io/inboxshield-cli/)
- **2026 Comparison Guide (vs MxToolbox, EasyDMARC & GlockApps):** [https://zcoldwater.github.io/inboxshield-cli/mxtoolbox-easydmarc-alternative.html](https://zcoldwater.github.io/inboxshield-cli/mxtoolbox-easydmarc-alternative.html)
- **InboxShield Pro (Fleet Batch Monitor, SPF Flattener, DNSBL Blacklists, 24/7 Slack Drift Alerts & Client PDF Reports):** [https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield)
- **⚡ Instant Direct / Agent Checkout (24/7 Instant ZIP Download):** [https://omnipulse-x402.appwrite.network/checkout/inboxshield](https://omnipulse-x402.appwrite.network/checkout/inboxshield) | **3-in-1 Founder Launch Stack ($49/$89):** [https://omnipulse-x402.appwrite.network/checkout/launch-stack](https://omnipulse-x402.appwrite.network/checkout/launch-stack)


---

## Why Sending Domains Silently Drop Into Spam

1. **Silent SPF `>10` Lookup `PermError` (RFC 7208):** Adding one extra SaaS tool (`include:_spf.google.com`, `include:sendgrid.net`, `include:spf.protection.outlook.com`, HubSpot, Zendesk) pushes nested DNS lookups past **10**. Receivers immediately fail SPF with `PermError` — without warning you.
2. **Unenforced `p=none` DMARC:** Google, Yahoo, and Microsoft bulk-sender mandates penalize unauthenticated domains and require aligned SPF/DKIM + valid `_dmarc`.
3. **DNS Drift & Blacklists Across Client Fleets:** Agencies and outbound teams managing 10–200 domains pay `$59–$129/month` for basic DNS monitoring — or find out weeks too late after reply rates crash.

---

## Quick Start (Zero Install via `npx`)

Requires **Node.js 18+** (uses native `node:dns/promises`, zero external packages):

```bash
# Audit any sending domain in 1.5 seconds
npx github:zColdWater/inboxshield-cli check stripe.com

# Machine-readable JSON output for CI pipelines
npx github:zColdWater/inboxshield-cli check linear.app --json
```

---

## 1-Click GitHub Action (Free Automated CI Deliverability Gate)

Catch silent SPF `>10` lookup PermErrors or missing `_dmarc` records automatically on a daily schedule or pull request (`uses: zColdWater/inboxshield-cli@v1`):

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

Every run writes a clean Markdown audit table to your **GitHub Job Summary** and exposes `score`, `grade`, `spf-lookups`, and `dmarc-policy` step outputs. Need **20–500 domains** + Slack/Discord drift alerts + SPF flattening? Upgrade to **[InboxShield Pro](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield)** or **[Instant Checkout](https://omnipulse-x402.appwrite.network/checkout/inboxshield)**.

---

## Free Lite CLI vs. InboxShield Pro (`$0/mo` Ongoing)

`inboxshield-cli` (this repo) is our free MIT-licensed **1-domain quick scanner**. To monitor your entire sending fleet for `$0/month` ongoing instead of `$59–$129/mo` SaaS subscriptions, upgrade to **[InboxShield Pro](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield)**:

| Capability | InboxShield Lite (Free OSS) | InboxShield Pro Solo ($29) | InboxShield Pro Agency ($49) |
| :--- | :---: | :---: | :---: |
| **Recursive SPF 10-Lookup Walker** | 1 domain / run | **Unlimited domains** (CSV/TXT fleet) | **Unlimited client fleets** |
| **DKIM Selector & RSA Bit-Length Audit** | 8 common selectors | **18+ selectors + `<1024-bit` weak key detection** | **18+ selectors + custom client selectors** |
| **DMARC + Google/Yahoo Mandate Grader** | Policy & `rua` check | Full alignment + MTA-STS live policy fetch + BIMI | Full alignment + executive compliance matrix |
| **Live DNSBL Blacklist Screening** | — | **Spamhaus DBL, SURBL, Barracuda, SpamCop, SORBS** | **Domain + MX IP blacklist fleet scan** |
| **Copy-Paste DNS Remediation Records** | — | **Exact Cloudflare / Route53 / Namecheap TXT fixes** | **Client-ready remediation instructions** |
| **24/7 GitHub Actions + Slack/Discord Alerts** | — | **Included** (6-hour cron diff, `$0/mo` hosting) | **Included** (multi-client webhook routing) |
| **Local HTML Fleet Dashboard (`:3848`)** | — | **Included** | **Included** |
| **White-Label Client HTML/PDF Reports** | — | Solo / internal domains | **Commercial 10-seat license + `--brand` / `--client`** |

👉 **[Get InboxShield Pro ($29 Solo / $49 Agency — One-Time Download) on Gumroad](https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield)**

## License

MIT © OmniForge Studio
