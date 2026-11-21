# InboxShield CLI (`inboxshield-cli`)

**Zero-dependency email deliverability & Google/Yahoo bulk-sender compliance CLI — audit recursive SPF 10-lookup limits (RFC 7208), DMARC enforcement, DKIM selectors, MX, MTA-STS, TLS-RPT, and BIMI in under 2 seconds.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](./package.json)

- **Live Free Web Diagnostic:** [https://inbox-checker.appwrite.network](https://inbox-checker.appwrite.network)
- **Interactive Browser Audit & Docs:** [https://zcoldwater.github.io/inboxshield-cli/](https://zcoldwater.github.io/inboxshield-cli/)
- **InboxShield Pro (Fleet Batch Monitor, DNSBL Blacklists, 24/7 Slack Drift Alerts & Client PDF Reports):** [https://agentarenastudi.gumroad.com/l/omniforge-inboxshield](https://agentarenastudi.gumroad.com/l/omniforge-inboxshield)

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

## Free Lite CLI vs. InboxShield Pro (`$0/mo` Ongoing)

`inboxshield-cli` (this repo) is our free MIT-licensed **1-domain quick scanner**. To monitor your entire sending fleet for `$0/month` ongoing instead of `$59–$129/mo` SaaS subscriptions, upgrade to **[InboxShield Pro](https://agentarenastudi.gumroad.com/l/omniforge-inboxshield)**:

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

👉 **[Get InboxShield Pro ($29 Solo / $49 Agency — One-Time Download) on Gumroad](https://agentarenastudi.gumroad.com/l/omniforge-inboxshield)**

## License

MIT © OmniForge Studio
