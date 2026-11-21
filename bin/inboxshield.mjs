#!/usr/bin/env node
/**
 * InboxShield Lite CLI — Zero-dependency single-domain email deliverability scanner.
 * Walks recursive SPF DNS lookups (RFC 7208 10-lookup ceiling), inspects DMARC policy,
 * MX records, common DKIM selectors, MTA-STS, TLS-RPT, and BIMI.
 *
 * Need 200-domain fleet batch scanning, 18-selector DKIM RSA bit-length checks,
 * live Spamhaus/Barracuda DNSBL screening, 24/7 GitHub Actions + Slack drift alerts,
 * and white-label client PDF/HTML reports?
 * Upgrade to InboxShield Pro ($29 Solo / $49 Agency — one-time buy, $0/mo ongoing):
 *   https://agentarenastudi.gumroad.com/l/omniforge-inboxshield
 */
import dns from "node:dns/promises";

const WEB_SCANNER = "https://inbox-checker.appwrite.network";
const PRO_URL = "https://agentarenastudi.gumroad.com/l/omniforge-inboxshield";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

const QUICK_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "s1", "resend", "mail"];

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = { domain: "", json: false, help: false };
  const pos = [];
  for (const a of args) {
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "--json") opts.json = true;
    else pos.push(a);
  }
  if (pos[0] === "check" || pos[0] === "audit") pos.shift();
  opts.domain = (pos[0] || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/^.*@/, "");
  return opts;
}

function printHelp() {
  console.log(`
${C.bold}${C.cyan}InboxShield CLI (Lite v1.0.0)${C.reset} — SPF 10-Lookup, DMARC, DKIM & Deliverability Scanner

${C.bold}USAGE${C.reset}
  npx github:zColdWater/inboxshield-cli check <domain.com> [--json]

${C.bold}EXAMPLES${C.reset}
  npx github:zColdWater/inboxshield-cli check stripe.com
  npx github:zColdWater/inboxshield-cli check linear.app --json

${C.bold}FREE WEB DIAGNOSTIC${C.reset}
  ${WEB_SCANNER}

${C.bold}UPGRADE TO INBOXSHIELD PRO ($29 Solo / $49 Agency — $0/mo Ongoing)${C.reset}
  Unlimited sending-domain fleet CLI, 18-selector DKIM RSA bit-length audit,
  Spamhaus/Barracuda DNSBL screening, 24/7 GitHub Actions + Slack drift alerts,
  local HTML Fleet Dashboard & white-label client PDF/HTML audit reports:
  ${C.cyan}${PRO_URL}${C.reset}
`);
}

async function safeTxt(name) {
  try {
    const rows = await dns.resolveTxt(name);
    return rows.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

async function walkSpf(domain, visited = new Set(), depth = 0) {
  if (depth > 8 || visited.has(domain)) {
    return { lookups: 0, record: null, loop: visited.has(domain), includes: [] };
  }
  visited.add(domain);
  const txts = await safeTxt(domain);
  const spfList = txts.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  if (!spfList.length) return { lookups: 0, record: null, duplicate: false, includes: [] };

  const rec = spfList[0].trim();
  const tokens = rec.split(/\s+/).slice(1);
  let lookups = 0;
  const includes = [];
  let qualifier = "neutral";

  for (const tok of tokens) {
    const clean = tok.replace(/^[+\-~?]/, "");
    if (/^include:/i.test(clean)) {
      lookups += 1;
      const target = clean.slice(8).trim();
      if (target) {
        const sub = await walkSpf(target, visited, depth + 1);
        lookups += sub.lookups;
        includes.push({ target, subLookups: sub.lookups });
      }
    } else if (/^redirect=/i.test(clean)) {
      lookups += 1;
      const target = clean.slice(9).trim();
      if (target) {
        const sub = await walkSpf(target, visited, depth + 1);
        lookups += sub.lookups;
        includes.push({ target, redirect: true, subLookups: sub.lookups });
      }
    } else if (/^(a|mx|ptr|exists)(:|\/|$)/i.test(clean)) {
      lookups += 1;
    } else if (/^[+\-~?]?all$/i.test(tok)) {
      qualifier = tok.toLowerCase();
    }
  }

  return {
    record: rec,
    duplicate: spfList.length > 1,
    lookups,
    qualifier,
    includes,
  };
}

function parseTags(record) {
  const map = {};
  for (const part of String(record || "").split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0) {
      map[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
    }
  }
  return map;
}

async function auditDomain(domain) {
  const [mxRes, spf, dmarcTxts, mtaStsTxts, tlsRptTxts, bimiTxts, dkimHits] = await Promise.all([
    dns.resolveMx(domain).catch(() => []),
    walkSpf(domain),
    safeTxt(`_dmarc.${domain}`),
    safeTxt(`_mta-sts.${domain}`),
    safeTxt(`_smtp._tls.${domain}`),
    safeTxt(`default._bimi.${domain}`),
    Promise.all(
      QUICK_SELECTORS.map(async (sel) => {
        const recs = await safeTxt(`${sel}._domainkey.${domain}`);
        const hit = recs.find((r) => /p=[A-Za-z0-9+/]{16,}/.test(r) || /v=DKIM1/i.test(r));
        return hit ? sel : null;
      })
    ),
  ]);

  const dmarcRec = dmarcTxts.find((t) => /^v=DMARC1/i.test(t.trim())) || null;
  const dmarcTags = dmarcRec ? parseTags(dmarcRec) : {};
  const foundSelectors = dkimHits.filter(Boolean);

  let score = 0;
  const issues = [];

  if (mxRes.length > 0) score += 15;
  else issues.push("No MX records found for domain.");

  if (spf.record) {
    if (spf.duplicate) {
      issues.push("Multiple v=spf1 TXT records detected (causes RFC 7208 PermError).");
    } else if (spf.lookups > 10) {
      issues.push(`SPF exceeds RFC 7208 10-DNS-lookup limit (${spf.lookups}/10 -> silent PermError!).`);
      score += 5;
    } else {
      score += 25;
      if (spf.lookups >= 8) issues.push(`SPF lookup count is close to the 10-lookup ceiling (${spf.lookups}/10).`);
    }
    if (spf.qualifier === "+all" || spf.qualifier === "all") {
      issues.push("Dangerous +all in SPF allows anyone on the internet to spoof your domain!");
      score = Math.max(0, score - 20);
    } else if (spf.qualifier === "-all" || spf.qualifier === "~all") {
      score += 5;
    }
  } else {
    issues.push("Missing v=spf1 TXT record.");
  }

  if (dmarcRec) {
    const p = (dmarcTags.p || "none").toLowerCase();
    if (p === "reject") score += 30;
    else if (p === "quarantine") score += 25;
    else {
      score += 12;
      issues.push("DMARC policy is p=none (monitoring only — zero spoofing enforcement).");
    }
    if (dmarcTags.rua) score += 5;
    else issues.push("DMARC lacks rua= aggregate report destination.");
  } else {
    issues.push("Missing _dmarc TXT record (violates Google & Yahoo bulk-sender mandate).");
  }

  if (foundSelectors.length > 0) score += 10;
  else issues.push("No common public DKIM selector detected in quick 8-selector scan (Pro probes 18+ selectors & RSA key bits).");

  if (mtaStsTxts.some((t) => /v=STSv1/i.test(t))) score += 5;
  if (tlsRptTxts.some((t) => /v=TLSRPTv1/i.test(t))) score += 3;
  if (bimiTxts.some((t) => /v=BIMI1/i.test(t))) score += 2;

  score = Math.min(100, Math.max(0, score));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : "D";

  return {
    domain,
    checkedAt: new Date().toISOString(),
    score,
    grade,
    mxCount: mxRes.length,
    mxHosts: mxRes.sort((a, b) => a.priority - b.priority).slice(0, 4).map((m) => m.exchange),
    spf,
    dmarc: { record: dmarcRec, policy: dmarcTags.p || null, rua: dmarcTags.rua || null },
    dkimSelectorsFound: foundSelectors,
    mtaSts: mtaStsTxts.some((t) => /v=STSv1/i.test(t)),
    tlsRpt: tlsRptTxts.some((t) => /v=TLSRPTv1/i.test(t)),
    bimi: bimiTxts.some((t) => /v=BIMI1/i.test(t)),
    issues,
  };
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.domain) {
    printHelp();
    process.exit(opts.help ? 0 : 1);
  }

  if (opts.domain.includes(",")) {
    console.error(
      `${C.yellow}Note:${C.reset} InboxShield Lite audits 1 sending domain per run.\n` +
        `For 200-domain fleet scanning, DNSBL blacklist checks & 24/7 GitHub Actions drift alerts, get InboxShield Pro:\n` +
        `  ${C.cyan}${PRO_URL}${C.reset}\n`
    );
    opts.domain = opts.domain.split(",")[0].trim();
  }

  const r = await auditDomain(opts.domain);
  if (opts.json) {
    console.log(JSON.stringify(r, null, 2));
    return;
  }

  const scoreColor = r.score >= 80 ? C.green : r.score >= 55 ? C.yellow : C.red;
  console.log(`\n${C.bold}InboxShield Deliverability Audit — ${r.domain}${C.reset}`);
  console.log(`Health Score: ${scoreColor}${C.bold}${r.score}/100 (Grade ${r.grade})${C.reset}\n`);

  console.log(
    `  MX Servers       ${r.mxCount > 0 ? `${C.green}✔ ${r.mxCount} host(s)${C.reset} ${C.dim}(${r.mxHosts.join(", ")})${C.reset}` : `${C.red}✖ Missing${C.reset}`}`
  );
  if (!r.spf.record) {
    console.log(`  SPF (RFC 7208)   ${C.red}✖ Missing v=spf1 record${C.reset}`);
  } else {
    const lColor = r.spf.lookups > 10 ? C.red : r.spf.lookups >= 8 ? C.yellow : C.green;
    console.log(
      `  SPF (RFC 7208)   ${lColor}${r.spf.lookups > 10 ? "✖ PermError" : "✔ Valid"} (${r.spf.lookups}/10 DNS lookups, ${r.spf.qualifier})${C.reset}`
    );
  }
  console.log(
    `  DMARC Policy     ${
      r.dmarc.record
        ? r.dmarc.policy === "reject" || r.dmarc.policy === "quarantine"
          ? `${C.green}✔ p=${r.dmarc.policy}${C.reset}`
          : `${C.yellow}⚠ p=${r.dmarc.policy || "none"} (unprotected)${C.reset}`
        : `${C.red}✖ Missing _dmarc${C.reset}`
    }`
  );
  console.log(
    `  DKIM (Quick 8)   ${
      r.dkimSelectorsFound.length
        ? `${C.green}✔ Active selector(s): ${r.dkimSelectorsFound.join(", ")}${C.reset}`
        : `${C.yellow}? None in quick-8 list (use Pro for 18-selector + RSA bit check)${C.reset}`
    }`
  );
  console.log(
    `  Transport/Brand  MTA-STS: ${r.mtaSts ? `${C.green}✔${C.reset}` : `${C.dim}—${C.reset}`}  |  TLS-RPT: ${
      r.tlsRpt ? `${C.green}✔${C.reset}` : `${C.dim}—${C.reset}`
    }  |  BIMI: ${r.bimi ? `${C.green}✔${C.reset}` : `${C.dim}—${C.reset}`}`
  );

  if (r.issues.length) {
    console.log(`\n${C.bold}Actionable Findings:${C.reset}`);
    for (const iss of r.issues) {
      console.log(`  ${C.yellow}•${C.reset} ${iss}`);
    }
  }

  console.log(
    `\n${C.bold}${C.magenta}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}\n` +
      `${C.bold}Stop paying $59–$129/mo to monitor your sending domains.${C.reset}\n` +
      `Upgrade to ${C.bold}InboxShield Pro${C.reset} ($29 Solo / $49 Agency — one-time buy, $0/mo ongoing):\n` +
      `  • Batch-audit unlimited sending domains + Spamhaus/Barracuda/SpamCop DNSBL checks\n` +
      `  • 18-selector DKIM RSA bit-length audit + copy-paste Cloudflare/Route53 TXT fixes\n` +
      `  • Free 24/7 GitHub Actions + Slack/Discord DNS-drift alerts & White-Label PDF reports\n` +
      `  👉 ${C.bold}${C.cyan}${PRO_URL}${C.reset}\n` +
      `  🌐 Free web diagnostic: ${C.cyan}${WEB_SCANNER}${C.reset}\n` +
      `${C.bold}${C.magenta}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}\n`
  );
}

main();
