#!/usr/bin/env node
/**
 * InboxShield CLI v7.0.0 — Zero-dependency 6-Phase Real Email DNS Protocol Auditor.
 * Uses Node.js built-in node:dns/promises (zero external npm packages):
 *   1. Authoritative NS Consistency (native vs DoH) & SOA Primary Verification
 *   2. MX Multi-Node Priority & Unique IPv4 Redundancy + ESP Auto-Detection
 *   3. Recursive SPF Lookup & Per-Layer IPv4/IPv6 CIDR Expansion (RFC 7208)
 *   4. 24-Selector DKIM Public Key & RSA Bit-Length Audit
 *   5. Strict RFC 7489 DMARC Tag Syntax Linter + Duplicate Record Detection
 *   6. MTA-STS, TLS-RPT, BIMI, CAA & 5-DNSBL Blacklist Screening
 *
 * Need instant copy-paste 5-registrar DNS fix records, auto-merged SPF flattening,
 * 50-domain online batch CSV & branded A4 PDF reports?
 *   Free Web Workbench: https://inbox-checker.appwrite.network
 *   Single-Domain Emergency Fix ($9 Once): https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield
 */

import { auditDomain } from "../src/dns-engine.mjs";

const VERSION = "7.0.0";
const WEB_SCANNER = "https://inbox-checker.appwrite.network";
const PRO_URL = "https://omnipulse-x402.appwrite.network/go/gumroad/inboxshield";
const STACK_URL = "https://omnipulse-x402.appwrite.network/go/gumroad/launch-stack";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = { domain: "", json: false, help: false, version: false };
  const pos = [];
  for (const a of args) {
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--json") opts.json = true;
    else pos.push(a);
  }
  if (pos[0] === "check" || pos[0] === "audit" || pos[0] === "scan") pos.shift();
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
${C.bold}${C.cyan}InboxShield CLI v${VERSION}${C.reset} — 6-Phase Real Email DNS Protocol Auditor (RFC 7208 / RFC 7489)

${C.bold}USAGE${C.reset}
  npx github:zColdWater/inboxshield-cli check <domain.com> [--json]

${C.bold}EXAMPLES${C.reset}
  npx github:zColdWater/inboxshield-cli check stripe.com
  npx github:zColdWater/inboxshield-cli check github.com --json

${C.bold}LIVE WEB DIAGNOSTIC & SINGLE-DOMAIN EMERGENCY FIX ($9 ONCE)${C.reset}
  Free 6-Phase Web Scanner:   ${WEB_SCANNER}
  Free Online SPF Flattener:  ${WEB_SCANNER}/spf-flattener
  Single-Domain Fix ($9):     ${PRO_URL}
  4-in-1 Launch Stack ($29):  ${STACK_URL}
`);
}

async function main() {
  const opts = parseArgs(process.argv);
  if (opts.version) {
    console.log(VERSION);
    return;
  }
  if (opts.help || !opts.domain) {
    printHelp();
    process.exit(opts.help ? 0 : 1);
  }

  let r;
  try {
    r = await auditDomain(opts.domain);
    if (!r || r.ok === false || !r.assessment) {
      throw new Error(r?.error || "Could not audit domain");
    }
  } catch (err) {
    console.error(`${C.red}Audit failed:${C.reset} ${err.message}`);
    process.exit(1);
  }

  const score = r.assessment?.score ?? 0;
  const grade = r.assessment?.grade || "-";
  const mxHosts = (r.mx?.records || []).map((m) => m.exchange || String(m));
  const dkimFound = (r.dkim?.found || []).map((d) => d.selector || String(d));
  const issues = [
    ...(r.spf?.issues || []),
    ...(r.dmarc?.issues || []),
    ...(r.dkim?.issues || []),
    ...(r.dnsMeta?.nsHealth?.issues || []),
    ...(r.mx?.redundancy?.issues || []),
  ];

  // Backward-compatible JSON contract for action.yml + full v7.0 fields
  const outObj = {
    version: VERSION,
    domain: r.domain,
    score,
    grade,
    status: r.assessment?.status || "CHECKED",
    elapsedMs: r.elapsedMs,
    provider: r.mx?.provider || "Unknown",
    mxCount: mxHosts.length,
    mxHosts,
    mxRedundancy: r.mx?.redundancy || null,
    spf: r.spf,
    dmarc: r.dmarc,
    dkimSelectorsChecked: r.dkim?.checkedCount || 24,
    dkimSelectorsFound: dkimFound,
    mtaSts: Boolean(r.advanced?.mtaSts?.present),
    tlsRpt: Boolean(r.advanced?.tlsRpt?.present),
    bimi: Boolean(r.advanced?.bimi?.present),
    nsHealth: r.dnsMeta?.nsHealth || null,
    blacklists: r.blacklists || null,
    issues,
    executionTrace: r.executionTrace || [],
  };

  if (opts.json) {
    console.log(JSON.stringify(outObj, null, 2));
    return;
  }

  const scCol = score >= 85 ? C.green : score >= 65 ? C.yellow : C.red;
  console.log(`\n${C.bold}InboxShield v${VERSION} — 6-Phase Email DNS Audit (${r.domain})${C.reset}`);
  console.log(`Score: ${scCol}${C.bold}${score}/100 (Grade ${grade})${C.reset} | Provider: ${outObj.provider} | Time: ${r.elapsedMs || 0}ms\n`);
  console.log(`  1. NS / SOA:       ${r.dnsMeta?.nsHealth?.count || 0} NS (${r.dnsMeta?.nsHealth?.distinctSubnets || 0} /16 subnets) | SOA Match: ${r.dnsMeta?.nsHealth?.soaMatchesNs ? "Yes" : "Check"}`);
  console.log(`  2. MX Redundancy:  ${mxHosts.length} host(s), ${r.mx?.redundancy?.uniqueIpv4Count ?? (r.mx?.ips || []).length} unique IPv4(s)`);
  console.log(`  3. SPF (RFC 7208): ${r.spf?.record ? `${r.spf.lookups}/10 lookups (${r.spf.ip4Count || 0} IPv4 + ${r.spf.ip6Count || 0} IPv6 CIDRs, ${r.spf.qualifier || "none"})` : "MISSING"}`);
  console.log(`  4. DKIM (24 chk):  ${dkimFound.length ? dkimFound.join(", ") : "None detected across 24 standard selectors"}`);
  console.log(`  5. DMARC (7489):   ${r.dmarc?.record ? `p=${r.dmarc.policy || "none"} (${(r.dmarc.syntaxErrors || []).length} syntax error(s))` : "MISSING"}`);
  console.log(`  6. Advanced:       MTA-STS=${outObj.mtaSts ? "Yes" : "No"} | TLS-RPT=${outObj.tlsRpt ? "Yes" : "No"} | BIMI=${outObj.bimi ? "Yes" : "No"}\n`);

  if (issues.length) {
    console.log(`${C.bold}Detected Issues (${issues.length}):${C.reset}`);
    for (const iss of issues.slice(0, 8)) console.log(`  - ${iss}`);
    console.log("");
  }

  console.log(`${C.cyan}Interactive 6-Phase Report:${C.reset} ${WEB_SCANNER}/?domain=${encodeURIComponent(r.domain)}`);
  console.log(`${C.cyan}Single-Domain Fix ($9):${C.reset}    ${PRO_URL}\n`);
}

main();
