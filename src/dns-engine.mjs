// InboxShield — Authoritative Global & China Enterprise Email Deliverability Engine (v2.0)
// Zero dependencies. Node 20+ native DNS + Cloudflare DoH fallback.
// Supports automatic www. stripping & apex root fallback, Chinese enterprise mail providers
// (Tencent Exmail, Alibaba Enterprise Mail, Feishu/Lark Mail, NetEase 163), and full EN/ZH structured diagnostics.

import dns from "node:dns/promises";

export const COMMON_DKIM_SELECTORS = [
  "google",
  "selector1",
  "selector2",
  "s1",
  "s2",
  "k1",
  "k2",
  "resend",
  "mailgun",
  "mandrill",
  "pm",
  "dkim",
  "default",
  "zoho",
  "protonmail",
  "smtp",
  "mail",
  "mx",
  "qmail",
  "tencent",
  "aliyun",
  "feishu",
  "netease",
  "dkim2048",
];

// Two-level public suffixes so stripping www. or falling back to root never strips too far (e.g. qq.com.cn -> qq.com.cn)
const MULTI_LABEL_TLDS = new Set([
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "com.hk", "com.tw", "org.tw", "co.uk", "org.uk", "ac.uk",
  "co.jp", "ne.jp", "or.jp", "com.au", "com.sg", "co.kr", "com.br", "com.mx", "co.in",
]);

const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

export function normalizeDomain(raw) {
  return String(raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^.*@/, "")
    .split(/[/?#:\s]/)[0]
    .replace(/\.+$/, "");
}

export function getApexDomain(host) {
  const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_LABEL_TLDS.has(lastTwo)) {
    return parts.length > 3 ? parts.slice(-3).join(".") : parts.join(".");
  }
  return lastTwo;
}

export function stripLeadingWww(host) {
  const clean = normalizeDomain(host);
  if (!clean) return { domain: "", requestedDomain: "", autoStrippedWww: false };
  const apex = getApexDomain(clean);
  if (/^(?:www|m|web)\./.test(clean) && clean !== apex) {
    const stripped = clean.replace(/^(?:www|m|web)\./, "");
    if (stripped.includes(".")) {
      return { domain: stripped, requestedDomain: clean, autoStrippedWww: true };
    }
  }
  return { domain: clean, requestedDomain: clean, autoStrippedWww: false };
}

function withTimeout(promise, ms, fallbackValue) {
  return Promise.race([
    promise,
    new Promise((resolve) => setTimeout(() => resolve(fallbackValue), ms)),
  ]);
}

async function dohResolve(name, type) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 1600);
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      { headers: { accept: "application/dns-json" }, signal: ctl.signal }
    );
    if (!r.ok) return [];
    const j = await r.json();
    if (!Array.isArray(j.Answer)) return [];
    return j.Answer.map((a) => String(a.data || "").replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
  } catch {
    return [];
  } finally {
    clearTimeout(t);
  }
}

export async function resolveTxt(domain) {
  try {
    const rows = await withTimeout(dns.resolveTxt(domain), 1500, null);
    if (rows === null) return dohResolve(domain, "TXT");
    return rows.map((parts) => parts.join(""));
  } catch (e) {
    if (e.code === "ENOTFOUND" || e.code === "ENODATA") return [];
    return dohResolve(domain, "TXT");
  }
}

export async function resolveMx(domain) {
  try {
    const rows = await withTimeout(dns.resolveMx(domain), 1500, null);
    if (rows !== null) return rows.sort((a, b) => a.priority - b.priority);
  } catch (e) {
    if (e.code === "ENOTFOUND" || e.code === "ENODATA") return [];
  }
  const raw = await dohResolve(domain, "MX");
  return raw
    .map((line) => {
      const [prio, exch] = line.split(/\s+/);
      return { priority: Number(prio) || 10, exchange: String(exch || "").replace(/\.$/, "") };
    })
    .filter((x) => x.exchange)
    .sort((a, b) => a.priority - b.priority);
}

export async function resolveA(host, { dohFallback = false } = {}) {
  try {
    const rows = await withTimeout(dns.resolve4(host), 1300, null);
    if (Array.isArray(rows) && rows.length > 0) return rows;
  } catch (e) {
    if (e.code === "ENOTFOUND" || e.code === "ENODATA") return [];
  }
  if (!dohFallback) return [];
  const raw = await dohResolve(host, "A");
  return raw.filter((ip) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip));
}

export async function resolveNs(domain) {
  try {
    const rows = await withTimeout(dns.resolveNs(domain), 1400, null);
    if (Array.isArray(rows)) return rows.map((x) => String(x || "").replace(/\.$/, "").toLowerCase()).filter(Boolean);
  } catch (e) {
    if (e.code === "ENOTFOUND" || e.code === "ENODATA") return [];
  }
  const raw = await dohResolve(domain, "NS");
  return raw.map((x) => String(x || "").replace(/\.$/, "").toLowerCase()).filter(Boolean);
}

export async function resolveSoa(domain) {
  try {
    const soa = await withTimeout(dns.resolveSoa(domain), 1300, null);
    if (soa && soa.nsname) {
      return {
        nsname: String(soa.nsname).replace(/\.$/, "").toLowerCase(),
        hostmaster: String(soa.hostmaster || "").replace(/\.$/, "").toLowerCase(),
        serial: Number(soa.serial || 0),
        refresh: Number(soa.refresh || 0),
        retry: Number(soa.retry || 0),
        expire: Number(soa.expire || 0),
        minttl: Number(soa.minttl || 0),
      };
    }
  } catch {}
  const raw = await dohResolve(domain, "SOA");
  if (raw.length) {
    const parts = String(raw[0]).trim().split(/\s+/);
    if (parts.length >= 7) {
      return {
        nsname: parts[0].replace(/\.$/, "").toLowerCase(),
        hostmaster: parts[1].replace(/\.$/, "").toLowerCase(),
        serial: Number(parts[2] || 0),
        refresh: Number(parts[3] || 0),
        retry: Number(parts[4] || 0),
        expire: Number(parts[5] || 0),
        minttl: Number(parts[6] || 0),
      };
    }
  }
  return null;
}

export async function checkNsConsistency(domain, nativeNs = []) {
  const [dohNsRaw, soa] = await Promise.all([dohResolve(domain, "NS"), resolveSoa(domain)]);
  const dohNs = dohNsRaw.map((x) => String(x || "").replace(/\.$/, "").toLowerCase()).filter(Boolean);
  const nsSet = [...new Set([...(nativeNs || []), ...dohNs])];
  const nativeSorted = [...new Set(nativeNs || [])].sort();
  const dohSorted = [...new Set(dohNs)].sort();

  const resolvedNodes = await Promise.all(
    nsSet.slice(0, 12).map(async (host) => {
      const ips = await resolveA(host, { dohFallback: true });
      return { host, ips, resolvable: ips.length > 0 };
    })
  );

  const subnets = new Set();
  for (const n of resolvedNodes) {
    for (const ip of n.ips) {
      const p = ip.split(".");
      if (p.length === 4) subnets.add(`${p[0]}.${p[1]}`);
    }
  }

  const issues = [];
  const issuesZh = [];
  const resolverDiff = [];
  if (nativeSorted.length && dohSorted.length) {
    const natOnly = nativeSorted.filter((x) => !dohSorted.includes(x));
    const dohOnly = dohSorted.filter((x) => !nativeSorted.includes(x));
    if (natOnly.length || dohOnly.length) {
      resolverDiff.push(...natOnly.map((x) => `local-only:${x}`), ...dohOnly.map((x) => `doh-only:${x}`));
      issues.push(`Authoritative NS delegation differs between local resolver and Cloudflare 1.1.1.1 (${resolverDiff.slice(0, 3).join(", ")}).`);
      issuesZh.push(`权威 NS 记录在本地解析与 Cloudflare 1.1.1.1 间存在不一致（${resolverDiff.slice(0, 3).join("、")}），可能引发全球解析漂移。`);
    }
  }

  if (nsSet.length === 0) {
    issues.push("No authoritative NS records found — domain DNS delegation may be broken.");
    issuesZh.push("未解析到权威 NS 记录，域名 DNS 授权可能异常。");
  } else if (nsSet.length < 2) {
    issues.push(`Only ${nsSet.length} authoritative NS server found — RFC 2182 requires >= 2 redundant nameservers.`);
    issuesZh.push(`仅检测到 ${nsSet.length} 台权威 NS 服务器（RFC 2182 要求至少 2 台冗余节点），存在单点中断风险。`);
  }

  const brokenNs = resolvedNodes.filter((n) => !n.resolvable);
  if (brokenNs.length > 0) {
    issues.push(`Unresolvable NS glue detected: ${brokenNs.map((b) => b.host).join(", ")}.`);
    issuesZh.push(`检测到无法解析 IP 的失效 NS 节点：${brokenNs.map((b) => b.host).join("、")}。`);
  }

  const soaInNs = !soa || nsSet.length === 0 || nsSet.includes(soa.nsname);
  if (soa && nsSet.length > 0 && !soaInNs) {
    issues.push(`SOA primary nameserver (${soa.nsname}) is not listed in the authoritative NS delegation set.`);
    issuesZh.push(`SOA 主名称服务器（${soa.nsname}）未出现在权威 NS 列表中，建议核对权威区文件一致性。`);
  }

  const consistent = resolverDiff.length === 0 && brokenNs.length === 0 && soaInNs;
  const redundant = nsSet.length >= 2 && resolvedNodes.filter((n) => n.resolvable).length >= 2;
  const status = nsSet.length === 0 || brokenNs.length > 0 ? "fail" : (!redundant || !consistent) ? "warn" : "pass";

  return {
    count: nsSet.length,
    redundant,
    consistent,
    resolvedCount: resolvedNodes.filter((n) => n.resolvable).length,
    distinctSubnets: subnets.size,
    soa,
    soaMatchesNs: soaInNs,
    resolverDiff,
    nodes: resolvedNodes,
    status,
    issues,
    issuesZh,
  };
}

export async function checkMxRedundancy(mxRecords = []) {
  const list = Array.isArray(mxRecords) ? mxRecords : [];
  const nullMx = list.length === 1 && list[0].priority === 0 && (!list[0].exchange || list[0].exchange === ".");
  if (nullMx) {
    return {
      nodeCount: 1,
      resolvableCount: 0,
      uniqueIpCount: 0,
      priorityTiers: [0],
      hasBackupTier: false,
      nullMx: true,
      status: "warn",
      nodes: [{ priority: 0, exchange: ".", ips: [], resolvable: false, isNullMx: true }],
      issues: ["Null MX (0 .) published (RFC 7505) — domain explicitly refuses inbound email."],
      issuesZh: ["该域名配置了 Null MX（0 .），按 RFC 7505 声明明确拒绝接收任何入站邮件。"],
    };
  }

  const nodes = await Promise.all(
    list.slice(0, 6).map(async (m) => {
      const ips = m.exchange ? await resolveA(m.exchange, { dohFallback: true }) : [];
      const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(String(m.exchange || ""));
      return { priority: m.priority, exchange: m.exchange, ips, resolvable: ips.length > 0, isIpLiteral, isNullMx: false };
    })
  );

  const uniqueIps = new Set();
  for (const n of nodes) for (const ip of n.ips) uniqueIps.add(ip);
  const priorityTiers = [...new Set(list.map((m) => Number(m.priority)))].sort((a, b) => a - b);
  const resolvableCount = nodes.filter((n) => n.resolvable).length;
  const broken = nodes.filter((n) => !n.resolvable);
  const ipLiterals = nodes.filter((n) => n.isIpLiteral);
  const issues = [];
  const issuesZh = [];

  if (list.length === 0) {
    issues.push("No MX records configured — domain cannot receive replies or bounce reports.");
    issuesZh.push("未配置任何 MX 收信记录，无法接收客户回信或退信通知。");
  } else {
    if (broken.length > 0) {
      issues.push(`Unresolvable MX target(s): ${broken.map((b) => b.exchange).join(", ")} (missing A record).`);
      issuesZh.push(`存在无法解析 IP 的失效 MX 主机：${broken.map((b) => b.exchange).join("、")}。`);
    }
    if (ipLiterals.length > 0) {
      issues.push("RFC 5321 violation: MX record points directly to an IP address instead of a hostname.");
      issuesZh.push("违反 RFC 5321：MX 记录直接填写了 IP 地址，必须指向有效主机域名。");
    }
    if (list.length === 1 && uniqueIps.size <= 1) {
      issues.push("Single MX node pointing to 1 IP — no failover redundancy if primary mail host goes offline.");
      issuesZh.push("仅配置 1 条 MX 记录且仅指向单个 IP，主收信节点故障时无备用冗余。");
    } else if (list.length > 1 && uniqueIps.size === 1) {
      issues.push(`All ${list.length} MX records resolve to the same single IP (${[...uniqueIps][0]}) — false redundancy.`);
      issuesZh.push(`全部 ${list.length} 条 MX 记录均指向同一 IP（${[...uniqueIps][0]}），未形成真实多节点冗余。`);
    }
  }

  const hasBackupTier = priorityTiers.length >= 2 || uniqueIps.size >= 2;
  const status = list.length === 0 || broken.length > 0 || ipLiterals.length > 0 ? "fail" : (issues.length > 0 ? "warn" : "pass");
  return {
    nodeCount: list.length,
    resolvableCount,
    uniqueIpCount: uniqueIps.size,
    priorityTiers,
    hasBackupTier,
    nullMx: false,
    status,
    nodes,
    issues,
    issuesZh,
  };
}

export async function resolveCaa(domain) {
  try {
    const rows = await withTimeout(dns.resolveCaa(domain), 1400, null);
    if (Array.isArray(rows)) {
      return rows.map((r) => {
        const tag = r.issue ? "issue" : r.issuewild ? "issuewild" : r.iodef ? "iodef" : Object.keys(r).find((k) => k !== "critical") || "issue";
        return { critical: Number(r.critical || 0), tag, value: String(r[tag] || "") };
      }).filter((r) => r.value);
    }
  } catch (e) {
    if (e.code === "ENOTFOUND" || e.code === "ENODATA") return [];
  }
  const raw = await dohResolve(domain, "CAA");
  return raw
    .map((line) => {
      const m = String(line || "").match(/^(\d+)\s+(\w+)\s+"?([^"]+)"?$/);
      if (!m) return null;
      return { critical: Number(m[1] || 0), tag: m[2].toLowerCase(), value: m[3] };
    })
    .filter(Boolean);
}

export function detectDnsHost(nsRecords = []) {
  const joined = (nsRecords || []).join(" ").toLowerCase();
  if (!joined) return { id: "unknown", name: "Unknown / Unresolved" };
  if (joined.includes("cloudflare.com")) return { id: "cloudflare", name: "Cloudflare DNS" };
  if (joined.includes("domaincontrol.com")) return { id: "godaddy", name: "GoDaddy DNS" };
  if (joined.includes("registrar-servers.com") || joined.includes("namecheap")) return { id: "namecheap", name: "Namecheap DNS" };
  if (joined.includes("alidns.com") || joined.includes("hichina.com") || joined.includes("aliyun")) return { id: "aliyun", name: "Alibaba Cloud DNS" };
  if (joined.includes("dnspod.net") || joined.includes("dnsv")) return { id: "dnspod", name: "Tencent Cloud DNSPod" };
  if (joined.includes("awsdns")) return { id: "route53", name: "AWS Route 53" };
  if (joined.includes("nsone.net")) return { id: "ns1", name: "NS1 / IBM DNS" };
  if (joined.includes("googledomains.com") || joined.includes("google.com")) return { id: "gcp", name: "Google Cloud DNS" };
  if (joined.includes("azure-dns")) return { id: "azure", name: "Azure DNS" };
  if (joined.includes("vercel-dns.com")) return { id: "vercel", name: "Vercel DNS" };
  return { id: "custom", name: nsRecords[0] || "Authoritative DNS" };
}

// ------------------------------------------------------------------ Typo & Alternate-TLD Hint Engine (incl. .info, .xyz, etc.)
const POPULAR_DOMAINS = [
  "gmail.com", "google.com", "stripe.com", "github.com", "binance.com", "resend.com",
  "baidu.com", "apple.com", "microsoft.com", "outlook.com", "paypal.com", "amazon.com",
  "cloudflare.com", "shopify.com", "vercel.com", "linear.app", "supabase.com", "notion.so",
  "slack.com", "openai.com", "qq.com", "163.com", "aliyun.com", "feishu.cn", "cnn.com",
  "yahoo.com", "hotmail.com", "proton.me", "hubspot.com", "sendgrid.net", "mailgun.com",
];

const TLD_TYPOS = {
  cmo: "com", con: "com", ocm: "com", comm: "com", cm: "com", xom: "com", vom: "com",
  inof: "info", ifno: "info", infoo: "info", inf: "info",
  orgg: "org", ogr: "org", nett: "net", nte: "net",
};

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 2) return 3;
  const dp = Array.from({ length: m + 1 }, (_, i) => i);
  for (let j = 1; j <= n; j++) {
    let prev = dp[0];
    dp[0] = j;
    for (let i = 1; i <= m; i++) {
      const tmp = dp[i];
      dp[i] = Math.min(dp[i] + 1, dp[i - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[m];
}

export function suggestDomainFix(rawInput) {
  const cleaned = String(rawInput || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^.*@/, "")
    .split(/[/?#:\s]/)[0]
    .replace(/,/g, ".")
    .replace(/\.{2,}/g, ".")
    .replace(/^\.+|\.+$/g, "")
    .replace(/^(?:www|m|web)\./, "");
  if (!cleaned || !cleaned.includes(".")) return null;
  const parts = cleaned.split(".");
  const tld = parts[parts.length - 1];
  if (TLD_TYPOS[tld]) {
    parts[parts.length - 1] = TLD_TYPOS[tld];
    return parts.join(".");
  }
  if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59}))+$/.test(cleaned) && cleaned !== String(rawInput || "").trim().toLowerCase()) {
    return cleaned;
  }
  return null;
}

export function detectTypoOrAltTld(domain, audit) {
  const clean = String(domain || "").toLowerCase();
  if (!clean || !clean.includes(".")) return null;
  const parts = clean.split(".");
  const tld = parts[parts.length - 1];
  const sld = parts.slice(0, -1).join(".");

  // 1. Direct TLD typo (e.g. stripe.cmo -> stripe.com, binance.inof -> binance.info)
  if (TLD_TYPOS[tld]) {
    const fixed = `${sld}.${TLD_TYPOS[tld]}`;
    return {
      kind: "typo",
      suggestedDomain: fixed,
      messageEn: `Possible TLD typo detected (".${tld}"). Did you mean ${fixed}?`,
      messageZh: `检测到疑似域名后缀拼写错误（".${tld}"），您是不是想查询 ${fixed}？`,
    };
  }

  // 2. Alternate TLD of a major sending brand (e.g. binance.info -> binance.com)
  const noMailAuth = (!audit?.mx?.records?.length) && (!audit?.spf?.record) && (!audit?.dmarc?.record);
  for (const pop of POPULAR_DOMAINS) {
    if (pop === clean) return null;
    const popParts = pop.split(".");
    const popSld = popParts.slice(0, -1).join(".");
    if (sld === popSld && clean !== pop) {
      return {
        kind: "alt_tld",
        suggestedDomain: pop,
        messageEn: noMailAuth
          ? `${clean} publishes no MX/SPF/DMARC mail records (uses .${tld}). Did you mean the primary mail domain ${pop}?`
          : `You scanned the .${tld} domain (${clean}). Looking for the primary brand domain ${pop}?`,
        messageZh: noMailAuth
          ? `${clean} 未配置任何 MX/SPF/DMARC 邮件解析（当前后缀为 .${tld}）。您是否想体检主站邮箱域名 ${pop}？`
          : `您当前正在检测 .${tld} 后缀域名（${clean}），是否需要同步查验主站域名 ${pop}？`,
      };
    }
  }

  // 3. Close edit-distance typo against popular domains (e.g. gamil.com -> gmail.com, binace.info -> binance.com)
  let best = null;
  let bestDist = 3;
  for (const pop of POPULAR_DOMAINS) {
    const popParts = pop.split(".");
    const popSld = popParts.slice(0, -1).join(".");
    if (sld.length < 4 || popSld.length < 4) continue;
    const dSld = levenshtein(sld, popSld);
    if (dSld > 0 && dSld <= (popSld.length >= 6 ? 2 : 1) && dSld < bestDist) {
      bestDist = dSld;
      best = pop;
    }
  }
  if (best && noMailAuth) {
    return {
      kind: "typo",
      suggestedDomain: best,
      messageEn: `${clean} appears to have no mail DNS records and closely resembles ${best}. Did you mean ${best}?`,
      messageZh: `${clean} 未查到邮件解析记录且与 ${best} 高度相似，您是不是想检测 ${best}？`,
    };
  }

  // 4. Generic non-.com domain with zero mail records (suggest trying .com counterpart)
  if (noMailAuth && tld !== "com" && parts.length === 2 && sld.length >= 3) {
    const comAlt = `${sld}.com`;
    return {
      kind: "no_mail_dns",
      suggestedDomain: comAlt,
      messageEn: `${clean} (.${tld}) has no active MX, SPF, or DMARC records. If this is a parked or mirror TLD, try checking ${comAlt}.`,
      messageZh: `${clean}（.${tld}）暂无任何 MX/SPF/DMARC 邮件配置。若为镜像或防注后缀，可一键查验 ${comAlt}。`,
    };
  }

  return null;
}

// ------------------------------------------------------------------ 1. Global + China Mail Provider Detection
export const PROVIDER_CATALOG = {
  tencent: { id: "tencent", en: "Tencent Exmail / QQ Mail", zh: "腾讯企业邮 / QQ邮箱", spfInclude: "include:spf.mail.qq.com" },
  aliyun: { id: "aliyun", en: "Alibaba Cloud Enterprise Mail", zh: "阿里企业邮", spfInclude: "include:spf.qiye.aliyun.com" },
  feishu: { id: "feishu", en: "Feishu / Lark Mail", zh: "飞书邮箱", spfInclude: "include:_spf.feishu.cn" },
  netease: { id: "netease", en: "NetEase Enterprise Mail (163)", zh: "网易企业邮", spfInclude: "include:spf.163.com" },
  huawei: { id: "huawei", en: "Huawei Cloud Enterprise Mail", zh: "华为云企业邮", spfInclude: "include:spf.huaweicloud.com" },
  sina: { id: "sina", en: "Sina Enterprise Mail", zh: "新浪企业邮", spfInclude: "include:spf.sina.net" },
  baidu: { id: "baidu", en: "Baidu Mail Infrastructure", zh: "百度企业邮件系统", spfInclude: "mx" },
  apple: { id: "apple", en: "Apple Mail / iCloud", zh: "Apple 邮件系统", spfInclude: "include:icloud.com" },
  google: { id: "google", en: "Google Workspace", zh: "Google Workspace", spfInclude: "include:_spf.google.com" },
  microsoft: { id: "microsoft", en: "Microsoft 365", zh: "Microsoft 365 企业邮", spfInclude: "include:spf.protection.outlook.com" },
  proton: { id: "proton", en: "Proton Mail", zh: "Proton Mail", spfInclude: "include:_spf.protonmail.ch" },
  fastmail: { id: "fastmail", en: "Fastmail", zh: "Fastmail", spfInclude: "include:spf.messagingengine.com" },
  zoho: { id: "zoho", en: "Zoho Mail", zh: "Zoho 企业邮", spfInclude: "include:zoho.com" },
  cloudflare: { id: "cloudflare", en: "Cloudflare Email Routing", zh: "Cloudflare 邮件路由", spfInclude: "include:_spf.mx.cloudflare.net" },
  ses: { id: "ses", en: "Amazon SES", zh: "Amazon SES", spfInclude: "include:amazonses.com" },
  mailgun: { id: "mailgun", en: "Mailgun", zh: "Mailgun", spfInclude: "include:mailgun.org" },
  sendgrid: { id: "sendgrid", en: "SendGrid", zh: "SendGrid", spfInclude: "include:sendgrid.net" },
  resend: { id: "resend", en: "Resend", zh: "Resend", spfInclude: "include:amazonses.com" },
  mimecast: { id: "mimecast", en: "Mimecast Security Gateway", zh: "Mimecast 邮件安全网关", spfInclude: "mx" },
  proofpoint: { id: "proofpoint", en: "Proofpoint Security Gateway", zh: "Proofpoint 邮件安全网关", spfInclude: "mx" },
  custom: { id: "custom", en: "Custom / Self-Hosted Mail", zh: "自建 / 独立邮件服务器", spfInclude: "mx" },
  none: { id: "none", en: "No MX Configured", zh: "未配置收信邮箱 (无 MX)", spfInclude: "mx" },
};

export function detectMailProvider(mxRecords, spfRecord = "") {
  const joined = (mxRecords || []).map((m) => String(m.exchange || "").toLowerCase()).join(" ");
  const spfLow = String(spfRecord || "").toLowerCase();

  if (/exmail\.qq\.com|mxbiz\d*\.qq\.com|mx\d*\.qq\.com|\.qq\.com\b/.test(joined) || spfLow.includes("spf.mail.qq.com")) return PROVIDER_CATALOG.tencent;
  if (/mxhichina\.com|qiye\.aliyun\.com|mx\d*\.qiye\.aliyun|alibaba-inc\.com|aliyun\.com/.test(joined) || spfLow.includes("qiye.aliyun.com") || spfLow.includes("mxhichina.com")) return PROVIDER_CATALOG.aliyun;
  if (/feishu\.cn|larksuite\.com|bytedance\.com/.test(joined) || spfLow.includes("_spf.feishu.cn") || spfLow.includes("_spf.larksuite.com")) return PROVIDER_CATALOG.feishu;
  if (/qiye\.163\.com|mxmail\.netease\.com|ym\.163\.com|163mx\d*\.mxmail\.netease|netease\.com|163\.com|126\.com/.test(joined) || spfLow.includes("spf.163.com") || spfLow.includes("spf.qiye.163.com")) return PROVIDER_CATALOG.netease;
  if (/huaweicloud\.com|hwcloud\.cn/.test(joined)) return PROVIDER_CATALOG.huawei;
  if (/sina\.net|sina\.com\.cn/.test(joined)) return PROVIDER_CATALOG.sina;
  if (/\.baidu\.com\b/.test(joined)) return PROVIDER_CATALOG.baidu;
  if (/google\.com|googlemail\.com/.test(joined)) return PROVIDER_CATALOG.google;
  if (/protection\.outlook\.com|outlook\.com|mail\.eo\.outlook/.test(joined)) return PROVIDER_CATALOG.microsoft;
  if (/\.apple\.com\b|icloud\.com/.test(joined)) return PROVIDER_CATALOG.apple;
  if (/protonmail\.ch/.test(joined)) return PROVIDER_CATALOG.proton;
  if (/messagingengine\.com/.test(joined)) return PROVIDER_CATALOG.fastmail;
  if (/zoho\.com|zoho\.eu|zoho\.com\.cn/.test(joined)) return PROVIDER_CATALOG.zoho;
  if (/mx\.cloudflare\.net/.test(joined)) return PROVIDER_CATALOG.cloudflare;
  if (/amazonses\.com/.test(joined)) return PROVIDER_CATALOG.ses;
  if (/mailgun\.org/.test(joined)) return PROVIDER_CATALOG.mailgun;
  if (/sendgrid\.net/.test(joined)) return PROVIDER_CATALOG.sendgrid;
  if (/mimecast\.com/.test(joined)) return PROVIDER_CATALOG.mimecast;
  if (/pphosted\.com/.test(joined)) return PROVIDER_CATALOG.proofpoint;
  if (!joined) return PROVIDER_CATALOG.none;
  return PROVIDER_CATALOG.custom;
}

// ------------------------------------------------------------------ 2. Recursive SPF 10-Lookup & Per-Layer CIDR Expansion Auditor (RFC 7208)
export async function checkSpf(domain, providerInfo = PROVIDER_CATALOG.custom) {
  const txts = await resolveTxt(domain);
  const spfRecords = txts.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  const spfMech = providerInfo?.spfInclude || "mx";

  if (spfRecords.length === 0) {
    const recVal = `v=spf1 ${spfMech} ~all`;
    return {
      status: "missing",
      record: null,
      allRecords: [],
      recordCount: 0,
      lookups: 0,
      voidLookups: 0,
      maxLookups: 10,
      maxDepth: 0,
      recordBytes: 0,
      ip4Count: 0,
      ip6Count: 0,
      totalCidrs: 0,
      layerStats: [],
      qualifier: null,
      includes: [],
      tree: [],
      issues: ["No v=spf1 TXT record found — receivers cannot authenticate sending servers."],
      issuesZh: ["未配置 SPF (v=spf1) 解析记录，收件方无法核验您的发信服务器身份，极易被直接判为垃圾邮件。"],
      fix: {
        type: "TXT",
        host: "@",
        value: recVal,
        note: `Add a single SPF TXT record authorized for ${providerInfo?.en || "your mail server"}.`,
        noteZh: `按当前识别的邮箱服务商（${providerInfo?.zh || "当前发信服务器"}）添加唯一一条 SPF TXT 记录。`,
      },
    };
  }

  const record = spfRecords[0];
  const issues = [];
  const issuesZh = [];
  if (spfRecords.length > 1) {
    issues.push(`Multiple v=spf1 records found (${spfRecords.length}) — triggers immediate RFC 7208 PermError! Merge into ONE record.`);
    issuesZh.push(`检测到 ${spfRecords.length} 条重复的 SPF 记录！RFC 7208 规定每个域名只能有 1 条 SPF 记录，多条会直接导致验证彻底失效，请合并为唯一一条。`);
  }

  let lookups = 0;
  let voidLookups = 0;
  let maxDepth = 0;
  const visited = new Set([domain]);
  const includes = [];
  const tree = [];
  const ip4Set = new Set();
  const ip6Set = new Set();
  const layerMap = new Map();

  function touchLayer(d) {
    if (!layerMap.has(d)) layerMap.set(d, { depth: d, lookups: 0, ip4Count: 0, ip6Count: 0 });
    return layerMap.get(d);
  }

  async function walk(dom, rec, depth, parent) {
    if (depth > 8) return 0;
    if (depth > maxDepth) maxDepth = depth;
    const layer = touchLayer(depth);
    let subLookups = 0;
    const tokens = rec.trim().split(/\s+/).slice(1);
    for (const tok of tokens) {
      const clean = tok.replace(/^[+\-~?]/, "");
      const lower = clean.toLowerCase();
      if (lower.startsWith("ip4:")) {
        const cidr = clean.slice(4);
        if (cidr && !ip4Set.has(cidr)) {
          ip4Set.add(cidr);
          layer.ip4Count++;
        }
      } else if (lower.startsWith("ip6:")) {
        const cidr = clean.slice(4);
        if (cidr && !ip6Set.has(cidr)) {
          ip6Set.add(cidr);
          layer.ip6Count++;
        }
      } else if (lower.startsWith("include:") || lower.startsWith("redirect=")) {
        const isRedir = lower.startsWith("redirect=");
        const target = clean.slice(isRedir ? 9 : 8).toLowerCase();
        lookups++;
        subLookups++;
        layer.lookups++;
        if (!isRedir) includes.push(target);
        const isCycle = visited.has(target);
        const node = {
          depth,
          parent,
          mechanism: tok,
          target,
          directLookups: 1,
          nestedLookups: 0,
          ip4Added: 0,
          ip6Added: 0,
          voidLookup: false,
          cycle: isCycle,
        };
        tree.push(node);
        if (!isCycle && lookups <= 30) {
          visited.add(target);
          const before4 = ip4Set.size;
          const before6 = ip6Set.size;
          const subTxts = await resolveTxt(target);
          const subSpf = subTxts.find((t) => /^v=spf1(\s|$)/i.test(t.trim()));
          if (subSpf) {
            node.nestedLookups = await walk(target, subSpf, depth + 1, target);
            subLookups += node.nestedLookups;
          } else {
            node.voidLookup = true;
            voidLookups++;
          }
          node.ip4Added = ip4Set.size - before4;
          node.ip6Added = ip6Set.size - before6;
        }
      } else if (/^(a|mx|ptr|exists)(:|\/|$)/i.test(lower)) {
        lookups++;
        subLookups++;
        layer.lookups++;
        tree.push({
          depth,
          parent,
          mechanism: tok,
          target: dom,
          directLookups: 1,
          nestedLookups: 0,
          ip4Added: 0,
          ip6Added: 0,
          voidLookup: false,
          cycle: false,
        });
        if (lower.startsWith("ptr")) {
          issues.push("Deprecated 'ptr' mechanism used in SPF (slow & prohibited by RFC 7208 Section 5.5).");
          issuesZh.push("SPF 中使用了已被 RFC 7208 淘汰的 ptr 规则，可能拖慢解析并引发收件箱扣分。");
        }
      }
    }
    return subLookups;
  }

  await walk(domain, record, 0, domain);

  const allMatch = record.match(/(?:^|\s)([+\-~?])?all(?:\s|$)/i);
  const qualifier = allMatch ? `${allMatch[1] || "+"}all` : "none";
  const hasRedirect = /(?:^|\s)redirect=/i.test(record);
  const recordBytes = record.length;

  if (lookups > 10) {
    issues.push(`SPF exceeds RFC 7208 limit (${lookups}/10 DNS lookups) — triggers silent PermError across Gmail & Outlook!`);
    issuesZh.push(`SPF 递归查询已达 ${lookups}/10 次（超出协议 10 次硬上限），Gmail、Outlook 与 QQ 邮箱会直接判定 SPF 验证失败！建议立即解锁展平修复。`);
  } else if (lookups >= 8) {
    issues.push(`SPF lookup budget nearly exhausted (${lookups}/10) — adding one more email service will break delivery.`);
    issuesZh.push(`SPF 查询次数已用掉 ${lookups}/10 次，已非常接近上限，再新增任意发信工具就可能导致邮件退信。`);
  }
  if (voidLookups > 2) {
    issues.push(`SPF triggers ${voidLookups} void DNS lookups (RFC 7208 max 2) — causes PermError on strict receivers!`);
    issuesZh.push(`SPF 存在 ${voidLookups} 次空查询（RFC 7208 上限 2 次），部分收件箱会直接返回 PermError。`);
  }
  if (hasRedirect && allMatch) {
    issues.push("SPF combines redirect= with an 'all' mechanism — redirect= is silently ignored when 'all' is present.");
    issuesZh.push("SPF 同时混用了 redirect= 与 all 结尾机制，协议规定此时 redirect= 会被忽略，请清理冲突规则。");
  }
  if (recordBytes > 450) {
    issues.push(`SPF TXT record is ${recordBytes} bytes (>450B UDP DNS guidance) — risk of truncated UDP responses.`);
    issuesZh.push(`SPF 记录长度达 ${recordBytes} 字节（超过 450 字节单 UDP 包建议上限），存在解析截断风险。`);
  }
  if (qualifier === "+all") {
    issues.push("Dangerous '+all' qualifier authorizes the entire internet to spoof your domain!");
    issuesZh.push("高危配置：SPF 结尾使用了 +all，等于允许全网任何人冒充您的域名群发诈骗邮件！请立刻改为 ~all 或 -all。");
  } else if (qualifier === "?all" || (qualifier === "none" && !hasRedirect)) {
    issues.push(`Weak SPF ending (${qualifier}) — change to '~all' (softfail) or '-all' (hardfail).`);
    issuesZh.push(`SPF 结尾策略偏弱（${qualifier === "none" ? "未写结尾规则" : qualifier}），建议改为 ~all（软拒绝）或 -all（严格拒绝）。`);
  }

  let status = "pass";
  if (spfRecords.length > 1 || lookups > 10 || voidLookups > 2 || qualifier === "+all") status = "fail";
  else if (issues.length > 0) status = "warn";

  const fixedValue = allMatch ? record.replace(/(^|\s)[+\-~?]?all\b/i, "$1~all") : `${record.trim()} ~all`;
  const layerStats = [...layerMap.values()].sort((a, b) => a.depth - b.depth);

  return {
    status,
    record,
    allRecords: spfRecords,
    recordCount: spfRecords.length,
    lookups,
    voidLookups,
    maxLookups: 10,
    maxDepth,
    recordBytes,
    ip4Count: ip4Set.size,
    ip6Count: ip6Set.size,
    totalCidrs: ip4Set.size + ip6Set.size,
    layerStats,
    qualifier,
    includes: [...new Set(includes)],
    tree,
    issues,
    issuesZh,
    fix:
      status !== "pass"
        ? {
            type: "TXT",
            host: "@",
            value: fixedValue,
            note: lookups > 10 ? "Remove unused include: entries or flatten static IPs so total DNS lookups stay <= 10." : "Enforce ~all or -all and ensure only one v=spf1 record exists.",
            noteZh: lookups > 10 ? "请删除不再使用的第三方 include:，或使用本工具的「SPF 展平器」压缩至 10 次查询以内。" : "请确保域名下仅保留 1 条 SPF 记录，且以 ~all 或 -all 结尾。",
          }
        : null,
  };
}

// ------------------------------------------------------------------ 3. Strict RFC 7489 DMARC Tag Syntax Linter
const VALID_DMARC_TAGS = new Set(["v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"]);

export async function checkDmarc(domain) {
  const txts = await resolveTxt(`_dmarc.${domain}`);
  const dmarcRecs = txts.filter((t) => /^\s*v\s*=\s*dmarc1\b/i.test(t));
  const rec = dmarcRecs[0] || null;
  if (!rec) {
    return {
      status: "missing",
      record: null,
      recordCount: 0,
      policy: null,
      tags: {},
      syntaxChecks: [
        { tag: "v=DMARC1", value: "missing", valid: false, severity: "fail", note: "No _dmarc TXT record published.", noteZh: "未发布 _dmarc TXT 记录。" },
      ],
      syntaxErrors: ["No _dmarc TXT record published."],
      syntaxErrorsZh: ["未发布 _dmarc TXT 记录。"],
      issues: ["No _dmarc TXT record found — fails Google & Yahoo bulk sender mandates and leaves domain open to spoofing."],
      issuesZh: ["未配置 _dmarc 防伪造记录！您的域名不满足 Google / Yahoo 发信规范，且极易被他人冒名发送钓鱼邮件。"],
      fix: {
        type: "TXT",
        host: "_dmarc",
        value: `v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r; rua=mailto:dmarc@${domain}`,
        note: "Publish this _dmarc TXT record to activate anti-spoofing protection and receive delivery reports.",
        noteZh: "添加这条 _dmarc 记录后，即可防止域名被冒用并满足海内外主流收件箱的防垃圾合规要求。",
      },
    };
  }

  const rawParts = rec.split(";").map((s) => s.trim()).filter(Boolean);
  const tags = {};
  const tagOrder = [];
  const syntaxChecks = [];
  const syntaxErrors = [];
  const syntaxErrorsZh = [];
  const issues = [];
  const issuesZh = [];

  if (dmarcRecs.length > 1) {
    const eEn = `Duplicate _dmarc TXT records found (${dmarcRecs.length}) — RFC 7489 requires receivers to ignore DMARC when multiple records exist!`;
    const eZh = `检测到 ${dmarcRecs.length} 条重复的 _dmarc 记录！RFC 7489 规定多条 DMARC 记录会导致全网收件箱直接忽略该策略！`;
    syntaxErrors.push(eEn); syntaxErrorsZh.push(eZh);
    issues.push(eEn); issuesZh.push(eZh);
    syntaxChecks.push({ tag: "records", value: `${dmarcRecs.length} records`, valid: false, severity: "fail", note: eEn, noteZh: eZh });
  }

  for (let i = 0; i < rawParts.length; i++) {
    const seg = rawParts[i];
    const eqIdx = seg.indexOf("=");
    if (eqIdx === -1) {
      const eEn = `Malformed DMARC token "${seg}" (missing "=" separator).`;
      const eZh = `DMARC 标签语法错误：「${seg}」缺少 "=" 分隔符。`;
      syntaxErrors.push(eEn); syntaxErrorsZh.push(eZh);
      syntaxChecks.push({ tag: seg, value: "invalid", valid: false, severity: "fail", note: eEn, noteZh: eZh });
      continue;
    }
    const k = seg.slice(0, eqIdx).trim().toLowerCase();
    const v = seg.slice(eqIdx + 1).trim();
    tagOrder.push(k);
    if (Object.prototype.hasOwnProperty.call(tags, k)) {
      const eEn = `Duplicate DMARC tag "${k}=" found.`;
      const eZh = `检测到重复的 DMARC 标签「${k}=」。`;
      syntaxErrors.push(eEn); syntaxErrorsZh.push(eZh);
      syntaxChecks.push({ tag: k, value: v, valid: false, severity: "warn", note: eEn, noteZh: eZh });
    }
    tags[k] = v;

    if (!VALID_DMARC_TAGS.has(k)) {
      const eEn = `Unknown DMARC tag "${k}=${v}" (not part of RFC 7489).`;
      const eZh = `未知的 DMARC 标签「${k}=${v}」（不符合 RFC 7489 规范）。`;
      syntaxErrors.push(eEn); syntaxErrorsZh.push(eZh);
      syntaxChecks.push({ tag: k, value: v, valid: false, severity: "warn", note: eEn, noteZh: eZh });
    }
  }

  // Strict v=DMARC1 first-tag & exact case check
  const vOk = tagOrder[0] === "v" && tags.v === "DMARC1";
  syntaxChecks.push({
    tag: "v",
    value: tags.v || "missing",
    valid: vOk,
    severity: vOk ? "pass" : "fail",
    note: vOk ? "Exact case v=DMARC1 in required first position." : "RFC 7489 requires exact-case v=DMARC1 as the very first tag.",
    noteZh: vOk ? "首标签精确符合 v=DMARC1 规范。" : "RFC 7489 要求 v=DMARC1 必须严格大写且位于第 1 位。",
  });
  if (!vOk) {
    syntaxErrors.push("DMARC version tag must be exact-case v=DMARC1 in first position.");
    syntaxErrorsZh.push("DMARC 版本标签必须严格为大写 v=DMARC1 且排在首位。");
  }

  // Strict p= policy check
  const policyRaw = (tags.p || "").toLowerCase();
  const pValid = ["none", "quarantine", "reject"].includes(policyRaw);
  const policy = pValid ? policyRaw : "invalid";
  syntaxChecks.push({
    tag: "p",
    value: tags.p || "missing",
    valid: pValid,
    severity: !pValid ? "fail" : policy === "none" ? "warn" : "pass",
    note: !pValid ? `Invalid or missing p= value ("${tags.p || ""}"). Must be none, quarantine, or reject.` : (policy === "none" ? "Valid syntax, but monitor-only (does not block spoofing)." : `Valid enforcement policy (p=${policy}).`),
    noteZh: !pValid ? `p= 策略值非法或缺失（"${tags.p || ""}"），仅允许 none / quarantine / reject。` : (policy === "none" ? "语法合法，但仅监控不拦截伪造邮件。" : `强制拦截策略合法生效（p=${policy}）。`),
  });
  if (!pValid) {
    const eEn = `Invalid DMARC p= policy "${tags.p || "missing"}" — must be none, quarantine, or reject.`;
    const eZh = `DMARC p= 策略值错误（「${tags.p || "缺失"}」），必须为 none、quarantine 或 reject。`;
    syntaxErrors.push(eEn); syntaxErrorsZh.push(eZh);
    issues.push(eEn); issuesZh.push(eZh);
  } else if (policy === "none") {
    issues.push("DMARC policy is p=none (monitoring only) — does not block spoofing; upgrade to p=quarantine or p=reject.");
    issuesZh.push("当前 DMARC 策略仅为 p=none（仅观察不拦截），无法阻止他人冒充发信；确认业务正常后建议升级为 p=quarantine（隔离）或 p=reject（拦截）。");
  }

  // sp= check
  if (tags.sp) {
    const spValid = ["none", "quarantine", "reject"].includes(tags.sp.toLowerCase());
    syntaxChecks.push({
      tag: "sp",
      value: tags.sp,
      valid: spValid,
      severity: spValid ? (tags.sp.toLowerCase() === "none" ? "warn" : "pass") : "fail",
      note: spValid ? `Subdomain policy sp=${tags.sp.toLowerCase()}.` : `Invalid sp="${tags.sp}" (must be none, quarantine, or reject).`,
      noteZh: spValid ? `子域名策略 sp=${tags.sp.toLowerCase()} 语法合法。` : `子域名策略 sp="${tags.sp}" 非法。`,
    });
    if (!spValid) {
      syntaxErrors.push(`Invalid sp=${tags.sp} tag.`);
      syntaxErrorsZh.push(`子域名策略 sp=${tags.sp} 语法非法。`);
    }
  }

  // pct= check
  let pctNum = 100;
  if (tags.pct !== undefined) {
    const n = Number(tags.pct);
    const pctValid = /^\d{1,3}$/.test(tags.pct) && n >= 0 && n <= 100;
    pctNum = pctValid ? n : 0;
    syntaxChecks.push({
      tag: "pct",
      value: tags.pct,
      valid: pctValid,
      severity: !pctValid ? "fail" : n < 100 ? "warn" : "pass",
      note: !pctValid ? `Invalid pct="${tags.pct}" (must be integer 0-100).` : (n < 100 ? `Partial enforcement (${n}% of messages).` : "100% enforcement coverage."),
      noteZh: !pctValid ? `pct="${tags.pct}" 必须为 0-100 的整数。` : (n < 100 ? `仅对 ${n}% 邮件生效，稳定后建议调至 100%。` : "100% 全量生效。"),
    });
    if (!pctValid) {
      syntaxErrors.push(`Invalid pct=${tags.pct} (must be 0-100).`);
      syntaxErrorsZh.push(`pct=${tags.pct} 非法（必须为 0-100 整数）。`);
    } else if (n < 100) {
      issues.push(`DMARC pct=${n} — enforcement only applies to ${n}% of messages.`);
      issuesZh.push(`当前 DMARC 生效比例仅为 ${n}%（pct=${n}），建议观察稳定后调至 100%。`);
    }
  }

  // adkim= & aspf= alignment checks
  for (const alignTag of ["adkim", "aspf"]) {
    if (tags[alignTag] !== undefined) {
      const ok = ["r", "s"].includes(tags[alignTag].toLowerCase());
      syntaxChecks.push({
        tag: alignTag,
        value: tags[alignTag],
        valid: ok,
        severity: ok ? "pass" : "fail",
        note: ok ? (tags[alignTag].toLowerCase() === "s" ? "Strict domain alignment." : "Relaxed subdomain alignment.") : `Invalid ${alignTag}="${tags[alignTag]}" (only "r" or "s" allowed).`,
        noteZh: ok ? (tags[alignTag].toLowerCase() === "s" ? "严格对齐模式。" : "宽松子域对齐模式。") : `${alignTag}="${tags[alignTag]}" 非法（仅允许 r 或 s）。`,
      });
      if (!ok) {
        syntaxErrors.push(`Invalid ${alignTag}=${tags[alignTag]} (only r or s allowed).`);
        syntaxErrorsZh.push(`${alignTag}=${tags[alignTag]} 语法错误（仅允许 r 或 s）。`);
      }
    }
  }

  // rua= & ruf= URI validation
  if (!tags.rua) {
    issues.push("No aggregate report address (rua=mailto:...) configured — you have no visibility into auth failures.");
    issuesZh.push("未填写 DMARC 报表接收邮箱（rua=mailto:...），您无法收到每日发信异常与冒名拦截报告。");
    syntaxChecks.push({ tag: "rua", value: "missing", valid: false, severity: "warn", note: "Missing aggregate reporting URI (mailto:...).", noteZh: "缺少每日聚合报表接收邮箱（rua=mailto:...）。" });
  } else {
    const uris = tags.rua.split(",").map((u) => u.trim()).filter(Boolean);
    const badUris = uris.filter((u) => !/^mailto:[^\s@!]+@[^\s@!]+(?:!\d+[kmgt]?)?$/i.test(u));
    const ruaOk = uris.length > 0 && badUris.length === 0;
    syntaxChecks.push({
      tag: "rua",
      value: `${uris.length} URI(s)`,
      valid: ruaOk,
      severity: ruaOk ? "pass" : "fail",
      note: ruaOk ? `Valid RFC 7489 mailto: aggregate reporting target(s).` : `Malformed rua URI (must begin with mailto:): ${badUris.join(", ")}`,
      noteZh: ruaOk ? `合法的 mailto: 聚合报表接收地址（${uris.length} 个）。` : `rua 地址格式错误（必须以 mailto: 开头）：${badUris.join("、")}`,
    });
    if (!ruaOk) {
      const eEn = `Invalid DMARC rua= URI syntax: "${badUris.join(", ")}" — every address must start with mailto:.`;
      const eZh = `DMARC rua= 语法错误：「${badUris.join("、")}」必须以 mailto: 开头。`;
      syntaxErrors.push(eEn); syntaxErrorsZh.push(eZh);
      issues.push(eEn); issuesZh.push(eZh);
    }
  }

  // fo= & ri= optional checks
  if (tags.fo !== undefined) {
    const foParts = tags.fo.split(":").map((x) => x.trim().toLowerCase()).filter(Boolean);
    const foOk = foParts.length > 0 && foParts.every((x) => ["0", "1", "d", "s"].includes(x));
    syntaxChecks.push({ tag: "fo", value: tags.fo, valid: foOk, severity: foOk ? "pass" : "fail", note: foOk ? "Valid failure reporting option." : `Invalid fo="${tags.fo}" (allowed: 0, 1, d, s).`, noteZh: foOk ? "fo 失败报告选项合法。" : `fo="${tags.fo}" 非法（仅允许 0/1/d/s）。` });
    if (!foOk) { syntaxErrors.push(`Invalid fo=${tags.fo}.`); syntaxErrorsZh.push(`fo=${tags.fo} 语法非法。`); }
  }
  if (tags.ri !== undefined) {
    const riNum = Number(tags.ri);
    const riOk = /^\d+$/.test(tags.ri) && riNum >= 3600;
    syntaxChecks.push({ tag: "ri", value: tags.ri + "s", valid: riOk, severity: riOk ? "pass" : "warn", note: riOk ? `Report interval ${riNum}s.` : `Unusual ri="${tags.ri}" (standard is 86400s).`, noteZh: riOk ? `报表间隔 ${riNum} 秒。` : `ri="${tags.ri}" 偏异常（建议 86400 秒）。` });
  }

  let status = "pass";
  if (dmarcRecs.length > 1 || !vOk || !pValid || syntaxErrors.some((e) => /Invalid|Duplicate|Malformed/i.test(e))) status = "fail";
  else if (policy === "none" || issues.length > 0) status = "warn";

  return {
    status,
    record: rec,
    recordCount: dmarcRecs.length,
    policy: pValid ? policy : null,
    subdomainPolicy: tags.sp ? tags.sp.toLowerCase() : (pValid ? policy : null),
    rua: tags.rua || null,
    pct: pctNum,
    tags,
    syntaxChecks,
    syntaxErrors,
    syntaxErrorsZh,
    issues,
    issuesZh,
    fix:
      status !== "pass"
        ? {
            type: "TXT",
            host: "_dmarc",
            value: `v=DMARC1; p=quarantine; sp=quarantine; pct=100; adkim=r; aspf=r; rua=${(tags.rua && /^mailto:/i.test(tags.rua)) ? tags.rua : `mailto:dmarc@${domain}`}`,
            note: "Fix DMARC syntax errors and upgrade to p=quarantine (then p=reject) with a valid mailto: RUA address.",
            noteZh: "修正 DMARC 语法并升级为 p=quarantine（随后切至 p=reject）且填写规范的 mailto: 报表邮箱。",
          }
        : null,
  };
}

// ------------------------------------------------------------------ 4. Multi-Selector DKIM Prober
function estimateRsaBits(base64Key) {
  if (!base64Key) return 0;
  try {
    const bytes = Buffer.from(base64Key.replace(/\s+/g, ""), "base64").length;
    if (bytes >= 250) return 2048;
    if (bytes >= 120) return 1024;
    if (bytes >= 60) return 512;
    return bytes * 8;
  } catch {
    return 0;
  }
}

export async function checkDkim(domain, customSelectors = []) {
  const selectors = [...new Set([...customSelectors, ...COMMON_DKIM_SELECTORS])];
  const found = [];

  await Promise.all(
    selectors.map(async (sel) => {
      const host = `${sel}._domainkey.${domain}`;
      const txts = await resolveTxt(host);
      const rec = txts.find((t) => /v=DKIM1|p=/i.test(t));
      if (rec) {
        const pMatch = rec.match(/(?:^|[\s;])p=([A-Za-z0-9+/=]*)/i);
        const keyB64 = pMatch ? pMatch[1].replace(/\s+/g, "") : "";
        const bits = estimateRsaBits(keyB64);
        const revoked = Boolean(pMatch && keyB64.length === 0);
        found.push({
          selector: sel,
          host,
          bits,
          revoked,
          weak: !revoked && bits > 0 && bits < 1024,
          recordPreview: rec.slice(0, 90) + (rec.length > 90 ? "..." : ""),
        });
      }
    })
  );

  const active = found.filter((f) => !f.revoked);
  const issues = [];
  const issuesZh = [];
  if (active.length === 0) {
    issues.push(`No active DKIM key found across ${selectors.length} standard selectors (your email provider may use a custom selector name).`);
    issuesZh.push(`在 ${selectors.length} 个常用 DKIM 名称中未发现公开公钥（若您的企业邮使用了自定义选择器，可在上方选填框输入后再测，或登录邮箱后台开启 DKIM 签名）。`);
  } else {
    const weakKeys = active.filter((f) => f.bits > 0 && f.bits < 2048);
    if (weakKeys.length === active.length && active.every((f) => f.bits < 1024)) {
      issues.push("DKIM RSA key is below 1024-bit — rotate immediately to 2048-bit.");
      issuesZh.push("当前 DKIM 密钥长度低于 1024 位，安全性不足，请尽快在邮箱后台升级轮换为 2048 位密钥。");
    }
  }

  return {
    status: active.length > 0 ? (issues.length ? "warn" : "pass") : "warn",
    checkedCount: selectors.length,
    found: active,
    issues,
    issuesZh,
  };
}

// ------------------------------------------------------------------ 5. MTA-STS, TLS-RPT & BIMI
export async function checkAdvancedAuth(domain) {
  const [mtaTxt, tlsRptTxt, bimiTxt] = await Promise.all([
    resolveTxt(`_mta-sts.${domain}`),
    resolveTxt(`_smtp._tls.${domain}`),
    resolveTxt(`default._bimi.${domain}`),
  ]);

  const mtaRecord = mtaTxt.find((t) => /^v=STSv1/i.test(t.trim())) || null;
  let mtaPolicyMode = null;
  if (mtaRecord) {
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 1800);
      const r = await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { signal: ctl.signal });
      clearTimeout(timer);
      if (r.ok) {
        const txt = await r.text();
        const m = txt.match(/^mode:\s*(\w+)/im);
        if (m) mtaPolicyMode = m[1].toLowerCase();
      }
    } catch {}
  }

  const tlsRptRecord = tlsRptTxt.find((t) => /^v=TLSRPTv1/i.test(t.trim())) || null;
  const bimiRecord = bimiTxt.find((t) => /^v=BIMI1/i.test(t.trim())) || null;
  let bimiLogoUrl = null;
  let bimiVmcUrl = null;
  if (bimiRecord) {
    const lMatch = bimiRecord.match(/(?:^|;\s*)l=(https:\/\/[^;\s]+)/i);
    const aMatch = bimiRecord.match(/(?:^|;\s*)a=(https:\/\/[^;\s]+)/i);
    if (lMatch) bimiLogoUrl = lMatch[1].trim();
    if (aMatch) bimiVmcUrl = aMatch[1].trim();
  }

  return {
    mtaSts: { present: Boolean(mtaRecord), record: mtaRecord, mode: mtaPolicyMode },
    tlsRpt: { present: Boolean(tlsRptRecord), record: tlsRptRecord },
    bimi: { present: Boolean(bimiRecord), record: bimiRecord, logoUrl: bimiLogoUrl, vmcUrl: bimiVmcUrl },
  };
}

// ------------------------------------------------------------------ 6. Live DNSBL Blacklist Check
const DOMAIN_BLS = [
  { name: "Spamhaus DBL", zone: "dbl.spamhaus.org" },
  { name: "SURBL Multi", zone: "multi.surbl.org" },
];

const IP_BLS = [
  { name: "Barracuda BRBL", zone: "b.barracudacentral.org" },
  { name: "SpamCop", zone: "bl.spamcop.net" },
  { name: "SORBS", zone: "dnsbl.sorbs.net" },
];

function isValidBlacklistHit(zone, ips) {
  if (!ips?.length) return false;
  return ips.some((ip) => {
    if (!ip.startsWith("127.")) return false;
    if (ip.startsWith("127.255.")) return false;
    if (zone === "dbl.spamhaus.org" && (ip === "127.0.1.255" || ip === "127.0.1.254")) return false;
    if (zone === "multi.surbl.org" && ip === "127.0.0.1") return false;
    return true;
  });
}

export async function checkBlacklists(domain, mxRecords) {
  const hits = [];
  const checkedZones = [];

  await Promise.all(
    DOMAIN_BLS.map(async (bl) => {
      checkedZones.push(bl.name);
      const res = await resolveA(`${domain}.${bl.zone}`);
      if (isValidBlacklistHit(bl.zone, res)) {
        hits.push({ target: domain, list: bl.name, zone: bl.zone, codes: res });
      }
    })
  );

  const mxIps = [];
  for (const mx of mxRecords.slice(0, 2)) {
    const ips = await resolveA(mx.exchange);
    for (const ip of ips.slice(0, 2)) {
      if (!mxIps.includes(ip)) mxIps.push(ip);
    }
  }

  await Promise.all(
    mxIps.flatMap((ip) => {
      const rev = ip.split(".").reverse().join(".");
      return IP_BLS.map(async (bl) => {
        if (!checkedZones.includes(bl.name)) checkedZones.push(bl.name);
        const res = await resolveA(`${rev}.${bl.zone}`);
        if (isValidBlacklistHit(bl.zone, res)) {
          hits.push({ target: ip, list: bl.name, zone: bl.zone, codes: res });
        }
      });
    })
  );

  return {
    status: hits.length === 0 ? "clean" : "listed",
    checkedLists: checkedZones,
    checkedIps: mxIps,
    hits,
  };
}

// ------------------------------------------------------------------ 7. Deterministic Scoring & Bilingual Summary
export function scoreDeliverability(audit) {
  let score = 100;
  const blockers = [];
  const blockersZh = [];
  const warnings = [];
  const warningsZh = [];
  const fixes = [];

  if (!audit.mx.records.length) {
    score -= 20;
    blockers.push("No MX records configured (domain cannot receive replies or bounce notices).");
    blockersZh.push("未检测到 MX 收信记录，该域名目前无法正常接收客户回复或退信通知。");
  } else if (audit.mx.redundancy) {
    if (audit.mx.redundancy.status === "fail") {
      score -= 10;
      blockers.push(...(audit.mx.redundancy.issues || []));
      blockersZh.push(...(audit.mx.redundancy.issuesZh || []));
    } else if (audit.mx.redundancy.status === "warn") {
      score -= 3;
      warnings.push(...(audit.mx.redundancy.issues || []));
      warningsZh.push(...(audit.mx.redundancy.issuesZh || []));
    }
  }

  if (audit.dnsMeta?.nsHealth) {
    if (audit.dnsMeta.nsHealth.status === "fail") {
      score -= 8;
      blockers.push(...(audit.dnsMeta.nsHealth.issues || []));
      blockersZh.push(...(audit.dnsMeta.nsHealth.issuesZh || []));
    } else if (audit.dnsMeta.nsHealth.status === "warn") {
      score -= 3;
      warnings.push(...(audit.dnsMeta.nsHealth.issues || []));
      warningsZh.push(...(audit.dnsMeta.nsHealth.issuesZh || []));
    }
  }

  if (audit.spf.status === "missing") {
    score -= 28;
    blockers.push(...audit.spf.issues);
    blockersZh.push(...(audit.spf.issuesZh || audit.spf.issues));
  } else if (audit.spf.status === "fail") {
    score -= 26;
    blockers.push(...audit.spf.issues);
    blockersZh.push(...(audit.spf.issuesZh || audit.spf.issues));
  } else if (audit.spf.status === "warn") {
    score -= 8;
    warnings.push(...audit.spf.issues);
    warningsZh.push(...(audit.spf.issuesZh || audit.spf.issues));
  }
  if (audit.spf.fix) fixes.push({ area: "SPF", ...audit.spf.fix });

  if (audit.dmarc.status === "missing") {
    score -= 26;
    blockers.push(...audit.dmarc.issues);
    blockersZh.push(...(audit.dmarc.issuesZh || audit.dmarc.issues));
  } else if (audit.dmarc.status === "fail") {
    score -= 22;
    blockers.push(...audit.dmarc.issues);
    blockersZh.push(...(audit.dmarc.issuesZh || audit.dmarc.issues));
  } else if (audit.dmarc.policy === "none") {
    score -= 10;
    warnings.push(...audit.dmarc.issues);
    warningsZh.push(...(audit.dmarc.issuesZh || audit.dmarc.issues));
  } else if (audit.dmarc.issues.length) {
    score -= 4;
    warnings.push(...audit.dmarc.issues);
    warningsZh.push(...(audit.dmarc.issuesZh || audit.dmarc.issues));
  }
  if (audit.dmarc.fix) fixes.push({ area: "DMARC", ...audit.dmarc.fix });

  if (audit.dkim.found.length === 0) {
    score -= 12;
    warnings.push(...audit.dkim.issues);
    warningsZh.push(...(audit.dkim.issuesZh || audit.dkim.issues));
  } else if (audit.dkim.issues.length) {
    score -= 8;
    warnings.push(...audit.dkim.issues);
    warningsZh.push(...(audit.dkim.issuesZh || audit.dkim.issues));
  }

  if (audit.blacklists.hits.length > 0) {
    score -= 38;
    for (const h of audit.blacklists.hits) {
      blockers.push(`Listed on ${h.list} (${h.target} -> ${h.codes.join(",")}) — request delisting immediately.`);
      blockersZh.push(`命中反垃圾黑名单 ${h.list}（目标 ${h.target}），发信极可能被大面积拦截，请立即申诉移出。`);
    }
  }

  if (!audit.advanced.mtaSts.present) score -= 3;
  if (!audit.advanced.tlsRpt.present) score -= 2;

  score = Math.max(0, Math.min(100, Math.round(score)));

  const googleYahooCompliant =
    audit.spf.status !== "missing" &&
    audit.spf.status !== "fail" &&
    audit.dmarc.status !== "missing" &&
    audit.blacklists.hits.length === 0;

  let grade = "A+";
  if (score < 50) grade = "F";
  else if (score < 65) grade = "D";
  else if (score < 78) grade = "C";
  else if (score < 88) grade = "B";
  else if (score < 95) grade = "A";

  let status = "HEALTHY";
  if (audit.blacklists.hits.length > 0 || score < 55) status = "CRITICAL";
  else if (blockers.length > 0 || score < 75) status = "AT_RISK";
  else if (warnings.length > 0) status = "NEEDS_HARDENING";

  return { score, grade, status, googleYahooCompliant, blockers, blockersZh, warnings, warningsZh, fixes };
}

export async function auditDomain(rawDomain, opts = {}) {
  const checkedAt = nowIso();
  const stripped = stripLeadingWww(rawDomain);
  let domain = stripped.domain;
  let fallbackNote = stripped.autoStrippedWww
    ? {
        en: `Auto-resolved root sending domain ${domain} from ${stripped.requestedDomain}.`,
        zh: `已自动为您剥离前缀，正在检测主发信域名 ${domain}（原输入：${stripped.requestedDomain}）。`,
      }
    : null;

  // Fetch MX first (fast) so we can detect China/Global mail provider AND gracefully fallback from subdomain -> apex if needed
  let mxRecords = await resolveMx(domain);
  let apexCandidate = getApexDomain(domain);
  if (!mxRecords.length && apexCandidate !== domain) {
    const [subTxts, apexMx] = await Promise.all([resolveTxt(domain), resolveMx(apexCandidate)]);
    const subHasSpf = subTxts.some((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    if (!subHasSpf && apexMx.length > 0) {
      const prev = domain;
      domain = apexCandidate;
      mxRecords = apexMx;
      fallbackNote = {
        en: `Subdomain ${prev} has no email DNS records; automatically audited root domain ${domain}.`,
        zh: `子域名 ${prev} 未配置邮件记录，已自动回退检测主域名 ${domain}。`,
      };
    }
  }

  const tStart = Date.now();
  const initialProvider = detectMailProvider(mxRecords);
  const timed = async (label, fn) => {
    const s = Date.now();
    const res = await fn();
    return { label, ms: Date.now() - s, res };
  };

  const [spfT, dmarcT, dkimT, advT, blT, nsT, caaT, mxRedT] = await Promise.all([
    timed("spf", () => checkSpf(domain, initialProvider)),
    timed("dmarc", () => checkDmarc(domain)),
    timed("dkim", () => checkDkim(domain, opts.selectors || [])),
    timed("advanced", () => checkAdvancedAuth(domain)),
    timed("dnsbl", () =>
      opts.skipBlacklists
        ? Promise.resolve({ status: "skipped", checkedLists: [], checkedIps: [], hits: [] })
        : checkBlacklists(domain, mxRecords)
    ),
    timed("ns", async () => {
      const nsRecs = await resolveNs(domain);
      const nsHealth = await checkNsConsistency(domain, nsRecs);
      return { nsRecs, nsHealth };
    }),
    timed("caa", () => resolveCaa(domain)),
    timed("mx_redundancy", () => checkMxRedundancy(mxRecords)),
  ]);

  const spf = spfT.res;
  const dmarc = dmarcT.res;
  const dkim = dkimT.res;
  const advanced = advT.res;
  const blacklists = blT.res;
  const nsRecords = nsT.res.nsRecs;
  const nsHealth = nsT.res.nsHealth;
  const caaRecords = caaT.res;
  const mxRedundancy = mxRedT.res;

  const providerInfo = detectMailProvider(mxRecords, spf.record || "");
  const dnsHost = detectDnsHost(nsRecords);
  const mxAllIps = [...new Set([...(blacklists.checkedIps || []), ...mxRedundancy.nodes.flatMap((n) => n.ips || [])])];

  const executionTrace = [
    {
      phase: "NS & SOA Consistency",
      ms: nsT.ms,
      status: nsHealth.status,
      detail: `${nsHealth.count} authoritative NS (${nsHealth.resolvedCount} resolved, ${nsHealth.distinctSubnets} /16 net), SOA ${nsHealth.soa ? `serial ${nsHealth.soa.serial}` : "none"}, ${nsHealth.consistent ? "resolver-consistent" : "drift detected"}`,
    },
    {
      phase: "MX Priority Redundancy",
      ms: mxRedT.ms,
      status: mxRedundancy.status,
      detail: `${mxRedundancy.nodeCount} MX node(s), ${mxRedundancy.priorityTiers.length} priority tier(s), ${mxRedundancy.uniqueIpCount} unique IPv4(s) -> ${providerInfo.en}`,
    },
    {
      phase: "SPF Recursive IP Expansion",
      ms: spfT.ms,
      status: spf.status === "missing" ? "fail" : spf.status,
      detail: `${spf.lookups}/10 lookups (${spf.voidLookups || 0} void), ${spf.ip4Count || 0} IPv4 + ${spf.ip6Count || 0} IPv6 CIDRs across ${spf.layerStats ? spf.layerStats.length : 0} nesting layer(s)`,
    },
    {
      phase: "24-Selector DKIM Sweep",
      ms: dkimT.ms,
      status: dkim.status,
      detail: `Probed ${dkim.checkedCount} selectors -> ${dkim.found.length} active key(s)`,
    },
    {
      phase: "RFC 7489 DMARC Linter",
      ms: dmarcT.ms,
      status: dmarc.status === "missing" ? "fail" : dmarc.status,
      detail: `${dmarc.record ? `p=${dmarc.policy || "invalid"}` : "missing"}, ${(dmarc.syntaxChecks || []).length} tag rule(s) checked, ${(dmarc.syntaxErrors || []).length} syntax error(s)`,
    },
    {
      phase: "BIMI, MTA-STS, CAA & 5 DNSBL",
      ms: Math.max(advT.ms, blT.ms, caaT.ms),
      status: blacklists.hits.length > 0 ? "fail" : "pass",
      detail: `BIMI=${advanced.bimi.present ? "SVG" : "none"}, MTA-STS=${advanced.mtaSts.present ? (advanced.mtaSts.mode || "on") : "none"}, CAA=${caaRecords.length}, DNSBL=${blacklists.hits.length}/5 listed`,
    },
  ];

  const audit = {
    domain,
    requestedDomain: stripped.requestedDomain,
    autoResolved: Boolean(fallbackNote),
    fallbackNote,
    checkedAt,
    elapsedMs: Date.now() - tStart,
    mx: {
      providerId: providerInfo.id,
      provider: providerInfo.en,
      providerZh: providerInfo.zh,
      spfInclude: providerInfo.spfInclude,
      records: mxRecords,
      ips: mxAllIps,
      redundancy: mxRedundancy,
    },
    spf,
    dmarc,
    dkim,
    advanced,
    blacklists,
    dnsMeta: {
      ns: nsRecords,
      nsHealth,
      caa: caaRecords,
      dnsHost,
    },
    executionTrace,
  };
  audit.assessment = scoreDeliverability(audit);
  audit.typoHint = detectTypoOrAltTld(domain, audit);
  return audit;
}

export async function auditFleet(domains, opts = {}, onProgress = null) {
  const clean = [...new Set(domains.map((d) => stripLeadingWww(d).domain).filter(Boolean))].slice(0, 50);
  const concurrency = Math.max(1, Math.min(8, Number(opts.concurrency || 5)));
  const startedAt = nowIso();
  const results = new Array(clean.length);
  let idx = 0;
  let completed = 0;

  await Promise.all(
    Array.from({ length: Math.min(concurrency, clean.length) }, async () => {
      while (idx < clean.length) {
        const i = idx++;
        const r = await auditDomain(clean[i], opts);
        results[i] = r;
        completed++;
        if (onProgress) onProgress({ completed, total: clean.length, result: r });
      }
    })
  );

  const byUrgency = [...results].sort((a, b) => a.assessment.score - b.assessment.score);
  return {
    meta: {
      tool: "InboxShield Web Pro v2.0",
      startedAt,
      finishedAt: nowIso(),
      totalAudited: results.length,
    },
    results,
    byUrgency,
  };
}
