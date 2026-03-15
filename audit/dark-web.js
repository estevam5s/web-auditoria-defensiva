/* ═══════════════════════════════════════════════════════════════════
   DARK WEB / DEEP WEB INTELLIGENCE MODULE
   Free APIs (no keys needed):
     ✓ OTX AlienVault     — threat indicators, malware, pulses
     ✓ URLScan.io         — web scan results & verdicts
     ✓ HaveIBeenPwned     — all known data breaches (domain filter)
     ✓ HackerTarget       — DNS history, IP lookup
     ✓ IPInfo.io          — IP geolocation / ASN
     ✓ crt.sh             — subdomain enumeration
   Optional (key via .env):
     ✓ VirusTotal         — VIRUSTOTAL_API_KEY
     ✓ Google Safe Browsing — SAFEBROWSING_API_KEY
   ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');
const dns   = require('dns').promises;

const UA = 'Mozilla/5.0 (compatible; SecurityResearchBot/1.0)';

async function safeFetch(url, opts = {}) {
  try {
    const { headers: h = {}, timeout: t, ...rest } = opts;
    const res = await fetch(url, {
      timeout: t || 14000,
      headers: { 'User-Agent': UA, 'Accept': 'application/json, text/html, */*', ...h },
      ...rest,
    });
    return res;
  } catch { return null; }
}

async function safeJSON(url, opts = {}) {
  const res = await safeFetch(url, opts);
  if (!res?.ok) return null;
  try { return await res.json(); } catch { return null; }
}

// ── 1. OTX AlienVault — Free threat intelligence ───────────────
async function checkOTX(domain) {
  const base = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}`;

  const [gen, mal, urls, pdns] = await Promise.allSettled([
    safeJSON(`${base}/general`),
    safeJSON(`${base}/malware`),
    safeJSON(`${base}/url_list`),
    safeJSON(`${base}/passive_dns`),
  ]);

  const g = gen.value;
  const m = mal.value;
  const u = urls.value;
  const d = pdns.value;

  const pulseCount   = g?.pulse_info?.count   || 0;
  const malwareCount = m?.data?.length         || 0;

  const malwareFamilies = [...new Set(
    (m?.data || []).map(x => x.detections?.avast || x.detections?.microsoft || 'Unknown').filter(Boolean)
  )].slice(0, 8);

  const threatenedUrls = (u?.url_list || [])
    .filter(x => x.result?.safebrowsing?.threat || x.result?.urlhaus?.id || x.httpcode >= 400)
    .slice(0, 6)
    .map(x => ({
      url:      x.url,
      threat:   x.result?.safebrowsing?.threat || x.result?.urlhaus?.threat || 'Suspicious',
      httpCode: x.httpcode,
    }));

  const dnsHistory = (d?.passive_dns || []).slice(0, 10).map(r => ({
    ip:      r.address,
    first:   r.first,
    last:    r.last,
    asn:     r.asn,
    country: r.flag?.title,
  }));

  return {
    pulseCount,
    malwareCount,
    malwareFamilies,
    threatLevel: g?.threat_score || 0,
    tags:        g?.tags || [],
    country:     g?.country_name || null,
    threatenedUrls,
    dnsHistory,
    related:     (g?.pulse_info?.pulses || []).slice(0, 5).map(p => ({
      name:        p.name,
      description: p.description?.slice(0, 120),
      created:     p.created,
      tlp:         p.tlp,
      tags:        p.tags?.slice(0, 4),
    })),
  };
}

// ── 2. URLScan.io — Recent scan verdicts ──────────────────────
async function checkURLScan(domain) {
  const data = await safeJSON(
    `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`
  );
  if (!data?.results) return { total: 0, scans: [], malicious: 0, suspicious: 0 };

  const scans = data.results.slice(0, 8).map(s => ({
    uuid:       s.task?.uuid,
    url:        s.page?.url,
    domain:     s.page?.domain,
    ip:         s.page?.ip,
    country:    s.page?.country,
    server:     s.page?.server,
    asn:        s.page?.asnname,
    reportUrl:  `https://urlscan.io/result/${s.task?.uuid}/`,
    screenshot: s.screenshot,
    time:       s.task?.time,
    malicious:  s.verdicts?.overall?.malicious  || false,
    suspicious: s.verdicts?.overall?.suspicious || false,
    score:      s.verdicts?.overall?.score      || 0,
    categories: s.verdicts?.overall?.categories || [],
    tags:       s.verdicts?.urlscan?.tags        || [],
  }));

  return {
    total:      data.total || 0,
    scans,
    malicious:  scans.filter(s => s.malicious).length,
    suspicious: scans.filter(s => s.suspicious && !s.malicious).length,
    mostRecent: scans[0] || null,
  };
}

// ── 3. HIBP — Known data breaches (no key for breach listing) ─
async function checkHIBP(domain) {
  const rootDomain = domain.replace(/^www\./, '');

  // GET /api/v3/breaches lists ALL breaches, no API key needed
  const all = await safeJSON('https://haveibeenpwned.com/api/v3/breaches', {
    h: { 'hibp-api-key': process.env.HIBP_API_KEY || '' },
  });

  if (!Array.isArray(all)) return { total: 0, domainBreaches: [], dataClassFreq: {} };

  // Filter breaches that mention this domain
  const domainBreaches = all.filter(b => {
    const bd = (b.Domain || '').toLowerCase();
    return bd === rootDomain || bd.endsWith('.' + rootDomain) || rootDomain.endsWith('.' + bd);
  });

  // Aggregate data classes across all breaches
  const dataClassFreq = {};
  all.forEach(b => {
    (b.DataClasses || []).forEach(dc => {
      dataClassFreq[dc] = (dataClassFreq[dc] || 0) + 1;
    });
  });

  // Top most-leaked data types
  const topClasses = Object.entries(dataClassFreq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([name, count]) => ({ name, count }));

  return {
    total: all.length,
    domainBreaches: domainBreaches.map(b => ({
      name:        b.Name,
      title:       b.Title,
      domain:      b.Domain,
      breachDate:  b.BreachDate,
      addedDate:   b.AddedDate,
      pwnCount:    b.PwnCount,
      dataClasses: b.DataClasses || [],
      description: (b.Description || '').replace(/<[^>]*>/g, '').slice(0, 250),
      isVerified:  b.IsVerified,
      isSensitive: b.IsSensitive,
      logo:        b.LogoPath,
    })),
    topClasses,
  };
}

// ── 4. HackerTarget + IPInfo — Network exposure ───────────────
async function checkNetwork(domain) {
  let ips = [];
  try { ips = await dns.resolve4(domain); } catch {}
  if (!ips.length) { try { ips = await dns.resolve6(domain); } catch {} }

  const ip = ips[0] || null;
  if (!ip) return { ip: null, ips: [] };

  const [ipInfo, htGeo, htDns] = await Promise.allSettled([
    safeJSON(`https://ipinfo.io/${ip}/json`),
    safeJSON(`https://api.hackertarget.com/geoip/?q=${ip}`),
    safeJSON(`https://api.hackertarget.com/dnslookup/?q=${domain}`),
  ]);

  const info = ipInfo.value;

  return {
    ip,
    ips,
    org:       info?.org      || null,
    city:      info?.city     || null,
    region:    info?.region   || null,
    country:   info?.country  || null,
    timezone:  info?.timezone || null,
    hostname:  info?.hostname || null,
    asn:       info?.org?.split(' ')[0] || null,
    hosting:   info?.org?.replace(/^AS\d+\s+/, '') || null,
    anycast:   info?.anycast  || false,
  };
}

// ── 5. crt.sh subdomains ──────────────────────────────────────
async function checkSubdomains(domain) {
  const data = await safeJSON(`https://crt.sh/?q=%25.${domain}&output=json`);
  if (!Array.isArray(data)) return { count: 0, subdomains: [] };

  const subs = new Set();
  data.forEach(c => {
    (c.name_value || '').split('\n').forEach(n => {
      const clean = n.trim().replace(/^\*\./, '');
      if (clean && clean !== domain && clean.endsWith(domain)) subs.add(clean);
    });
  });

  return {
    count:      subs.size,
    subdomains: [...subs].slice(0, 25),
  };
}

// ── 6. Optional: VirusTotal ───────────────────────────────────
async function checkVirusTotal(domain) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return null;

  const data = await safeJSON(
    `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
    { h: { 'x-apikey': key } }
  );
  if (!data?.data) return null;

  const stats = data.data.attributes?.last_analysis_stats || {};
  const votes = data.data.attributes?.total_votes || {};
  return {
    malicious:  stats.malicious  || 0,
    suspicious: stats.suspicious || 0,
    harmless:   stats.harmless   || 0,
    undetected: stats.undetected || 0,
    reputation: data.data.attributes?.reputation || 0,
    categories: data.data.attributes?.categories || {},
    communityUp: votes.harmless   || 0,
    communityDown: votes.malicious || 0,
  };
}

// ── Risk classifier ───────────────────────────────────────────
function classifyThreat(auditScore, intel) {
  const breachCount    = intel.hibp?.domainBreaches?.length || 0;
  const malwareCount   = intel.otx?.malwareCount            || 0;
  const pulseCount     = intel.otx?.pulseCount              || 0;
  const urlMalicious   = intel.urlscan?.malicious           || 0;
  const vtMalicious    = intel.virustotal?.malicious        || 0;

  // Clean site — don't show
  if (
    auditScore > 85 &&
    breachCount === 0 && malwareCount === 0 &&
    pulseCount === 0 && urlMalicious === 0 && vtMalicious === 0
  ) return null;

  // Dark Web — active threats, critical score, known malware
  if (
    auditScore < 50 ||
    malwareCount > 0 ||
    (breachCount > 0 && auditScore < 65) ||
    urlMalicious > 1 ||
    pulseCount > 5 ||
    vtMalicious > 3
  ) return 'DARK_WEB';

  // Deep Web — moderate risk
  if (
    auditScore < 75 ||
    breachCount > 0 ||
    pulseCount > 0 ||
    urlMalicious > 0 ||
    vtMalicious > 0
  ) return 'DEEP_WEB';

  // Surface Web — minor issues
  return 'SURFACE_WEB';
}

function calcRiskScore(auditScore, intel) {
  let s = (100 - auditScore) * 0.35;
  s += Math.min((intel.hibp?.domainBreaches?.length || 0) * 15, 30);
  s += Math.min((intel.otx?.malwareCount || 0) * 8, 20);
  s += Math.min((intel.otx?.pulseCount   || 0) * 3, 15);
  s += Math.min((intel.urlscan?.malicious || 0) * 5, 15);
  s += Math.min((intel.virustotal?.malicious || 0) * 4, 15);
  return Math.round(Math.min(s, 100));
}

// ── Main runner ───────────────────────────────────────────────
async function runDarkWebScan(auditData) {
  let domain;
  try {
    domain = new URL(auditData.projectUrl.startsWith('http') ? auditData.projectUrl : `https://${auditData.projectUrl}`).hostname.replace(/^www\./, '');
  } catch {
    return { error: 'URL inválida' };
  }

  const [otxR, urlscanR, hibpR, networkR, subsR, vtR] = await Promise.allSettled([
    checkOTX(domain),
    checkURLScan(domain),
    checkHIBP(domain),
    checkNetwork(domain),
    checkSubdomains(domain),
    checkVirusTotal(domain),
  ]);

  const intel = {
    domain,
    timestamp:   new Date().toISOString(),
    auditScore:  auditData.score,
    auditGrade:  auditData.grade,
    auditId:     auditData.evidence?.auditId,
    sha256:      auditData.evidence?.sha256,
    projectUrl:  auditData.projectUrl,
    otx:         otxR.status    === 'fulfilled' ? otxR.value    : { pulseCount: 0, malwareCount: 0, dnsHistory: [], threatenedUrls: [], related: [], malwareFamilies: [] },
    urlscan:     urlscanR.status === 'fulfilled' ? urlscanR.value : { total: 0, scans: [], malicious: 0, suspicious: 0 },
    hibp:        hibpR.status   === 'fulfilled' ? hibpR.value   : { total: 0, domainBreaches: [], topClasses: [] },
    network:     networkR.status === 'fulfilled' ? networkR.value : null,
    subdomains:  subsR.status   === 'fulfilled' ? subsR.value   : { count: 0, subdomains: [] },
    virustotal:  vtR.status     === 'fulfilled' ? vtR.value     : null,
  };

  intel.threatLevel = classifyThreat(auditData.score, intel);
  intel.riskScore   = calcRiskScore(auditData.score, intel);

  return intel;
}

module.exports = { runDarkWebScan, classifyThreat };
