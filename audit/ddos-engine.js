'use strict';

/* ═══════════════════════════════════════════════════════════════════
   DDoS RESILIENCE TEST ENGINE
   Realiza testes de carga HTTP/HTTPS em múltiplas fases progressivas.
   Usa apenas módulos nativos do Node.js (sem dependências externas).
   ═══════════════════════════════════════════════════════════════════ */

const http         = require('http');
const https        = require('https');
const { URL }      = require('url');
const { EventEmitter } = require('events');

// ── Utilitários ──────────────────────────────────────────────────
const ms = () => Date.now();

function percentile(arr, p) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const idx = Math.min(Math.floor((p / 100) * s.length), s.length - 1);
  return s[idx];
}

function mean(arr) {
  if (!arr.length) return 0;
  return Math.round(arr.reduce((a, b) => a + b, 0) / arr.length);
}

// ── Perfis de teste ──────────────────────────────────────────────
const PROFILES = {
  calibration: {
    key: 'calibration', name: 'Calibração Inicial',
    concurrent: 5,   duration: 8,
    color: '#00d4ff', icon: '🔭',
    description: 'Baseline de performance sem pressão',
  },
  light: {
    key: 'light', name: 'Carga Leve',
    concurrent: 20,  duration: 12,
    color: '#22c55e', icon: '🟢',
    description: 'Tráfego normal de produção',
  },
  moderate: {
    key: 'moderate', name: 'Estresse Moderado',
    concurrent: 75,  duration: 15,
    color: '#eab308', icon: '🟡',
    description: 'Pico de tráfego esperado',
  },
  heavy: {
    key: 'heavy', name: 'Ataque Pesado',
    concurrent: 200, duration: 15,
    color: '#f97316', icon: '🟠',
    description: 'Ataque DDoS de média intensidade',
  },
  burst: {
    key: 'burst', name: 'Rajada Extrema',
    concurrent: 400, duration: 8,
    color: '#ef4444', icon: '🔴',
    description: 'Pico extremo / ataque volumétrico',
  },
};

// ── Requisição HTTP única ────────────────────────────────────────
function doRequest(parsedUrl, agent) {
  return new Promise(resolve => {
    const t0  = ms();
    const lib = parsedUrl.protocol === 'https:' ? https : http;

    const req = lib.request({
      hostname: parsedUrl.hostname,
      port:     parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path:     (parsedUrl.pathname || '/') + (parsedUrl.search || ''),
      method:   'GET',
      headers: {
        'User-Agent':      'SupabaseGuard-DDoSTest/1.0 (authorized-security-test)',
        'Accept':          'text/html,application/json,*/*',
        'Connection':      'keep-alive',
        'X-Security-Test': '1',
      },
      agent,
      timeout: 8000,
    }, res => {
      let bytes = 0;
      res.on('data',  d => { bytes += d.length; });
      res.on('end',   () => resolve({ ok: true,  status: res.statusCode, lat: ms() - t0, bytes }));
      res.on('error', () => resolve({ ok: false, error: 'RES_ERR',       lat: ms() - t0 }));
    });

    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'TIMEOUT',  lat: ms() - t0 }); });
    req.on('error',  e  => resolve({ ok: false, error: e.code || 'CONN_ERR', lat: ms() - t0 }));
    req.end();
  });
}

// ── Worker: envia requisições até endAt ──────────────────────────
async function worker(parsedUrl, agent, endAt, bucket) {
  while (ms() < endAt) {
    bucket.push(await doRequest(parsedUrl, agent));
  }
}

// ── Executa uma fase e emite ticks a cada segundo ────────────────
async function runPhase(parsedUrl, profile, emitter, abortSignal) {
  const AgentClass = parsedUrl.protocol === 'https:' ? https.Agent : http.Agent;
  const agent = new AgentClass({
    keepAlive:     true,
    maxSockets:    profile.concurrent,
    maxFreeSockets: Math.ceil(profile.concurrent / 4),
    timeout:       8000,
  });

  const bucket = [];
  const endAt  = ms() + profile.duration * 1000;
  let   prevLen = 0;

  // Timer de tick a cada segundo
  const ticker = setInterval(() => {
    if (abortSignal?.aborted) return;

    const snap    = bucket.slice(prevLen);
    prevLen       = bucket.length;
    const elapsed = profile.duration - Math.max(0, Math.ceil((endAt - ms()) / 1000));

    const okSnap  = snap.filter(r => r.ok);
    const lats    = okSnap.map(r => r.lat);
    const statuses = {};
    snap.forEach(r => { if (r.status) statuses[r.status] = (statuses[r.status] || 0) + 1; });

    emitter.emit('tick', {
      phase:    profile.key,
      elapsed:  Math.min(elapsed, profile.duration),
      duration: profile.duration,
      rps:      snap.length,
      total:    bucket.length,
      errors:   snap.filter(r => !r.ok).length,
      lats: {
        mean: mean(lats),
        p50:  percentile(lats, 50),
        p95:  percentile(lats, 95),
        p99:  percentile(lats, 99),
      },
      statuses,
    });
  }, 1000);

  // Inicia workers em paralelo
  const workers = [];
  for (let i = 0; i < profile.concurrent; i++) {
    workers.push(worker(parsedUrl, agent, endAt, bucket));
  }
  await Promise.all(workers);
  clearInterval(ticker);
  agent.destroy();

  // Estatísticas completas da fase
  const allOk   = bucket.filter(r => r.ok);
  const allFail = bucket.filter(r => !r.ok);
  const lats    = allOk.map(r => r.lat);
  const statusMap = {};
  bucket.forEach(r => { if (r.status) statusMap[r.status] = (statusMap[r.status] || 0) + 1; });
  const errMap = {};
  allFail.forEach(r => { errMap[r.error || 'unknown'] = (errMap[r.error || 'unknown'] || 0) + 1; });
  const totalBytes = bucket.reduce((a, r) => a + (r.bytes || 0), 0);

  return {
    profile:    profile.key,
    name:       profile.name,
    concurrent: profile.concurrent,
    duration:   profile.duration,
    color:      profile.color,
    icon:       profile.icon,
    total:      bucket.length,
    success:    allOk.length,
    errors:     allFail.length,
    errorRate:  bucket.length ? +((allFail.length / bucket.length) * 100).toFixed(1) : 0,
    rps:        Math.round(bucket.length / profile.duration),
    bytes:      totalBytes,
    latency: {
      min:  lats.length ? Math.min(...lats) : 0,
      mean: mean(lats),
      p50:  percentile(lats, 50),
      p95:  percentile(lats, 95),
      p99:  percentile(lats, 99),
      max:  lats.length ? Math.max(...lats) : 0,
    },
    statuses:  statusMap,
    errorBreakdown: errMap,
  };
}

// ── Score de resiliência ─────────────────────────────────────────
function calcResilienceScore(phases) {
  const byKey = Object.fromEntries(phases.map(p => [p.profile, p]));
  let s = 100;

  const heavy = byKey.heavy;
  const burst = byKey.burst;
  const mod   = byKey.moderate;

  if (heavy) {
    if      (heavy.errorRate > 60) s -= 35;
    else if (heavy.errorRate > 30) s -= 22;
    else if (heavy.errorRate > 10) s -= 12;
    else if (heavy.errorRate > 3)  s -= 5;

    if      (heavy.latency.p99 > 15000) s -= 18;
    else if (heavy.latency.p99 > 8000)  s -= 10;
    else if (heavy.latency.p99 > 4000)  s -= 5;
    else if (heavy.latency.p99 > 2000)  s -= 2;
  }

  if (burst) {
    if      (burst.errorRate > 75) s -= 25;
    else if (burst.errorRate > 45) s -= 16;
    else if (burst.errorRate > 20) s -= 9;
    else if (burst.errorRate > 5)  s -= 4;
  }

  if (mod && mod.rps > 800) s = Math.min(100, s + 5);
  else if (mod && mod.rps > 400) s = Math.min(100, s + 2);

  s = Math.max(0, Math.min(100, Math.round(s)));

  let grade, label, color, summary;
  if      (s >= 92) { grade = 'A+'; label = 'Fortaleza';    color = '#22c55e'; summary = 'Infraestrutura extremamente robusta. Resiste a ataques volumétricos com degradação mínima.'; }
  else if (s >= 82) { grade = 'A';  label = 'Forte';        color = '#22c55e'; summary = 'Excelente resiliência. Mantém serviço funcional mesmo sob ataque pesado.'; }
  else if (s >= 72) { grade = 'B+'; label = 'Bom';          color = '#84cc16'; summary = 'Boa resiliência. Pequena degradação sob ataque extremo, mas serviço mantido.'; }
  else if (s >= 60) { grade = 'B';  label = 'Adequado';     color = '#a3e635'; summary = 'Resiliência adequada para produção, com margem de melhoria em cenários extremos.'; }
  else if (s >= 48) { grade = 'C';  label = 'Moderado';     color = '#eab308'; summary = 'Degradação visível sob carga pesada. Recomendado implementar proteção anti-DDoS.'; }
  else if (s >= 35) { grade = 'D';  label = 'Fraco';        color = '#f97316'; summary = 'Alta taxa de erros sob pressão. Risco real de indisponibilidade em ataques reais.'; }
  else              { grade = 'F';  label = 'Vulnerável';   color = '#ef4444'; summary = 'Infraestrutura crítica. Um ataque DDoS moderado pode derrubar o serviço completamente.'; }

  return { score: s, grade, label, color, summary };
}

// ── Recomendações baseadas nos resultados ────────────────────────
function buildRecommendations(phases, resilience) {
  const byKey = Object.fromEntries(phases.map(p => [p.profile, p]));
  const heavy = byKey.heavy;
  const burst = byKey.burst;
  const mod   = byKey.moderate;
  const items = [];

  if ((heavy?.errorRate || 0) > 10 || (burst?.errorRate || 0) > 20) {
    items.push({ priority: 'P1', icon: '🛡️', title: 'Implementar CDN com proteção DDoS', body: 'Cloudflare, AWS Shield ou similar absorvem tráfego volumétrico antes de atingir o servidor. Reduz impacto de ataques L3/L4/L7 em até 99%.' });
  }
  if ((heavy?.latency.p99 || 0) > 3000) {
    items.push({ priority: 'P1', icon: '⚡', title: 'Otimizar tempo de resposta sob carga', body: `Latência p99 de ${heavy?.latency.p99}ms sob carga pesada. Implemente caching (Redis/Memcached), otimize queries e considere horizontal scaling.` });
  }
  if ((burst?.errorRate || 0) > 30) {
    items.push({ priority: 'P1', icon: '🚦', title: 'Configurar Rate Limiting e Throttling', body: 'Limite requisições por IP (ex: 100 req/min). Use nginx rate_limit ou middleware Express. Rejeite graciosamente com 429 em vez de deixar o servidor colapsar.' });
  }
  if ((mod?.rps || 0) < 100) {
    items.push({ priority: 'P2', icon: '📈', title: 'Escalar infraestrutura horizontal', body: 'Throughput abaixo de 100 req/s em carga moderada sugere gargalo. Considere auto-scaling, load balancer e múltiplas instâncias.' });
  }
  if (Object.keys(heavy?.statuses || {}).some(k => +k >= 500)) {
    items.push({ priority: 'P2', icon: '🔧', title: 'Corrigir erros 5xx sob carga', body: 'Erros de servidor detectados sob pressão. Verifique connection pooling do banco de dados, timeouts de queries e limites de recursos do servidor.' });
  }
  items.push({ priority: 'P2', icon: '📊', title: 'Implementar monitoramento de tráfego em tempo real', body: 'Configure alertas para anomalias de tráfego (ex: Datadog, New Relic, Grafana). Detecção precoce reduz impacto de ataques.' });
  items.push({ priority: 'P3', icon: '🌐', title: 'Habilitar HTTP/2 e compressão', body: 'HTTP/2 multiplexing reduz overhead de conexão. Compressão gzip/brotli diminui volume de dados transferidos, melhorando throughput sob carga.' });
  items.push({ priority: 'P3', icon: '🔒', title: 'Configurar CAPTCHA adaptativo', body: 'Para endpoints críticos (login, checkout), implemente CAPTCHA que ativa automaticamente quando tráfego anômalo é detectado.' });

  return items.slice(0, 6);
}

// ── Criador do teste (EventEmitter + Promise run) ────────────────
function createDDoSTest(auditData, options = {}) {
  const emitter = new EventEmitter();
  emitter.setMaxListeners(30);

  const run = async () => {
    let parsed;
    try {
      const raw = (auditData.projectUrl || '').startsWith('http')
        ? auditData.projectUrl
        : `https://${auditData.projectUrl}`;
      parsed = new URL(raw);
    } catch {
      emitter.emit('error', 'URL inválida para o teste DDoS');
      return;
    }

    const keys     = options.profiles || ['calibration', 'light', 'moderate', 'heavy', 'burst'];
    const profiles = keys.map(k => PROFILES[k]).filter(Boolean);
    const totalDur = profiles.reduce((a, p) => a + p.duration, 0) + (profiles.length - 1) * 2;

    emitter.emit('start', {
      target:        parsed.origin,
      totalDuration: totalDur,
      profiles:      profiles.map(p => ({ key: p.key, name: p.name, concurrent: p.concurrent, duration: p.duration, color: p.color, icon: p.icon, description: p.description })),
    });

    const phases = [];

    for (let i = 0; i < profiles.length; i++) {
      const profile = profiles[i];
      emitter.emit('phase_start', {
        phase:      profile.key,
        name:       profile.name,
        concurrent: profile.concurrent,
        duration:   profile.duration,
        color:      profile.color,
        icon:       profile.icon,
        index:      i,
        total:      profiles.length,
      });

      const result = await runPhase(parsed, profile, emitter, options.signal);
      phases.push(result);

      emitter.emit('phase_complete', { phase: profile.key, result, index: i, total: profiles.length });

      // Pausa entre fases
      if (i < profiles.length - 1) {
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    const resilience      = calcResilienceScore(phases);
    const recommendations = buildRecommendations(phases, resilience);

    emitter.emit('complete', {
      phases,
      resilience,
      recommendations,
      target:    parsed.origin,
      timestamp: new Date().toISOString(),
    });
  };

  return { emitter, run };
}

module.exports = { createDDoSTest, PROFILES };
