# Design — Melhorias Significativas: Supabase Guard v3.3.0
**Data:** 2026-03-14
**Status:** Aprovado pelo usuário (v2 — pós spec review)

---

## Contexto

**Supabase Guard** é um scanner de auditoria defensiva (Node.js/Express) que analisa projetos Supabase/web em busca de 40+ controles de segurança, gerando relatórios em PDF, HTML e JSON.

**Problemas identificados:**
- Credenciais reais hardcoded como fallback em `server.js` (linhas 132-133 e 762), `audit/grok-ai.js` (linha 8) e `audit/supabase-db.js` (linhas 9-10)
- CORS sem restrições em produção (`app.use(cors())`)
- Sem rate limiting nas APIs
- Versão inconsistente: `APP_VERSION = '3.3.0'` mas banner de startup e template de bug bounty ainda dizem `v3.2`
- Código duplicado: `askGrokStream` reimplementa fetch idêntico ao `askGrok`; padrão `auditData || auditStore.get(auditId)` repetido em 5 endpoints
- `.env` exposto mostra valores mascarados — usuário quer conteúdo completo
- Sem veredicto de "Apto para Produção" no relatório
- Sem detecção de dados de clientes (PII/SaaS) em tabelas expostas

---

## Abordagem Escolhida: B — Melhorias Estruturais + Funcionais

---

## Seção 1 — Segurança do Próprio Projeto

### 1.1 Remover credenciais hardcoded

**Localizações a corrigir (todas as 4):**

| Arquivo | Linha(s) | Credencial |
|---------|----------|------------|
| `server.js` | 132-133 | `SUPABASE_URL`, `SUPABASE_ANON_KEY` (fallback em `storeAudit`) |
| `server.js` | ~762 | `GROQ_API_KEY` (fallback no endpoint `/api/bugbounty/generate`) |
| `audit/supabase-db.js` | 9-10 | `SUPABASE_URL`, `SUPABASE_ANON_KEY` em `getSupabaseConfig()` |
| `audit/grok-ai.js` | 8 | `GROQ_API_KEY` |

**Comportamento quando env vars ausentes:**
- `SUPABASE_URL` / `SUPABASE_ANON_KEY` ausentes: `getSupabaseConfig()` retorna `null`; `storeAudit` e rotas de DB logam `[Supabase] Não configurado — pulando persistência.` e continuam sem erro
- `GROQ_API_KEY` ausente: `askGrok` e `generateFixPrompt` retornam `{ success: false, error: 'GROQ_API_KEY não configurada. Defina a variável de ambiente.' }`

### 1.2 CORS

```js
// Variáveis de controle:
// NODE_ENV — 'production' ativa restrição
// CORS_ORIGIN — string com origin permitida (ex: 'https://meusite.com')
//               suporta múltiplas origens separadas por vírgula

const isDev = process.env.NODE_ENV !== 'production';

function parseCorsOrigins(raw) {
  if (!raw) return false; // false = rejeitar todas origens externas
  return raw.split(',').map(s => s.trim());
}

app.use(cors({
  origin: isDev
    ? '*'
    : (req, callback) => {
        const allowed = parseCorsOrigins(process.env.CORS_ORIGIN);
        if (allowed === false) return callback(null, false);
        const origin = req.headers.origin;
        callback(null, allowed.includes(origin) ? origin : false);
      }
}));
```

**Fail-safe em produção:** se `NODE_ENV=production` e `CORS_ORIGIN` não está definido, o CORS **rejeita todas** origens externas (fail closed). Logar aviso no startup: `[CORS] Produção sem CORS_ORIGIN definido — todas origens externas bloqueadas.`

### 1.3 Rate Limiting (em memória, sem dependência nova)

```js
function createRateLimiter(maxReq, windowMs) {
  const counts = new Map();

  // Cleanup periódico a cada windowMs para evitar crescimento unbounded
  setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of counts.entries()) {
      if (now > entry.reset) counts.delete(ip);
    }
  }, windowMs);

  return (req, res, next) => {
    // Extrai IP: respeita x-forwarded-for (proxy), fallback para req.ip
    const ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
    const now = Date.now();
    const entry = counts.get(ip) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count++;
    counts.set(ip, entry);

    if (entry.count > maxReq) {
      const retryAfter = Math.ceil((entry.reset - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter,
        limit: maxReq,
        window: `${windowMs / 1000}s`
      });
    }
    next();
  };
}

// Aplicação:
const auditLimiter = createRateLimiter(5, 60_000);   // 5 req/min
const aiLimiter    = createRateLimiter(20, 60_000);  // 20 req/min

app.post('/api/audit', auditLimiter, ...);
app.use('/api/ai', aiLimiter);

// Nota: este rate limiter é por processo. Em deploy multi-processo (cluster/PM2)
// os contadores não são compartilhados. Para produção com múltiplos workers,
// substituir por Redis-based limiter (fora de escopo desta spec).
```

### 1.4 Correção de versão

Localizar e substituir todas as ocorrências de `v3.2` nos seguintes locais em `server.js`:
- Linha ~1002: banner de startup `Audit Console v3.2`
- Linha ~1005: `NEW Features v3.2`
- Linha ~894: template Markdown de bug bounty `Supabase Guard v3.2`

Resultado: todas passam a exibir `v3.3.0` (consistente com `APP_VERSION = '3.3.0'`).

---

## Seção 2 — Veredicto de Produção

### 2.1 Função `getProductionVerdict(score, results)` — em `audit/engine.js`

Chamada após `calculateScore`. Lógica exaustiva (sem "otherwise" ambíguo):

```js
function getProductionVerdict(score, results) {
  // Definições precisas:
  const criticalFails = results.filter(r =>
    r.status === 'FAIL' && r.severity === 'critical'
  );
  const credentialFails = results.filter(r =>
    r.status === 'FAIL' &&
    /Service Key|\.env|Credential|PII|saas/i.test(r.check)
  );
  const criticalWarns = results.filter(r =>
    r.status === 'WARN' && r.severity === 'critical'
  );

  const hasCriticalFail = criticalFails.length > 0;
  const hasCredentialFail = credentialFails.length > 0;
  const hasCriticalWarn = criticalWarns.length > 0;
  const scoreOk = score >= 85;

  let verdict, label, color;
  const reasons = [];
  const blockers = [];

  if (scoreOk && !hasCriticalFail && !hasCredentialFail && !hasCriticalWarn) {
    // APTO: todas as condições positivas, sem warings críticos
    verdict = 'APTO';
    label   = 'Apto para Produção';
    color   = '#00ff41';
    reasons.push(`Score ${score}/100 ≥ 85`);
    reasons.push('Zero falhas críticas');
    reasons.push('Nenhuma credencial exposta');
    reasons.push('Sem alertas críticos');

  } else if (scoreOk && !hasCriticalFail && !hasCredentialFail && hasCriticalWarn) {
    // APTO COM RESSALVAS: score ok, sem FAILs críticos, mas tem WARNs críticos
    verdict = 'APTO_COM_RESSALVAS';
    label   = 'Apto com Ressalvas';
    color   = '#ffaa00';
    reasons.push(`Score ${score}/100 ≥ 85`);
    reasons.push('Zero falhas críticas');
    criticalWarns.forEach(w => blockers.push(`Alerta crítico: ${w.check}`));

  } else {
    // NAO_APTO: score < 85, OU tem FAILs críticos, OU tem FAILs de credenciais
    verdict = 'NAO_APTO';
    label   = 'Não Apto para Produção';
    color   = '#ff0040';
    if (!scoreOk) blockers.push(`Score ${score}/100 abaixo do mínimo (85)`);
    criticalFails.forEach(f => blockers.push(`Falha crítica: ${f.check}`));
    credentialFails.forEach(f => blockers.push(`Credencial exposta: ${f.check}`));
  }

  return { verdict, label, color, reasons, blockers };
}
```

**Integração em `runFullAudit`:** o campo `productionReady` é adicionado ao objeto final retornado.

### 2.2 Exibição

**`public/app.js`:** após `auditResults` ser preenchido, renderizar banner fixo abaixo do score:
```html
<div id="productionVerdict" style="background: <color>; color: #0a0a0f; ...">
  <strong>🏭 Veredicto de Produção: <verdict label></strong>
  <ul class="blockers">...</ul>   <!-- se NAO_APTO ou APTO_COM_RESSALVAS -->
  <ul class="reasons">...</ul>    <!-- se APTO -->
</div>
```

**`audit/report-html.js`:** seção destacada no topo do relatório exportado, após o score principal, com mesma estrutura colorida.

**JSON API** (`/api/audit/:id`): campo `productionReady` incluído no payload (já está no objeto retornado por `runFullAudit`).

**PDF** (`audit/report-pdf.js`): fora de escopo desta spec — não modificado.

---

## Seção 3 — .env Sem Mascaramento + SaaS PII

### 3.1 `.env` com conteúdo completo — `audit/checks/env-exposure.js`

**Quando:** arquivo `.env` (ou variante da lista `SENSITIVE_PATHS`) retorna HTTP 200 com conteúdo não-HTML.

**Campo adicionado:** `details.rawContent` — string com conteúdo integral do arquivo.

**Importante — isolamento de persistência:**
- `rawContent` é incluído no resultado em memória (para exibição no relatório)
- Antes de salvar para o Supabase, `audit/supabase-db.js` deve remover `rawContent` de todos os `details` dos resultados (strip antes do INSERT)
- Critério de strip: `delete result.details.rawContent` em todos os results antes de serializar para DB

**Exibição:** `audit/report-html.js` e `public/app.js` renderizam `rawContent` em bloco `<pre>` vermelho com aviso:
```
⚠️ Arquivo .env acessível publicamente — conteúdo real exposto:
[bloco com conteúdo]
```

### 3.2 Novo check: `audit/checks/saas-pii.js`

**Padrões de colunas PII (case-insensitive, partial match):**
```js
const PII_PATTERNS = [
  // Crítico
  { pattern: /senha|password|passwd|secret|token|cvv|cvc|pin|ssn|social_security/i, severity: 'critical' },
  { pattern: /cpf|cnpj|cc_number|card_number|numero_cartao|cartao_credito|passport|passaporte/i, severity: 'critical' },
  // Alto
  { pattern: /email|e_mail|telefone|phone|celular|mobile|nascimento|birth_date|dob|data_nascimento/i, severity: 'high' },
  { pattern: /nome|name|full_name|nome_completo|rg|pis|pasep|pix_key|chave_pix|nif/i, severity: 'high' },
  // Médio
  { pattern: /endereco|address|logradouro|cep|zip_code|postal_code|cidade|city|estado|state/i, severity: 'medium' },
  { pattern: /ip_address|user_agent|device_id|session_id/i, severity: 'medium' },
];
```

**Algoritmo:**
1. Obtém tabelas expostas via `GET /rest/v1/` sem autenticação (mesma lógica do `checkRESTExposure`)
2. Para cada tabela com status 200 (acessível sem auth), consulta OpenAPI schema para listar colunas: `GET /rest/v1/?select=*` com header `Accept: application/openapi+json` ou via endpoint `/rest/v1/` (PostgREST retorna OpenAPI)
3. Compara nomes de colunas contra `PII_PATTERNS`
4. Se tabela tem RLS ativa (resultado do `checkRLSStatus` passado como contexto) → não emite FAIL, emite INFO
5. Consolida resultados por severidade máxima encontrada

**Resultado:**
```js
{
  check: '🧑‍💼 SaaS Customer Data Exposure',
  status: 'FAIL' | 'WARN' | 'PASS',
  severity: 'critical' | 'high' | 'medium' | 'info',
  message: string,
  details: {
    exposedTables: [{ table: string, piiColumns: [{ name: string, piiType: string, severity: string }] }],
    recommendation: 'Ative RLS em todas as tabelas com dados de clientes e revise as políticas de acesso.',
    totalPiiColumns: number
  }
}
```

**Integração em `engine.js`:**

Adicionado ao `SEMANTIC_GROUPS`:
```js
{ group: 'saas-pii', pattern: /SaaS Customer|Customer Data/i, weight: 1.8, keyControl: true },
```

Adicionado à lista `checks` em `runFullAudit`:
```js
{ name: '🧑‍💼 SaaS Customer Data Exposure', fn: saasCustomerDataCheck, enabled: config.options.checkSaasPII !== false, usesEmit: true },
```

---

## Seção 4 — Limpeza de Código

### 4.1 `askGrokStream` — eliminar duplicação (`audit/grok-ai.js`)

**Comportamento mantido:** simulação de streaming por palavra (10ms delay) — preservada para compatibilidade com a UI SSE.

**O que muda:** eliminar o bloco de fetch duplicado (linhas 131-145, identico ao de `askGrok`).

```js
// Antes: 48 linhas com fetch próprio + simulação de streaming
// Depois:
async function askGrokStream(auditData, question, onChunk) {
  const result = await askGrok(auditData, question);
  if (!result.success) {
    onChunk({ error: result.error, done: true });
    return;
  }
  const words = result.response.split(' ');
  for (const word of words) {
    onChunk({ content: word + ' ', done: false });
    await new Promise(r => setTimeout(r, 10));
  }
  onChunk({ done: true });
}
```

**Critério de aceitação:** comportamento externo idêntico ao atual — o SSE endpoint `/api/ai/chat` continua enviando chunks por palavra.

### 4.2 `resolveAuditData` — helper em `server.js`

```js
function resolveAuditData(auditId, auditData) {
  return auditData || (auditId ? auditStore.get(auditId) : null);
}
```

**Aplicado nos 5 endpoints** (todos que têm o padrão):
1. `/api/ai/chat`
2. `/api/ai/chat/simple`
3. `/api/ai/fix-prompt`
4. `/api/ai/generate-scripts`
5. `/api/bugbounty/generate`

### 4.3 `storeAudit` — condensar logs (`server.js`)

**Remover:** as ~20 linhas de `console.log` de debug (linhas 114-136 e 140-153), incluindo os blocos `=== STORING AUDIT ===` e `=== SAVE RESULT ===`.

**Manter (3 linhas):**
```js
console.log(`[Audit] Stored ${data.evidence.auditId} | Score: ${data.score} | IP: ${userIp}`);
// ... no callback de saveAuditToSupabase:
if (result.success) console.log(`[Supabase] Audit saved: ${result.auditId}`);
else console.error(`[Supabase] Save failed: ${result.error}`);
```

**Logs detalhados** (bloco completo original) movidos para `if (process.env.NODE_ENV !== 'production')`.

---

## Arquivos Modificados (10 total)

| # | Arquivo | Mudanças |
|---|---------|----------|
| 1 | `server.js` | Remove credentials hardcoded (4 locais), CORS restrito, rate limiter, `resolveAuditData`, condensar logs, fix versão (3 strings) |
| 2 | `audit/grok-ai.js` | Remove `GROQ_API_KEY` hardcoded, simplifica `askGrokStream` |
| 3 | `audit/supabase-db.js` | Remove credentials hardcoded, strip `rawContent` antes de persistir |
| 4 | `audit/engine.js` | `getProductionVerdict`, novo `SEMANTIC_GROUPS` entry, integra `saasCustomerDataCheck` |
| 5 | `audit/checks/env-exposure.js` | Adiciona `rawContent` para `.env` acessíveis |
| 6 | `audit/checks/saas-pii.js` | **NOVO** — SaaS Customer Data Exposure check |
| 7 | `audit/report-html.js` | Seção de veredicto de produção + exibição de `rawContent` |
| 8 | `public/app.js` | Banner de veredicto de produção + exibição de `rawContent` |
| 9 | `public/index.html` | (Se necessário para o banner de veredicto — avaliar em implementação) |
| 10 | `audit/report-pdf.js` | **Fora de escopo** — não modificado nesta spec |

---

## Não incluso (fora de escopo)

- Rate limiting compartilhado entre processos (Redis-based)
- Autenticação nos endpoints da API
- Testes automatizados
- Migração para TypeScript
- Refatoração de estrutura de pastas
- Atualização do `report-pdf.js` com veredicto de produção
