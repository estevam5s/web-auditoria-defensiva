# Design — Rota de Proposta de Consultoria `/consulting/:id`
**Data:** 2026-03-15
**Status:** Aprovado pelo usuário (v3 — pós spec review iteração 2)

---

## Contexto

O **Supabase Guard** já gera relatórios técnicos (HTML, PDF, Bug Bounty, Checklist). O usuário quer uma nova rota que produza um **documento profissional de proposta de consultoria** — voltado para apresentar ao cliente (empresa do site auditado) um levantamento de vulnerabilidades com serviços recomendados e valores.

---

## Abordagem Escolhida: A — Server-side rendering + Print CSS

O servidor gera HTML completo. O botão "Exportar PDF" usa `window.print()` com `@media print` otimizado. Sem dependências novas. Consistente com o padrão de `report-html.js`.

**Nota de assinatura:** `generateConsultingReport(auditData, consultingConfig)` — o segundo argumento é `consultingConfig` (não `networkInfo`). Desvio intencional do padrão existente: `networkInfo` não é necessário pois todos os dados relevantes já estão em `auditData`.

---

## Seção 1 — Arquitetura e Rota

### Novo arquivo
`audit/report-consulting.js` — exporta `generateConsultingReport(auditData, consultingConfig)` retornando string HTML completa auto-contida.

### Shape de `consultingConfig`
```js
{
  name:    string,  // env CONSULTANT_NAME, default "Consultor de Segurança"
  email:   string,  // env CONSULTANT_EMAIL, default ""
  phone:   string,  // env CONSULTANT_PHONE, default ""
  company: string,  // env CONSULTANT_COMPANY, default ""
  prices: {
    rls:     number, // env CONSULTING_PRICE_RLS, default 3500
    auth:    number, // env CONSULTING_PRICE_AUTH, default 2800
    env:     number, // env CONSULTING_PRICE_ENV, default 2000
    headers: number, // env CONSULTING_PRICE_HEADERS, default 1500
    pentest: number, // env CONSULTING_PRICE_PENTEST, default 8000
    hourly:  number, // env CONSULTING_PRICE_HOURLY, default 350
  }
}
```

**Campos de contato vazios:** se `email`, `phone` ou `company` forem string vazia, o campo é **omitido** do documento renderizado (não exibe linha em branco).

### Shape de `auditData.results[]` (campos usados)
Cada item de `results[]` tem:
- `check` — string: nome do check (ex: `"RLS Policy Check"`)
- `status` — `'PASS' | 'FAIL' | 'WARN' | 'ERROR' | 'INFO'`
- `severity` — `'critical' | 'high' | 'medium' | 'low' | 'info'`
- `message` — string: descrição do resultado

### Outros campos de `auditData` usados
- `projectUrl` — URL auditada
- `score` — número 0-100
- `grade` — `{ grade: string, label: string, color: string }`
- `productionReady` — `{ verdict, label, color, reasons[], blockers[] }`
- `evidence` — `{ auditId: string, sha256: string, timestamp: string }`
- `duration` — string (ex: `"12.3s"`)
- `totalChecks`, `passed`, `failed`, `warnings` — números

### Rota no `server.js`
```
GET /consulting/:id
```
1. `auditData = auditStore.get(req.params.id)`
2. Se não encontrado: tenta `await getAuditById(req.params.id)` (Supabase — mesmo padrão de `/api/audits/db/full/:auditId` já existente)
3. Se ainda não encontrado: responde 404 com HTML inline simples
4. Lê `consultingConfig` das env vars com os defaults acima
5. Aplica overrides de preços via query params — validação: `parseInt(v, 10)`, resultado deve ser > 0 e ≤ 999999; caso contrário **descarta e usa o valor da env var** (ou default hardcoded se a env var também não estiver definida)
6. Serve `res.send(generateConsultingReport(auditData, consultingConfig))`

### Variáveis de Ambiente

| Variável | Padrão |
|----------|--------|
| `CONSULTANT_NAME` | `Consultor de Segurança` |
| `CONSULTANT_EMAIL` | *(vazio)* |
| `CONSULTANT_PHONE` | *(vazio)* |
| `CONSULTANT_COMPANY` | *(vazio)* |
| `CONSULTING_PRICE_RLS` | `3500` |
| `CONSULTING_PRICE_AUTH` | `2800` |
| `CONSULTING_PRICE_ENV` | `2000` |
| `CONSULTING_PRICE_HEADERS` | `1500` |
| `CONSULTING_PRICE_PENTEST` | `8000` |
| `CONSULTING_PRICE_HOURLY` | `350` |

**Override via query param:** `/consulting/:id?price_rls=5000`
Nomes: `price_rls`, `price_auth`, `price_env`, `price_headers`, `price_pentest`, `price_hourly`

### Segurança — HTML Escaping

Todos os campos externos renderizados em HTML passam por `esc(str)`:
```js
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```
Campos obrigatoriamente escaped: `projectUrl`, `result.check`, `result.message`, `consultingConfig.name`, `consultingConfig.email`, `consultingConfig.company`, `consultingConfig.phone`.

---

## Seção 2 — Estrutura do Documento

### 1. Capa
- Borda superior `#1a2744` 6px
- Nome e dados de contato do consultor (`consultingConfig.name`, `.company`, `.email`, `.phone` — campos vazios omitidos)
- Título: **"Proposta de Consultoria em Segurança"**
- URL auditada (escaped) + data formatada: `new Date(evidence.timestamp).toLocaleDateString('pt-BR')`
- Círculo de score: fundo `#1a2744`, texto branco, score grande + grade label
- Badge de veredicto colorido: `productionReady.label` com fundo `productionReady.color`

### 2. Sumário Executivo

Template fixo (todos os campos interpolados via `esc()`):

```
A auditoria de segurança realizada em {projectUrl} em {data} identificou
{failed} falha(s) e {warnings} alerta(s) em um total de {totalChecks}
verificações, com duração de {duration}. O score de segurança obtido foi
{score}/100 (Grau {grade} — {gradeLabel}). {fraseFinal}
```

**`fraseFinal` por faixa de score:**

| Score | Frase |
|-------|-------|
| ≥ 88 | "O sistema apresenta boas práticas de segurança com pontos de melhoria menores." |
| ≥ 72 | "Recomenda-se correção dos itens identificados antes de um lançamento em produção." |
| ≥ 52 | "Atenção necessária: existem vulnerabilidades que devem ser corrigidas com prioridade." |
| ≥ 32 | "Risco elevado: falhas críticas detectadas requerem ação imediata." |
| < 32 | "Situação crítica: o sistema não deve ser mantido em produção até a resolução das falhas identificadas." |

**Precedência de `fraseFinal`:** verificar zero FAILs/WARNs **antes** dos tiers de score. Se `failed === 0 && warnings === 0` → `fraseFinal = "Nenhuma vulnerabilidade foi detectada nas verificações realizadas."` independentemente do score. Só aplicar os tiers de score se houver pelo menos 1 FAIL ou WARN.

Seções 3 e 6 exibem mensagem de conformidade quando zero FAILs/WARNs (definida em cada seção).

### 3. Levantamento de Vulnerabilidades por Categoria

#### Mapeamento de grupos e padrões de detecção

A lógica de agrupamento replica a de `engine.js` (a fonte de verdade permanece lá). A função `getGroup(checkName)` em `report-consulting.js`:

```js
const CONSULT_GROUPS = [
  { group: 'rls',              pattern: /RLS|Row Level/i,                                      label: 'Row Level Security (RLS)' },
  { group: 'service-key',      pattern: /Service Key/i,                                        label: 'Service Key / Chave de Serviço' },
  { group: 'auth',             pattern: /Auth(?!or)|Open Signup/i,                             label: 'Autenticação' },
  { group: 'jwt',              pattern: /JWT/i,                                                 label: 'Configuração JWT' },
  { group: 'bundle-keys',      pattern: /Bundle Key/i,                                         label: 'Chaves em Bundle JS' },
  { group: 'credential',       pattern: /Credential|PII/i,                                     label: 'Credenciais / PII' },
  { group: 'env',              pattern: /\.env|Key Exposure/i,                                 label: 'Arquivos .env Expostos' },
  { group: 'rest',             pattern: /REST|RPC/i,                                            label: 'REST API / RPC' },
  { group: 'cors',             pattern: /CORS/i,                                                label: 'Configuração CORS' },
  { group: 'storage',          pattern: /Storage/i,                                             label: 'Storage Buckets' },
  { group: 'graphql',          pattern: /GraphQL/i,                                             label: 'GraphQL' },
  { group: 'edge',             pattern: /Edge/i,                                                label: 'Edge Functions' },
  { group: 'vuln',             pattern: /Vulnerability/i,                                       label: 'Vulnerabilidades Gerais' },
  { group: 'routes',           pattern: /Route|Hidden/i,                                        label: 'Rotas Ocultas' },
  { group: 'source',           pattern: /Source Code/i,                                         label: 'Código-Fonte' },
  { group: 'sensitive',        pattern: /Sensitive Data/i,                                      label: 'Dados Sensíveis' },
  { group: 'hardening',        pattern: /Hardening|Rate Limit/i,                               label: 'Hardening / Rate Limiting' },
  { group: 'dns',              pattern: /DNS/i,                                                  label: 'DNS' },
  { group: 'realtime',         pattern: /Realtime/i,                                            label: 'Realtime' },
  { group: 'ddos',             pattern: /DDoS|ATTACK/i,                                         label: 'Proteção DDoS' },
  { group: 'brute-force',      pattern: /Brute Force|Lockout/i,                                label: 'Brute Force / Lockout' },
  { group: 'ssl',              pattern: /SSL|TLS/i,                                             label: 'SSL / TLS' },
  { group: 'security-headers', pattern: /Security Headers/i,                                   label: 'Headers de Segurança' },
  { group: 'hydra',            pattern: /Hydra/i,                                               label: 'Simulação Hydra' },
  { group: 'network',          pattern: /Network|Tailscale|VPN/i,                              label: 'Rede / Tailscale' },
  { group: 'dos-advanced',     pattern: /DoS Avançado|Slowloris|ReDoS|Connection Exhaustion/i, label: 'DoS Avançado' },
  { group: 'port-scan',        pattern: /Port Scan|Serviços.*Expostos|Portas.*Abertas/i,       label: 'Port Scan' },
  { group: 'git-exposure',     pattern: /Git Exposure|\.git|docker-compose/i,                  label: 'Exposição de Git' },
  { group: 'open-redirect',    pattern: /Open Redirect|Redirecionamento.*Aberto/i,             label: 'Open Redirect' },
  { group: 'saas-pii',         pattern: /SaaS Customer|Customer Data/i,                        label: 'Dados de Clientes (SaaS PII)' },
];

function getGroup(checkName) {
  for (const { group, pattern } of CONSULT_GROUPS) {
    if (pattern.test(checkName)) return group;
  }
  return 'other';
}
```

#### Renderização
- Filtra `results` por `status === 'FAIL' || status === 'WARN'`
- Agrupa por `getGroup(result.check)`
- Para cada grupo com itens: header com label do grupo + badge de severidade máxima + tabela: **Check | Status | Severidade | Descrição**
- Escala de severidade máxima: `critical > high > medium > low > info` (em ordem de prioridade)
- Badges de severidade: CRÍTICO (`#dc2626`), ALTO (`#ea580c`), MÉDIO (`#ca8a04`), BAIXO (`#2563eb`), INFO (cinza)
- **Edge case — zero FAILs/WARNs:** caixa verde: `"✓ Nenhuma vulnerabilidade encontrada — sistema em conformidade."`

### 4. Serviços de Consultoria Recomendados

#### Mapeamento serviço → grupos ativadores → preço

| Serviço | Grupos que ativam a linha | Preço |
|---------|--------------------------|-------|
| Implementação e Revisão de RLS | `rls` | `prices.rls` |
| Hardening de Autenticação e JWT | `auth`, `jwt` | `prices.auth` |
| Correção de Credenciais Expostas | `env`, `bundle-keys`, `credential`, `service-key` | `prices.env` |
| Configuração de Headers e CORS | `cors`, `security-headers`, `hardening` | `prices.headers` |
| Auditoria e Configuração SSL/TLS | `ssl` | `prices.hourly × 6` |
| Proteção contra Ataques | `ddos`, `brute-force`, `hydra`, `dos-advanced` | `prices.hourly × 12` |
| Hardening de Infraestrutura/Rede | `port-scan`, `network` | `prices.hourly × 8` |
| Remoção de Exposição de Código/Git | `git-exposure`, `source` | `prices.hourly × 3` |
| Proteção de Dados de Clientes (PII) | `saas-pii`, `sensitive` | `prices.hourly × 8` |
| Pentest Completo e Relatório Final | *(sempre presente)* | `prices.pentest` |

**Nota sobre preços:** serviços com preço próprio (`rls`, `auth`, `env`, `headers`, `pentest`) usam seu respectivo valor direto. Demais serviços usam `prices.hourly × horas`. Isso explica por que existem 6 chaves de preço para 10 serviços.

**Colunas:** Serviço | Descrição | Estimativa | Valor (R$)

**Total:** rodapé da tabela com soma de todos os valores.

**Nota abaixo:** *"Valores estimados. Proposta formal mediante definição detalhada do escopo."*

**Edge case — zero FAILs:** apenas linha do Pentest + nota: *"Nenhuma vulnerabilidade crítica detectada. Recomendamos pentest preventivo para validação contínua."*

### 5. Controles Aprovados

- Filtra `results` por `status === 'PASS'`
- Grid 2 colunas, ícone ✓ verde, `esc(result.check)`
- **Edge case — zero PASSes:** `"Nenhum controle aprovado registrado."`

### 6. Próximos Passos

**Ordenação por severidade:**
```js
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
fails.sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));
```

- Filtra `results` por `status === 'FAIL'`
- Ordena por `SEV_ORDER`, pega os primeiros 10
- Cada item: número + `esc(result.check)` + `esc(result.message)`
- **Edge case — zero FAILs:** `"✓ Nenhuma ação imediata necessária — mantenha monitoramento contínuo."`

### 7. Rodapé

- `esc(consultingConfig.name)`, `.company`, `.email`, `.phone` — campos vazios omitidos
- Número: `esc(auditData.evidence.auditId)`
- Hash: `auditData.evidence.sha256.substring(0, 16) + '...'`
- Data da auditoria: `new Date(auditData.evidence.timestamp).toLocaleDateString('pt-BR')`
- Data de geração: `new Date().toLocaleDateString('pt-BR')`
- Disclaimer: *"Este documento é confidencial e destinado exclusivamente ao destinatário indicado."*

---

## Seção 3 — Visual e CSS

**Palette:**
- Azul escuro: `#1a2744` — cabeçalhos, bordas, botão PDF, círculo de score
- Cinza claro: `#f5f7fa` — fundos de seção alternados
- Branco: `#ffffff` — fundo principal
- Texto: `#1f2937`
- Crítico: `#dc2626`
- Alto: `#ea580c`
- Médio: `#ca8a04`
- Baixo: `#2563eb`
- Aprovado: `#16a34a`

**Tipografia:** `system-ui, -apple-system, 'Segoe UI', sans-serif` — sem CDN.

**Botão PDF:** `position: fixed`, canto superior direito, `z-index: 1000`, oculto em `@media print`.

**`@media print`:**
- Oculta botão PDF
- `page-break-before: always` antes de cada `<section>`
- Remove `box-shadow`
- `background: white; color: black` onde necessário
- `page-break-inside: avoid` em `<tr>`

---

## Arquivos Modificados

| # | Arquivo | Mudança |
|---|---------|---------|
| 1 | `audit/report-consulting.js` | **NOVO** — gerador do documento de consultoria |
| 2 | `server.js` | Adiciona rota `GET /consulting/:id` |

**Fora de escopo:**
- Geração de PDF server-side (Puppeteer)
- Autenticação/proteção da rota
- Edição interativa dos preços pela UI
- Localização para outros idiomas
- Envio do documento por e-mail
