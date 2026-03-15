# Design — Rota de Proposta de Consultoria `/consulting/:id`
**Data:** 2026-03-15
**Status:** Aprovado pelo usuário

---

## Contexto

O **Supabase Guard** já gera relatórios técnicos (HTML, PDF, Bug Bounty, Checklist). O usuário quer uma nova rota que produza um **documento profissional de proposta de consultoria** — voltado para apresentar ao cliente (empresa do site auditado) um levantamento de vulnerabilidades com serviços recomendados e valores.

---

## Abordagem Escolhida: A — Server-side rendering + Print CSS

O servidor gera HTML completo. O botão "Exportar PDF" usa `window.print()` com `@media print` otimizado. Sem dependências novas. Consistente com o padrão de `report-html.js`.

---

## Seção 1 — Arquitetura e Rota

### Novo arquivo
`audit/report-consulting.js` — exporta `generateConsultingReport(auditData, consultingConfig)` retornando HTML completo auto-contido.

### Rota no `server.js`
```
GET /consulting/:id
```
1. Busca `auditData` do `auditStore.get(id)`. Se não encontrado em memória, tenta buscar do Supabase via `getAuditById(id)`.
2. Se não encontrado: responde 404 com página de erro simples.
3. Lê `consultingConfig` das env vars (com fallback para valores padrão).
4. Aceita override de preços via query params.
5. Serve o HTML gerado por `generateConsultingReport`.

### Novo HTML estático
`public/consulting.html` — página de entrada para a rota `GET /consulting/:id` servida pelo Express. Não necessário — o servidor gera o HTML diretamente.

### Variáveis de Ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `CONSULTANT_NAME` | `Consultor de Segurança` | Nome do consultor/empresa |
| `CONSULTANT_EMAIL` | *(vazio)* | E-mail de contato |
| `CONSULTANT_PHONE` | *(vazio)* | Telefone de contato |
| `CONSULTANT_COMPANY` | *(vazio)* | Nome da empresa consultora |
| `CONSULTING_PRICE_RLS` | `3500` | Preço serviço RLS (R$) |
| `CONSULTING_PRICE_AUTH` | `2800` | Preço serviço Auth (R$) |
| `CONSULTING_PRICE_ENV` | `2000` | Preço serviço Env/Credenciais (R$) |
| `CONSULTING_PRICE_HEADERS` | `1500` | Preço serviço Headers/Hardening (R$) |
| `CONSULTING_PRICE_PENTEST` | `8000` | Preço pentest completo (R$) |
| `CONSULTING_PRICE_HOURLY` | `350` | Valor hora técnica (R$) |

**Override via query param:** `/consulting/:id?price_rls=5000&price_auth=3000`

Os query params aceitam os mesmos nomes sem o prefixo `CONSULTING_` e em minúsculas: `price_rls`, `price_auth`, `price_env`, `price_headers`, `price_pentest`, `price_hourly`.

---

## Seção 2 — Estrutura do Documento

### 1. Capa
- Borda superior azul escuro 6px
- Nome e dados de contato do consultor (do `consultingConfig`)
- Título: **"Proposta de Consultoria em Segurança"**
- URL auditada e data da auditoria
- Score em círculo grande colorido (verde ≥88, laranja ≥52, vermelho <52)
- Veredicto de produção com badge colorido (Apto / Apto com Ressalvas / Não Apto)

### 2. Sumário Executivo
Parágrafo auto-gerado com:
- URL auditada, data, duração
- Total de checks realizados
- Contagem de FAILs, WARNs, PASSes
- Score e grade (A/B/C/D/F com label: Excelente/Bom/Atenção/Risco Elevado/Crítico)
- Frase de encerramento com recomendação de ação

### 3. Levantamento de Vulnerabilidades por Categoria
- Agrupa FAILs e WARNs pelos `SEMANTIC_GROUPS` do engine (RLS, Auth, Service Key, CORS, SSL, etc.)
- Para cada grupo com problemas: header com nome da categoria, severidade máxima encontrada, tabela com colunas: **Check | Status | Severidade | Descrição**
- Badges de severidade coloridos: CRÍTICO (vermelho), ALTO (laranja), MÉDIO (amarelo), BAIXO (azul)
- Grupos sem falhas omitidos desta seção

### 4. Serviços de Consultoria Recomendados
Tabela gerada **dinamicamente** a partir das falhas encontradas:
- Só aparece linha de RLS se houver FAIL/WARN de RLS
- Só aparece linha de Auth se houver FAIL/WARN de Auth
- Etc.
- Sempre inclui linha de "Pentest Completo" como recomendação geral
- Colunas: **Serviço | Descrição | Estimativa | Valor (R$)**
- Linha de total no rodapé
- Nota: *"Valores estimados. Proposta formal mediante escopo detalhado."*

#### Mapeamento grupo → serviço

| Grupo (SEMANTIC_GROUP) | Serviço | Estimativa |
|------------------------|---------|------------|
| `rls` | Implementação e Revisão de RLS | 10h |
| `auth` | Hardening de Autenticação | 8h |
| `env` / `bundle-keys` / `credential` | Correção de Credenciais Expostas | 6h |
| `cors` / `headers` / `security-headers` | Configuração de Headers de Segurança | 4h |
| `service-key` | Rotação e Proteção de Service Key | 4h |
| `ssl` | Auditoria e Configuração SSL/TLS | 6h |
| `ddos` / `brute-force` / `hydra` | Proteção contra Ataques (DDoS/Brute Force) | 12h |
| `port-scan` / `network` | Hardening de Infraestrutura/Rede | 8h |
| `git-exposure` | Remoção de Exposição de Repositório | 3h |
| *(sempre presente)* | Pentest Completo e Relatório Final | 24h |

### 5. Controles Aprovados
Lista compacta de checks com status PASS — demonstra o que já está em conformidade. Exibido em grid de 2 colunas com ícone ✓ verde.

### 6. Próximos Passos
Lista numerada de ações recomendadas, ordenadas por severidade (crítico primeiro), gerada automaticamente a partir dos FAILs. Máximo 10 itens.

### 7. Rodapé
- Dados de contato completos do consultor
- Número do relatório (`auditId`)
- Hash SHA-256 da evidência (primeiros 16 chars)
- Data de geração
- Disclaimer: *"Este documento é confidencial e destinado exclusivamente ao destinatário indicado."*

---

## Seção 3 — Visual e CSS

**Palette:**
- Azul escuro: `#1a2744` — cabeçalhos, bordas, botão PDF
- Cinza claro: `#f5f7fa` — fundos de seção alternados
- Branco: `#ffffff` — fundo principal
- Texto: `#1f2937`
- Crítico: `#dc2626` (vermelho)
- Alto: `#ea580c` (laranja)
- Médio: `#ca8a04` (amarelo/âmbar)
- Baixo: `#2563eb` (azul)
- Aprovado: `#16a34a` (verde)

**Tipografia:** `system-ui, -apple-system, 'Segoe UI', sans-serif` — sem dependência CDN.

**Auto-contido:** sem CDN externo. Funciona offline.

**Botão PDF:** posição `fixed` canto superior direito, `z-index: 1000`, oculto em `@media print`.

**`@media print`:**
- Oculta botão PDF
- `page-break-before: always` antes de cada seção `<section>`
- Remove `box-shadow`
- Força `background: white` e `color: black` onde necessário
- Evita quebra de linha no meio de linhas de tabela: `page-break-inside: avoid` em `<tr>`

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
