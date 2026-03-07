<!--supabase-guard-readme-->
<p align="center">
  <img src="https://img.shields.io/badge/Supabase%20Guard-v3.0.0-6e5cf7?style=for-the-badge&logo=shield" alt="Version">
  <img src="https://img.shields.io/badge/Node.js-18%2B-339933?style=for-the-badge&logo=node.js" alt="Node.js">
  <img src="https://img.shields.io/badge/License-MIT-ff6b6b?style=for-the-badge" alt="License">
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/estevamsouza/supabase-guard/main/public/logo.png" alt="Supabase Guard Logo" width="300">
</p>

<h1 align="center">🛡️ Supabase Guard</h1>

<p align="center">
  <strong>Auditor defensiva de segurança para Supabase e aplicações web</strong>
</p>

<p align="center">
  Sistema avançado de scanner de vulnerabilidades que detecta exposição de dados, chaves de API, configurações inseguras e muito mais em projetos Supabase.
</p>

---

## 📋 Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Funcionalidades](#funcionalidades)
- [Tecnologias](#tecnologias)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Scripts Disponíveis](#scripts-disponíveis)
- [API Endpoints](#api-endpoints)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Exemplo de Uso](#exemplo-de-uso)
- [Relatórios](#relatórios)
- [AI Assistant](#ai-assistant)
- [Segurança](#segurança)
- [Licença](#licença)

---

## 🎯 Sobre o Projeto

**Supabase Guard** é uma ferramenta de auditoria defensiva de código aberto projetada para identificar e reportar vulnerabilidades em projetos Supabase e aplicações web modernas.

### Por que usar?

- **Detecção Automática**: Escaneia automaticamente credenciais (SUPABASE_URL, ANON_KEY) nos bundles JS
- **Cobertura Completa**: Verifica REST API, RPC, GraphQL, Storage, Edge Functions, Realtime, Auth
- **Análise Profunda**: Source code analysis, vulnerability scanner, detection de dados sensíveis
- **Evidência Assinada**: Todos os resultados são assinados com SHA-256 para garantir integridade
- **Relatórios Detalhados**: PDF, HTML, JSON e catálogo visual
- **AI Assistant**: Integração com Grok AI para análise inteligente de resultados

---

## ⚡ Funcionalidades

### 🔐 Módulos de Auditoria

| Módulo | Descrição |
|--------|-----------|
| **Auto-Detect** | Detecta automaticamente SUPABASE_URL e ANON_KEY dos bundles JS |
| **REST API Scan** | Verifica exposição de tabelas e dados via REST API |
| **OpenAPI Introspection** | Mapeia todas as tabelas, colunas e funções RPC |
| **RPC Exposure** | Detecta funções RPC expostas |
| **GraphQL Scan** | Introspection completa de GraphQL |
| **Storage Analysis** | Analisa buckets de storage e permissões |
| **Edge Functions** | Verifica Edge Functions e permissões |
| **Realtime Channels** | Detecta canais Realtime expostos |
| **Auth Settings** | Analisa configurações de autenticação |
| **RLS Policy Check** | Verifica políticas Row Level Security |
| **Relationship RLS** | Detecta vazamentos via joins de tabelas |
| **Bundle Key Scanner** | Escaneia bundles JS/TS para chaves expostas |
| **Sensitive Data Detector** | Detecta dados sensíveis (PII, credenciais) |
| **Source Code Analysis** | Analise profunda do código fonte |
| **Vulnerability Scanner** | Scanner de vulnerabilidades web gerais |
| **Error Detector** | Detecta erros e vazamentos de informação |

### 🎨 Funcionalidades Avançadas

- **AI Assistant**: Chat com Grok AI para análise de resultados
- **Relatórios**: PDF, HTML, JSON, Catálogo Supabase
- **Evidence**: Hash SHA-256 e Audit ID para cada auditoria
- **Streaming**: Progresso em tempo real via SSE

---

## 🛠 Tecnologias

### Backend
- **Node.js** — Runtime JavaScript
- **Express.js** — Framework web
- **Puppeteer** — Headless browser para scraping
- **PDFKit** — Geração de relatórios PDF
- **node-fetch** — Requisições HTTP

### Frontend
- **HTML5** — Interface responsiva
- **CSS3** — Estilos modernos com CSS Variables
- **JavaScript Vanilla** — Lógica do cliente
- **Server-Sent Events (SSE)** — Streaming em tempo real

### APIs & Serviços
- **xAI Grok** — Inteligência Artificial para análise
- **Supabase** — Backend-as-a-Service escaneado

---

## 📦 Instalação

### Pré-requisitos

- Node.js 18+ 
- npm 9+

### Passos

```bash
# 1. Clonar o repositório
git clone https://github.com/estevamsouza/supabase-guard.git
cd supabase-guard

# 2. Instalar dependências
npm install

# 3. Iniciar o servidor
npm start

# 4. Acessar no navegador
# http://localhost:3000
```

---

## 🚀 Como Usar

### Via Interface Web

1. Acesse `http://localhost:3000`
2. Insira a URL do projeto Supabase (ex: `https://xyzproject.supabase.co`)
3. (Opcional) Insira a Anon Key manualmente
4. Clique em **"Iniciar Auditoria"**
5. Aguarde o progresso e veja os resultados
6. Use o **AI Assistant** para perguntar sobre vulnerabilidades

### Via API

```bash
# Executar auditoria
curl -X POST http://localhost:3000/api/audit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://seuprojeto.supabase.co"}'

# Obter resultados
curl http://localhost:3000/api/audits

# Gerar relatório PDF
curl -X POST http://localhost:3000/api/report/pdf \
  -H "Content-Type: application/json" \
  -d '{"auditData": {...}}'
```

---

## 📜 Scripts Disponíveis

| Script | Descrição |
|--------|-----------|
| `npm start` | Inicia o servidor na porta 3000 |
| `npm run dev` | Inicia em modo desenvolvimento |

---

## 🔌 API Endpoints

### Auditoria

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/audit` | Executa auditoria (SSE stream) |
| GET | `/api/audits` | Lista auditorias salvas |
| GET | `/api/audit/:id` | Detalhes de uma auditoria |

### Relatórios

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/report/pdf` | Gera relatório PDF |
| POST | `/api/report/html` | Gera relatório HTML |
| POST | `/api/report/catalog` | Gera catálogo JSON |
| POST | `/api/report/catalog/html` | Gera catálogo HTML |

### AI Assistant

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/ai/chat` | Chat com IA (streaming) |
| POST | `/api/ai/chat/simple` | Chat simples |
| GET | `/api/ai/audit/:id` | Dados para IA |

### Utilitários

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/scrape` | Baixa código fonte (ZIP) |
| GET | `/api/health` | Status do servidor |

---

## 📂 Estrutura do Projeto

```
supabase-guard/
├── audit/
│   ├── checks/              # Módulos de verificação
│   │   ├── auto-detect.js           # Auto-detecção de credenciais
│   │   ├── openapi-introspection.js # OpenAPI/REST scan
│   │   ├── rest-scan-deep.js        # REST scan profundo
│   │   ├── relationship-rls.js      # Relationship RLS
│   │   ├── graphql-scan.js          # GraphQL scan
│   │   ├── auth-settings.js         # Configurações de auth
│   │   ├── source-code.js           # Análise de código fonte
│   │   ├── bundle-keys.js           # Scanner de chaves
│   │   └── ...
│   ├── helpers/
│   │   └── http.js        # Utilitários HTTP
│   ├── engine.js          # Motor de auditoria
│   ├── grok-ai.js        # Integração Grok AI
│   ├── scraper.js        # Download de código fonte
│   ├── report-html.js    # Gerador HTML
│   ├── report-pdf.js     # Gerador PDF
│   └── report-supabase-catalog.js # Catálogo Supabase
├── public/
│   ├── index.html        # Interface principal
│   ├── app.js           # Lógica do frontend
│   └── styles.css       # Estilos
├── server.js            # Servidor Express
├── package.json         # Dependências
└── README.md           # Este arquivo
```

---

## 💡 Exemplo de Uso

### Executando uma Auditoria

```javascript
// Via API REST
const response = await fetch('/api/audit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'https://meuprojeto.supabase.co',
    anonKey: 'eyJhbGciOiJIUzI1NiIs...' // Opcional
  })
});

// Receber resultados via SSE
const reader = response.body.getReader();
const decoder = new TextDecoder();

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  
  const chunk = decoder.decode(value);
  const lines = chunk.split('\n');
  
  for (const line of lines) {
    if (line.startsWith('data: ')) {
      const data = JSON.parse(line.slice(6));
      console.log(data); // Processar eventos
    }
  }
}
```

### Usando o AI Assistant

```javascript
// Perguntar sobre vulnerabilidades
const response = await fetch('/api/ai/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    auditId: 'audit-id-aqui',
    question: 'Quais são as vulnerabilidades críticas?'
  })
});
```

---

## 📊 Relatórios

### Tipos de Relatório

1. **PDF** — Relatório formatado para impressão
2. **HTML** — Relatório interativo visual
3. **JSON** — Dados estruturados para integração
4. **Catálogo Supabase** — Visualização do schema detectado
5. **ZIP Código Fonte** — Download do código escaneado

### Evidência Assinada

Cada auditoria gera:
- **SHA-256 Hash** — Integridade dos resultados
- **Audit ID** — Identificador único
- **Timestamp** — Data e hora da auditoria

---

## 🤖 AI Assistant

O **Supabase Guard** inclui um assistente de IA integrado que pode:

- ✅ Analisar vulnerabilidades encontradas
- ✅ Listar chaves de API/tokens expostos
- ✅ Explicar como corrigir problemas
- ✅ Fornecer código SQL de exemplo
- ✅ Detalhar configurações inseguras
- ✅ Priorizar ações de remediation

### Exemplos de Perguntas

- "Quais são as vulnerabilidades críticas?"
- "Quais chaves de API estão expostas?"
- "Como corrigir os problemas de RLS?"
- "O que afeta minha nota de segurança?"
- "Liste todos os dados sensíveis encontrados"

---

## 🔒 Segurança

### Boas Práticas

- ✅ Não exponha service_role keys em código frontend
- ✅ Ative RLS em todas as tabelas
- ✅ Configure CORS corretamente
- ✅ Desabilite introspection GraphQL em produção
- ✅ Use HTTPS sempre
- ✅ Implemente rate limiting
- ✅Valide inputs e outputs
- ✅Rotate chaves e tokens regularmente

### Auditoria como GUEST

A auditoria é executada simulando um usuário anônimo (GUEST), o que permite descobrir o que um atacante externo poderia acessar sem autenticação.

---

## 📄 Licença

MIT License — Feel free to use, modify, and distribute.

---

## 🙏 Agradecimentos

- [Supabase](https://supabase.com) — Backend-as-a-Service
- [xAI](https://x.ai) — Grok AI
- [Node.js](https://nodejs.org) — Runtime
- [Express.js](https://expressjs.com) — Framework

---

<p align="center">
  <strong>🛡️ Supabase Guard — Protegendo suas aplicações Supabase</strong>
</p>

<p align="center">
  Feito com ❤️ por <a href="https://github.com/estevamsouza">Estevam Souza</a>
</p>

<p align="center">
  <a href="https://github.com/estevamsouza/supabase-guard">
    <img src="https://img.shields.io/github/stars/estevamsouza/supabase-guard?style=social" alt="Stars">
  </a>
  <a href="https://github.com/estevamsouza/supabase-guard/issues">
    <img src="https://img.shields.io/github/issues/estevamsouza/supabase-guard" alt="Issues">
  </a>
</p>
