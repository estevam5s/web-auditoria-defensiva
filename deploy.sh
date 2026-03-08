#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  SUPABASE GUARD — Deploy Script com Cache Bust Automático
#  Uso:
#    ./deploy.sh              → push + reinicia servidor local
#    ./deploy.sh --pm2        → push + reinicia via PM2
#    ./deploy.sh --docker     → push + reinicia container Docker
#    ./deploy.sh --dry-run    → mostra o que faria sem executar
# ═══════════════════════════════════════════════════════════════════

set -e  # Para em qualquer erro

# ── Cores ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()     { echo -e "${CYAN}[deploy]${NC} $1"; }
success() { echo -e "${GREEN}[✔]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✘]${NC} $1"; exit 1; }

# ── Argumentos ────────────────────────────────────────────────────
MODE="local"
DRY_RUN=false

for arg in "$@"; do
  case $arg in
    --pm2)      MODE="pm2" ;;
    --docker)   MODE="docker" ;;
    --railway)  MODE="railway" ;;
    --dry-run)  DRY_RUN=true ;;
  esac
done

# ── Build Hash único para este deploy ─────────────────────────────
BUILD_HASH=$(date +%s | sha256sum | cut -c1-12)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   SUPABASE GUARD — Deploy Automático     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
log "Branch: ${BOLD}${BRANCH}${NC}"
log "Build Hash: ${BOLD}${BUILD_HASH}${NC}"
log "Modo: ${BOLD}${MODE}${NC}"
log "Timestamp: ${TIMESTAMP}"
echo ""

if [ "$DRY_RUN" = true ]; then
  warn "DRY-RUN: nenhuma alteração será feita."
fi

# ── 1. Verificar se há alterações ─────────────────────────────────
log "Verificando alterações no git..."

if [ -z "$(git status --porcelain)" ]; then
  warn "Nenhuma alteração pendente. Continuando com o último commit."
else
  success "Alterações detectadas:"
  git status --short
fi

# ── 2. Atualizar BUILD_HASH no .env de produção ───────────────────
log "Atualizando BUILD_HASH..."

if [ "$DRY_RUN" = false ]; then
  # Cria/atualiza .env.production com o novo hash
  if [ -f ".env.production" ]; then
    if grep -q "BUILD_HASH" .env.production; then
      # macOS/Linux compatible sed
      sed -i.bak "s/BUILD_HASH=.*/BUILD_HASH=${BUILD_HASH}/" .env.production && rm -f .env.production.bak
    else
      echo "BUILD_HASH=${BUILD_HASH}" >> .env.production
    fi
  else
    echo "BUILD_HASH=${BUILD_HASH}" > .env.production
    echo "NODE_ENV=production" >> .env.production
    echo "PORT=2998" >> .env.production
  fi
  success "BUILD_HASH=${BUILD_HASH} salvo em .env.production"
fi

# ── 3. Git: stage, commit e push ──────────────────────────────────
log "Preparando commit..."

if [ "$DRY_RUN" = false ]; then
  # Stage todos os arquivos modificados (exclui node_modules e .env secrets)
  git add -A -- \
    ':!node_modules' \
    ':!.env' \
    ':!*.log' \
    ':!*.bak'

  # Só commita se tiver algo staged
  if ! git diff --cached --quiet; then
    git commit -m "deploy: cache-bust ${BUILD_HASH} — ${TIMESTAMP}

- Build hash: ${BUILD_HASH}
- Timestamp: ${TIMESTAMP}
- Branch: ${BRANCH}

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
    success "Commit criado."
  else
    warn "Nada para commitar — apenas fazendo push do último commit."
  fi

  log "Fazendo push para origin/${BRANCH}..."
  git push origin "${BRANCH}"
  success "Push concluído."
else
  warn "[DRY-RUN] Pulando git commit/push."
fi

# ── 4. Reiniciar servidor (invalidar cache do lado do servidor) ───
log "Reiniciando servidor com novo BUILD_HASH..."

if [ "$DRY_RUN" = false ]; then
  case $MODE in

    pm2)
      if command -v pm2 &>/dev/null; then
        pm2 restart supabase-guard --update-env 2>/dev/null || \
        pm2 start server.js --name supabase-guard --env production
        success "PM2 reiniciado."
        pm2 list
      else
        error "PM2 não encontrado. Instale com: npm install -g pm2"
      fi
      ;;

    docker)
      CONTAINER=$(docker ps -q --filter "name=supabase-guard" 2>/dev/null | head -1)
      if [ -n "$CONTAINER" ]; then
        docker restart "$CONTAINER"
        success "Container Docker reiniciado: $CONTAINER"
      else
        warn "Container 'supabase-guard' não encontrado. Tentando docker-compose..."
        if [ -f "docker-compose.yml" ]; then
          docker-compose up -d --build
          success "docker-compose up executado."
        else
          error "Nenhum container ou docker-compose.yml encontrado."
        fi
      fi
      ;;

    railway)
      if command -v railway &>/dev/null; then
        railway up
        success "Deploy Railway iniciado."
      else
        warn "Railway CLI não encontrado. O push ao GitHub já deve acionar o deploy automático."
      fi
      ;;

    local)
      # Mata processo na porta 2998 e reinicia
      PORT=${PORT:-2998}
      PID=$(lsof -ti tcp:${PORT} 2>/dev/null || true)
      if [ -n "$PID" ]; then
        kill -9 $PID 2>/dev/null && success "Processo anterior (PID $PID) finalizado."
      fi
      # Exporta o novo BUILD_HASH para o processo
      export BUILD_HASH="${BUILD_HASH}"
      nohup node server.js > server.log 2>&1 &
      NEW_PID=$!
      sleep 1
      if kill -0 $NEW_PID 2>/dev/null; then
        success "Servidor reiniciado na porta ${PORT} (PID ${NEW_PID})"
        log "Logs em: server.log"
      else
        error "Falha ao iniciar o servidor. Verifique server.log"
      fi
      ;;
  esac
else
  warn "[DRY-RUN] Pulando reinício do servidor (modo: ${MODE})."
fi

# ── 5. Verificar /api/version após deploy ────────────────────────
if [ "$DRY_RUN" = false ] && [ "$MODE" = "local" ]; then
  sleep 2
  PORT=${PORT:-2998}
  log "Verificando /api/version..."
  RESPONSE=$(curl -sf "http://localhost:${PORT}/api/version" 2>/dev/null || echo "")
  if [ -n "$RESPONSE" ]; then
    success "Servidor respondendo:"
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
  else
    warn "Servidor ainda não respondeu (pode levar alguns segundos)."
  fi
fi

# ── Resumo ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║         Deploy concluído com sucesso!     ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Build Hash:${NC}  ${BUILD_HASH}"
echo -e "  ${BOLD}Branch:${NC}      ${BRANCH}"
echo -e "  ${BOLD}Timestamp:${NC}   ${TIMESTAMP}"
echo -e "  ${BOLD}Modo:${NC}        ${MODE}"
echo ""
echo -e "  ${CYAN}O Service Worker irá detectar o novo buildHash"
echo -e "  e recarregar automaticamente para todos os clientes.${NC}"
echo ""
