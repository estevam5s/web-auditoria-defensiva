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

  // Baseado em vulnerabilidades encontradas
  if (failChecks.some(c => c.includes('route') || c.includes('hidden') || c.includes('endpoint'))) selected.add('route_scanner');
  if (failChecks.some(c => c.includes('brute') || c.includes('rate') || c.includes('lockout'))) selected.add('brute_force_test');
  if (failChecks.some(c => c.includes('ddos') || c.includes('dos') || c.includes('slowloris'))) selected.add('dos_test');
  if (failChecks.some(c => c.includes('xss') || c.includes('inject') || c.includes('redirect'))) selected.add('xss_scanner');
  if (failChecks.some(c => c.includes('credential') || c.includes('.env') || c.includes('key') || c.includes('bundle'))) selected.add('credential_scanner');

  // Se não encontrou vulnerabilidades específicas, inclui todos
  if (selected.size < 3) {
    Object.keys(SCRIPT_TEMPLATES).forEach(k => selected.add(k));
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
