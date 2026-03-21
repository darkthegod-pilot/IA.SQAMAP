# modulos/enumerador_web.py
# Vlad Volkov — Enumeração Web
# Diretórios, tecnologias, arquivos sensíveis, cabeçalhos de segurança

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

# ─────────────────────────── WORDLISTS ───────────────────────────────────────

DIRETORIOS_COMUNS: list[str] = [
    "/admin", "/admin/", "/administrator", "/administrator/", "/wp-admin", "/wp-admin/",
    "/login", "/login.php", "/signin", "/user/login", "/auth", "/panel", "/cpanel",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/mysql", "/db", "/database",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
    "/backup", "/backups", "/bak", "/old", "/archive", "/archives",
    "/uploads", "/upload", "/files", "/static", "/media", "/assets",
    "/images", "/img", "/css", "/js", "/scripts",
    "/config", "/configs", "/settings", "/setup", "/install",
    "/test", "/tests", "/dev", "/staging", "/demo",
    "/logs", "/log", "/tmp", "/temp",
    "/include", "/includes", "/lib", "/libs", "/vendor",
    "/cgi-bin", "/cgi-bin/", "/server-status", "/server-info",
    "/wp-content", "/wp-includes", "/wp-login.php", "/wp-json",
    "/xmlrpc.php", "/wp-cron.php",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known", "/.well-known/security.txt",
    "/swagger", "/swagger-ui", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/openapi.json", "/openapi.yaml", "/redoc",
    "/metrics", "/health", "/healthz", "/status", "/ping", "/info",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/console", "/h2-console", "/spring-console",
    "/.git", "/.git/HEAD", "/.git/config",
    "/.svn", "/.svn/entries",
    "/.env", "/.env.backup", "/.env.local", "/.env.prod",
    "/web.config", "/Web.config", "/.htaccess", "/.htpasswd",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/database.yml", "/database.yaml", "/database.php",
    "/wp-config.php", "/wp-config.bak",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/Pipfile",
    "/Makefile", "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/.dockerignore", "/.gitignore", "/.gitconfig",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/shell.php", "/cmd.php", "/webshell.php",
    "/error", "/errors", "/debug", "/trace",
    "/private", "/secret", "/secrets", "/credentials",
    "/dump", "/sql", "/export",
    "/manage.py", "/manage", "/django-admin",
    "/rails", "/app", "/src",
    "/portal", "/intranet", "/extranet",
    "/crm", "/erp", "/hr", "/billing", "/payment",
    "/checkout", "/cart", "/shop", "/store",
    "/user", "/users", "/account", "/accounts", "/profile",
    "/register", "/signup", "/forgot-password", "/reset-password",
    "/api/users", "/api/admin", "/api/config", "/api/settings",
    "/v1", "/v2", "/v3",
]

ARQUIVOS_SENSIVEIS: list[str] = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/config.php", "/wp-config.php", "/settings.php",
    "/database.yml", "/database.yaml",
    "/web.config", "/.htaccess", "/.htpasswd",
    "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/Dockerfile", "/docker-compose.yml",
    "/id_rsa", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/backup.sql", "/dump.sql", "/database.sql", "/backup.tar.gz",
    "/phpinfo.php", "/info.php",
    "/server-status", "/server-info",
    "/crossdomain.xml",
]

# ─────────────────────────── FINGERPRINTS ────────────────────────────────────

TECNOLOGIAS: dict[str, dict] = {
    "WordPress": {
        "headers": [],
        "body": [r"wp-content", r"wp-includes", r"/wp-json/"],
        "paths": ["/wp-login.php", "/wp-admin/"],
    },
    "Joomla": {
        "headers": [],
        "body": [r"/components/com_", r"Joomla!"],
        "paths": ["/administrator/"],
    },
    "Drupal": {
        "headers": [r"X-Generator: Drupal"],
        "body": [r"Drupal\.settings", r"/sites/default/"],
        "paths": [],
    },
    "Laravel": {
        "headers": [],
        "body": [r"laravel_session", r"XSRF-TOKEN"],
        "paths": ["/api", "/sanctum"],
    },
    "Django": {
        "headers": [],
        "body": [r"csrfmiddlewaretoken", r"Django"],
        "paths": ["/admin/", "/django-admin/"],
    },
    "Ruby on Rails": {
        "headers": [r"X-Runtime"],
        "body": [r"authenticity_token"],
        "paths": [],
    },
    "ASP.NET": {
        "headers": [r"X-AspNet-Version", r"X-Powered-By: ASP\.NET"],
        "body": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "paths": [],
    },
    "PHP": {
        "headers": [r"X-Powered-By: PHP"],
        "body": [],
        "paths": ["/phpinfo.php", "/info.php"],
    },
    "Apache": {
        "headers": [r"Server: Apache"],
        "body": [],
        "paths": ["/server-status"],
    },
    "Nginx": {
        "headers": [r"Server: nginx"],
        "body": [],
        "paths": [],
    },
    "IIS": {
        "headers": [r"Server: Microsoft-IIS"],
        "body": [],
        "paths": [],
    },
    "Node.js / Express": {
        "headers": [r"X-Powered-By: Express"],
        "body": [],
        "paths": [],
    },
    "Spring Boot": {
        "headers": [],
        "body": [],
        "paths": ["/actuator", "/actuator/health"],
    },
    "Swagger / OpenAPI": {
        "headers": [],
        "body": [r"swagger-ui", r"openapi"],
        "paths": ["/swagger-ui/", "/swagger.json", "/openapi.json"],
    },
}

CABECALHOS_SEGURANCA = [
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking"),
    ("X-Content-Type-Options", "MIME sniff"),
    ("Strict-Transport-Security", "HSTS"),
    ("X-XSS-Protection", "XSS Filter"),
    ("Referrer-Policy", "Referrer"),
    ("Permissions-Policy", "Permissions"),
]


# ─────────────────────────── SCANNER ─────────────────────────────────────────

class EnumeradorWeb:
    """Enumera recursos web: diretórios, tecnologias, arquivos expostos e cabeçalhos."""

    def __init__(self, timeout: int = 8, verificar_ssl: bool = False,
                 threads: int = 10) -> None:
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl
        self.threads = threads
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; Vlad-Scanner/2.1)",
        })
        self.sessao.verify = verificar_ssl
        self.resultados: list[dict] = []

    # ─────────────────────── PÚBLICO ─────────────────────────────────────────

    def escanear(self, url: str, verboso: bool = True) -> list[dict]:
        """Executa enumeração completa: robots, tecnologias, dirs, arquivos, headers."""
        self.resultados = []
        base = self._normalizar_url(url)

        if verboso:
            console.print(f"\n[bold cyan]  ◉ Enumeração Web:[/] {base}")

        # 1. Cabeçalhos de segurança
        hdrs = self._analisar_cabecalhos_seguranca(base)
        self.resultados.extend(hdrs)

        # 2. Detecção de tecnologias
        techs = self._detectar_tecnologias(base)
        if verboso and techs:
            console.print(f"    [green]✓ Tecnologias:[/] {', '.join(techs)}")

        for t in techs:
            self.resultados.append({
                "tipo": "tecnologia",
                "severidade": "informativo",
                "item": t,
                "descricao": f"Tecnologia identificada: {t}",
                "url": base,
            })

        # 3. robots.txt / sitemap
        robots = self._verificar_robots_sitemap(base)
        self.resultados.extend(robots)

        # 4. Arquivos sensíveis
        if verboso:
            with console.status("    [dim]Verificando arquivos sensíveis...[/]"):
                sensiveis = self._checar_arquivos_sensiveis(base)
        else:
            sensiveis = self._checar_arquivos_sensiveis(base)
        self.resultados.extend(sensiveis)

        # 5. Força bruta de diretórios
        if verboso:
            dirs = self._forcar_diretorios_verbose(base)
        else:
            dirs = self._forcar_diretorios(base, DIRETORIOS_COMUNS)
        self.resultados.extend(dirs)

        return self.resultados

    def exibir_resultado(self) -> None:
        """Exibe resultados em tabela rica."""
        if not self.resultados:
            console.print("    [dim]Nenhum resultado de enumeração.[/]")
            return

        tabela = Table(title="Enumeração Web", box=box.ROUNDED, border_style="cyan")
        tabela.add_column("Tipo", style="cyan", no_wrap=True)
        tabela.add_column("Severidade", style="bold")
        tabela.add_column("Item / Caminho", style="white")
        tabela.add_column("Descrição", style="dim")

        cores = {
            "critico": "bold red",
            "alto": "red",
            "medio": "yellow",
            "baixo": "blue",
            "informativo": "dim",
        }

        for r in self.resultados:
            sev = r.get("severidade", "informativo")
            cor = cores.get(sev, "white")
            tabela.add_row(
                r.get("tipo", ""),
                f"[{cor}]{sev.upper()}[/{cor}]",
                r.get("item", r.get("url", "")),
                r.get("descricao", ""),
            )

        console.print(tabela)

    # ─────────────────────── PRIVADOS ────────────────────────────────────────

    def _normalizar_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")

    def _get(self, url: str) -> Optional[requests.Response]:
        try:
            return self.sessao.get(url, timeout=self.timeout, allow_redirects=True)
        except RequestException:
            return None

    def _analisar_cabecalhos_seguranca(self, base: str) -> list[dict]:
        resultados = []
        resp = self._get(base)
        if not resp:
            return resultados

        for header, descricao in CABECALHOS_SEGURANCA:
            if header.lower() not in {k.lower() for k in resp.headers}:
                resultados.append({
                    "tipo": "header_ausente",
                    "severidade": "baixo",
                    "item": header,
                    "descricao": f"Header de segurança ausente: {header} ({descricao})",
                    "url": base,
                })

        # Cookies sem Secure/HttpOnly
        for ck in resp.cookies:
            problemas = []
            if not ck.secure:
                problemas.append("sem Secure")
            if not ck.has_nonstandard_attr("HttpOnly"):
                problemas.append("sem HttpOnly")
            if problemas:
                resultados.append({
                    "tipo": "cookie_inseguro",
                    "severidade": "medio",
                    "item": f"Cookie: {ck.name}",
                    "descricao": f"Cookie inseguro ({', '.join(problemas)})",
                    "url": base,
                })

        return resultados

    def _detectar_tecnologias(self, base: str) -> list[str]:
        detectadas = []
        resp = self._get(base)
        if not resp:
            return detectadas

        headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.text[:30000]

        for nome, assinaturas in TECNOLOGIAS.items():
            encontrou = False

            for padrao in assinaturas["headers"]:
                if re.search(padrao, headers_str, re.IGNORECASE):
                    encontrou = True
                    break

            if not encontrou:
                for padrao in assinaturas["body"]:
                    if re.search(padrao, body, re.IGNORECASE):
                        encontrou = True
                        break

            if not encontrou:
                for path in assinaturas["paths"]:
                    r2 = self._get(base + path)
                    if r2 and r2.status_code in (200, 301, 302, 403):
                        encontrou = True
                        break

            if encontrou:
                detectadas.append(nome)

        return detectadas

    def _verificar_robots_sitemap(self, base: str) -> list[dict]:
        resultados = []

        for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/.well-known/security.txt"]:
            resp = self._get(base + path)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                # Extrai caminhos sensíveis de robots.txt
                caminhos_proibidos = []
                if "robots.txt" in path:
                    for linha in resp.text.splitlines():
                        linha = linha.strip()
                        if linha.lower().startswith("disallow:"):
                            caminho = linha.split(":", 1)[-1].strip()
                            if caminho and caminho != "/":
                                caminhos_proibidos.append(caminho)

                descricao = f"Encontrado: {path}"
                if caminhos_proibidos:
                    descricao += f" — {len(caminhos_proibidos)} caminhos proibidos revelados"

                resultados.append({
                    "tipo": "arquivo_exposto",
                    "severidade": "informativo",
                    "item": base + path,
                    "descricao": descricao,
                    "url": base + path,
                    "conteudo_resumo": resp.text[:300],
                })

                # Testar os caminhos proibidos do robots
                for cp in caminhos_proibidos[:10]:
                    url_cp = base + cp
                    r2 = self._get(url_cp)
                    if r2 and r2.status_code not in (404, 410):
                        resultados.append({
                            "tipo": "caminho_revelado",
                            "severidade": "medio",
                            "item": url_cp,
                            "descricao": f"Caminho de robots.txt acessível (HTTP {r2.status_code}): {cp}",
                            "url": url_cp,
                        })

        return resultados

    def _checar_arquivos_sensiveis(self, base: str) -> list[dict]:
        resultados = []
        for path in ARQUIVOS_SENSIVEIS:
            resp = self._get(base + path)
            if not resp:
                continue
            if resp.status_code == 200 and len(resp.text) > 5:
                conteudo = resp.text[:200]
                # Verificar se é realmente conteúdo sensível (não página 404 customizada)
                if not any(p in conteudo.lower() for p in ["not found", "404", "error"]):
                    resultados.append({
                        "tipo": "arquivo_sensivel",
                        "severidade": "alto",
                        "item": base + path,
                        "descricao": f"Arquivo sensível exposto: {path}",
                        "url": base + path,
                        "evidencia": conteudo[:100],
                    })

                    # Detectar segredos no conteúdo
                    if re.search(r"(password|passwd|secret|api.?key|token|private.?key)\s*[=:]\s*\S+",
                                 conteudo, re.IGNORECASE):
                        resultados.append({
                            "tipo": "segredo_exposto",
                            "severidade": "critico",
                            "item": base + path,
                            "descricao": f"POSSÍVEL SEGREDO EXPOSTO em {path}",
                            "url": base + path,
                        })

        return resultados

    def _forcar_diretorios(self, base: str, wordlist: list[str]) -> list[dict]:
        resultados = []
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def testar(path: str) -> Optional[dict]:
            resp = self._get(base + path)
            if resp and resp.status_code in (200, 301, 302, 403):
                sev = "medio" if resp.status_code == 200 else "baixo"
                if resp.status_code == 403:
                    sev = "baixo"
                return {
                    "tipo": "diretorio_encontrado",
                    "severidade": sev,
                    "item": base + path,
                    "descricao": f"HTTP {resp.status_code} — {path}",
                    "url": base + path,
                    "status_code": resp.status_code,
                }
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(testar, p): p for p in wordlist}
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    resultados.append(r)

        return resultados

    def _forcar_diretorios_verbose(self, base: str) -> list[dict]:
        resultados = []
        total = len(DIRETORIOS_COMUNS)
        encontrados = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("    [cyan]Brute force de diretórios[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn(f"[dim]encontrados: {{task.fields[hits]}}[/]"),
            console=console,
        ) as prog:
            tarefa = prog.add_task("", total=total, hits=0)

            from concurrent.futures import ThreadPoolExecutor, as_completed

            def testar(path: str) -> Optional[dict]:
                resp = self._get(base + path)
                if resp and resp.status_code in (200, 301, 302, 403):
                    sev = "medio" if resp.status_code == 200 else "baixo"
                    return {
                        "tipo": "diretorio_encontrado",
                        "severidade": sev,
                        "item": base + path,
                        "descricao": f"HTTP {resp.status_code} — {path}",
                        "url": base + path,
                        "status_code": resp.status_code,
                    }
                return None

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(testar, p): p for p in DIRETORIOS_COMUNS}
                done = 0
                for fut in as_completed(futures):
                    done += 1
                    r = fut.result()
                    if r:
                        encontrados += 1
                        resultados.append(r)
                        prog.update(tarefa, advance=1, hits=encontrados)
                    else:
                        prog.update(tarefa, advance=1)

        return resultados
