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

    def __init__(self, timeout: int = 8, verificar_ssl: bool = True,
                 threads: int = 10, modo_furtivo=None) -> None:
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl  # True por padrão (seguro)
        self.threads = threads
        self._furtivo = modo_furtivo
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.sessao.verify = verificar_ssl
        self.resultados: list[dict] = []
        # Tamanho da página 404 para comparação (anti-false-positive)
        self._tamanho_404: int = 0

    # ─────────────────────── PÚBLICO ─────────────────────────────────────────

    def escanear(self, url: str, verboso: bool = True) -> list[dict]:
        """Executa enumeração completa: robots, tecnologias, dirs, arquivos, headers."""
        self.resultados = []
        base = self._normalizar_url(url)

        if verboso:
            console.print(f"\n[bold cyan]  ◉ Enumeração Web:[/] {base}")

        # Calibrar tamanho da página 404 (para evitar falsos positivos)
        self._calibrar_404(base)

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
        """Executa GET com UA rotacionado em modo furtivo."""
        try:
            # Rotacionar UA em modo furtivo
            if self._furtivo and self._furtivo.ativo:
                self._furtivo.atualizar_sessao(self.sessao)
                self._furtivo.aguardar()
            return self.sessao.get(url, timeout=self.timeout, allow_redirects=True)
        except RequestException:
            return None

    def _calibrar_404(self, base: str) -> None:
        """Faz request para URL inexistente para calibrar tamanho de 404 personalizado."""
        try:
            import random
            import string
            caminho_fake = "/" + "".join(random.choices(string.ascii_lowercase, k=16))
            r = self.sessao.get(base + caminho_fake, timeout=self.timeout, allow_redirects=True)
            if r and r.status_code in (200, 404):
                self._tamanho_404 = len(r.text)
        except Exception:
            self._tamanho_404 = 0

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
            # Verificar HttpOnly (case-insensitive)
            httponly = (
                ck.has_nonstandard_attr("HttpOnly")
                or ck.has_nonstandard_attr("httponly")
                or "httponly" in {k.lower() for k in getattr(ck, "_rest", {})}
            )
            if not httponly:
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
            if resp.status_code == 200 and len(resp.text) > 20:
                conteudo = resp.text[:400]
                conteudo_lower = conteudo.lower()

                # Anti-false-positive 1: conteúdo muito parecido com 404 calibrado
                if self._tamanho_404 > 0:
                    diff = abs(len(resp.text) - self._tamanho_404)
                    similaridade = 1 - (diff / max(self._tamanho_404, len(resp.text)))
                    if similaridade > 0.85:  # 85%+ similar = provavelmente 404 custom
                        continue

                # Anti-false-positive 2: conteúdo claramente é página de erro genérica
                palavras_erro = ["page not found", "404 not found", "file not found",
                                 "object not found", "the page you requested"]
                if any(p in conteudo_lower for p in palavras_erro):
                    continue

                # Anti-false-positive 3: content-type HTML para arquivos de config
                ct = resp.headers.get("Content-Type", "").lower()
                if path.endswith((".env", ".yml", ".yaml", ".json", ".xml", ".php",
                                  ".sql", ".cfg", ".config", ".ini")):
                    if "html" in ct and "<html" in conteudo_lower and "<!doctype" in conteudo_lower:
                        continue

                # Passou todas as verificações anti-false-positive
                resultados.append({
                    "tipo": "arquivo_sensivel",
                    "severidade": "alto",
                    "item": base + path,
                    "descricao": f"Arquivo sensível exposto: {path}",
                    "url": base + path,
                    "evidencia": conteudo[:100],
                })

                # Detectar segredos no conteúdo
                if re.search(
                    r"(password|passwd|secret|api[_\-.]?key|token|private[_\-.]?key"
                    r"|access[_\-.]?key|auth[_\-.]?key)\s*[=:]\s*\S+",
                    conteudo, re.IGNORECASE,
                ):
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
