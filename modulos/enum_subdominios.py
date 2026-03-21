# modulos/enum_subdominios.py
# Vlad Volkov — Enumeração de Subdominios via DNS

from __future__ import annotations

import socket
import concurrent.futures
from typing import List, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

SUBDOMINIOS_WORDLIST: list[str] = [
    # Infraestrutura básica
    "www", "www2", "www3", "mail", "email", "webmail", "smtp", "imap", "pop", "pop3",
    "ftp", "sftp", "ftps",
    # API e Desenvolvimento
    "api", "api2", "api3", "rest", "graphql", "grpc", "ws", "websocket",
    "dev", "develop", "development", "stage", "staging", "stg", "sandbox",
    "test", "testing", "qa", "uat", "beta", "alpha", "preview", "demo",
    # Administração
    "admin", "administrator", "panel", "cpanel", "whm", "plesk",
    "portal", "manage", "management", "console", "dashboard",
    "cms", "backend", "bo", "backoffice",
    # Segurança e VPN
    "vpn", "vpn2", "remote", "access", "sso", "auth", "login",
    "secure", "security", "ssl", "tls",
    # CDN e Estático
    "static", "cdn", "assets", "media", "img", "images", "video", "videos",
    "files", "download", "downloads", "upload", "uploads",
    "storage", "s3", "blob", "cache",
    # CI/CD e DevOps
    "git", "gitlab", "github", "bitbucket", "svn",
    "jenkins", "ci", "cd", "build", "deploy", "k8s", "kubernetes",
    "docker", "registry", "artifactory", "nexus",
    "grafana", "prometheus", "kibana", "elastic", "logstash",
    "sonar", "jira", "confluence",
    # Banco de dados
    "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb",
    "redis", "memcache", "elasticsearch", "solr",
    # Comunicação
    "chat", "slack", "teams", "meet", "video",
    "news", "blog", "forum", "community", "support", "help", "docs",
    "kb", "wiki", "knowledge",
    # Monitoramento
    "monitor", "monitoring", "status", "health", "uptime",
    "logs", "log", "metrics", "analytics",
    # Negócios
    "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    "crm", "erp", "hr", "finance",
    "app", "mobile", "ios", "android",
    # Subdominios genéricos
    "internal", "intranet", "extranet", "private", "corp", "corporate",
    "mx", "mail2", "relay", "smtp2",
    "ns", "ns1", "ns2", "dns", "resolver",
    "proxy", "gateway", "vpngateway", "firewall", "fw",
    "backup", "bkp", "archive",
    "old", "legacy", "deprecated", "new",
    "local", "lan", "wlan", "wifi",
    "owa", "autodiscover", "exchange", "ad", "ldap",
    "nagios", "zabbix", "pagerduty",
    "waf", "lb", "loadbalancer", "ha", "cluster",
    "web", "web1", "web2", "web3",
    "server", "srv", "host", "node",
    "us", "eu", "asia", "uk", "br", "de", "fr",
    "us-east", "us-west", "eu-west", "ap-southeast",
]


class EnumeradorSubdominios:
    """Enumera subdominios via DNS com wordlist embutida."""

    def __init__(self, threads: int = 30) -> None:
        self.threads = threads
        self.resultados: list[dict] = []

    def escanear(self, dominio: str, verboso: bool = True) -> list[dict]:
        """Testa todos os subdominios da wordlist e retorna os ativos."""
        self.resultados = []
        dominio = self._extrair_dominio(dominio)

        if verboso:
            console.print(f"\n[bold cyan]  ◉ Enumeração de Subdominios:[/] {dominio}")

        total = len(SUBDOMINIOS_WORDLIST)
        encontrados = 0

        if verboso:
            with Progress(
                SpinnerColumn(),
                TextColumn("    [cyan]Testando subdominios[/]"),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("[dim]ativos: {task.fields[hits]}[/]"),
                console=console,
            ) as prog:
                tarefa = prog.add_task("", total=total, hits=0)

                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as exe:
                    futures = {
                        exe.submit(self._resolver_dns, sub, dominio): sub
                        for sub in SUBDOMINIOS_WORDLIST
                    }
                    for fut in concurrent.futures.as_completed(futures):
                        prog.update(tarefa, advance=1)
                        resultado = fut.result()
                        if resultado:
                            encontrados += 1
                            self.resultados.append(resultado)
                            prog.update(tarefa, hits=encontrados)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as exe:
                futures = {
                    exe.submit(self._resolver_dns, sub, dominio): sub
                    for sub in SUBDOMINIOS_WORDLIST
                }
                for fut in concurrent.futures.as_completed(futures):
                    resultado = fut.result()
                    if resultado:
                        self.resultados.append(resultado)

        return self.resultados

    def exibir_resultado(self) -> None:
        """Exibe subdominios encontrados em tabela."""
        if not self.resultados:
            console.print("    [dim]Nenhum subdominio encontrado.[/]")
            return

        # Ordena por subdominio
        self.resultados.sort(key=lambda x: x["subdominio"])

        tabela = Table(
            title=f"Subdominios Encontrados ({len(self.resultados)})",
            box=box.ROUNDED,
            border_style="cyan",
        )
        tabela.add_column("Subdominio", style="bold cyan")
        tabela.add_column("IP", style="white")
        tabela.add_column("Status HTTP", style="yellow")

        for r in self.resultados:
            status = r.get("status_http", "—")
            if isinstance(status, int):
                if status < 300:
                    cor = "green"
                elif status < 400:
                    cor = "yellow"
                else:
                    cor = "dim"
                status_str = f"[{cor}]{status}[/{cor}]"
            else:
                status_str = f"[dim]{status}[/dim]"

            tabela.add_row(r["subdominio"], r.get("ip", "—"), status_str)

        console.print(tabela)

    # ─────────────────────── PRIVADOS ────────────────────────────────────────

    def _extrair_dominio(self, entrada: str) -> str:
        """Extrai o domínio base de uma URL ou string."""
        entrada = entrada.strip()
        if entrada.startswith(("http://", "https://")):
            parsed = urlparse(entrada)
            return parsed.netloc.split(":")[0]
        # Remove subdominio se enviado (pega apenas dominio.tld)
        return entrada.split(":")[0]

    def _resolver_dns(self, sub: str, dominio: str) -> Optional[dict]:
        """Tenta resolver o subdominio. Retorna dict se resolver."""
        fqdn = f"{sub}.{dominio}"
        try:
            ip = socket.gethostbyname(fqdn)
        except socket.gaierror:
            return None

        # Tenta requisição HTTP para ver status
        status_http: str | int = "—"
        try:
            import requests
            r = requests.get(
                f"http://{fqdn}",
                timeout=5,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; Vlad-Scanner/2.1)"},
            )
            status_http = r.status_code
        except Exception:
            pass

        return {
            "tipo": "subdominio",
            "severidade": "informativo",
            "subdominio": fqdn,
            "ip": ip,
            "status_http": status_http,
            "descricao": f"Subdominio ativo: {fqdn} → {ip}",
        }
