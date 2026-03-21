"""
Detector de WAF — Vlad Volkov
Identifica Web Application Firewalls a partir de respostas HTTP.

Uso:
    python utils/detector_waf.py --alvo "http://alvo.com/pagina?id=1"
    python utils/detector_waf.py --alvo "http://alvo.com" --probe
"""

import argparse
import re
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Instale requests: pip install requests")
    sys.exit(1)

console = Console()

# Assinaturas de WAFs conhecidos
ASSINATURAS_WAF = {
    "Cloudflare": {
        "cabecalhos": [
            ("server", "cloudflare"),
            ("cf-ray", None),
            ("cf-cache-status", None),
        ],
        "corpo": [
            r"cloudflare",
            r"Ray ID: [0-9a-f]{16}",
            r"Attention Required! \| Cloudflare",
        ],
        "codigos_status": [403, 503],
    },
    "ModSecurity": {
        "cabecalhos": [
            ("server", "mod_security"),
        ],
        "corpo": [
            r"Mod_Security",
            r"NAXSI",
            r"ModSecurity",
        ],
        "codigos_status": [403, 406],
    },
    "Imperva (Incapsula)": {
        "cabecalhos": [
            ("x-cdn", "incapsula"),
            ("x-iinfo", None),
        ],
        "corpo": [
            r"Incapsula incident ID",
            r"incapsula",
            r"_Incapsula_Resource",
        ],
        "codigos_status": [403],
    },
    "F5 BIG-IP ASM": {
        "cabecalhos": [
            ("x-wa-info", None),
        ],
        "corpo": [
            r"The requested URL was rejected",
            r"BIG-IP",
            r"F5 Networks",
        ],
        "codigos_status": [403],
    },
    "Akamai": {
        "cabecalhos": [
            ("server", "akamaighost"),
            ("x-check-cacheable", None),
        ],
        "corpo": [
            r"Reference #[0-9a-f.]+",
            r"Akamai",
        ],
        "codigos_status": [403],
    },
    "Sucuri": {
        "cabecalhos": [
            ("x-sucuri-id", None),
            ("x-sucuri-cache", None),
        ],
        "corpo": [
            r"Sucuri Website Firewall",
            r"Access Denied - Sucuri",
        ],
        "codigos_status": [403],
    },
    "Barracuda": {
        "cabecalhos": [
            ("x-barracuda-appid", None),
        ],
        "corpo": [
            r"Barracuda",
        ],
        "cookies": ["barra_counter_session"],
        "codigos_status": [400, 403],
    },
    "AWS WAF": {
        "cabecalhos": [
            ("x-amzn-requestid", None),
            ("x-amz-cf-id", None),
        ],
        "corpo": [
            r"AWS WAF",
        ],
        "codigos_status": [403],
    },
    "Fortinet FortiWeb": {
        "cabecalhos": [],
        "corpo": [
            r"FortiWeb",
            r"Web Application Firewall - Fortinet",
        ],
        "codigos_status": [403],
    },
    "Citrix NetScaler": {
        "cabecalhos": [
            ("via", "NS-CACHE"),
            ("x-nsprotect", None),
        ],
        "corpo": [
            r"NetScaler",
        ],
        "cookies": ["st8id", "ns_af"],
        "codigos_status": [403],
    },
}

# Payloads para provocar o WAF
PAYLOADS_PROBE = [
    "' OR '1'='1",
    "1 UNION SELECT 1,2,3--",
    "1 AND 1=1",
    "'; DROP TABLE test--",
    "1; SELECT SLEEP(0)--",
]

# Recomendações de tamper por WAF
RECOMENDACOES_TAMPER = {
    "Cloudflare": "space2comment,randomcase,charencode",
    "ModSecurity": "modsecurityzeroversioned,space2comment,randomcase",
    "Imperva (Incapsula)": "space2comment,randomcase,between,greatest,charencode",
    "F5 BIG-IP ASM": "randomcase,charencode,space2randomblank",
    "Akamai": "between,chardoubleencode,randomcase,space2comment",
    "Sucuri": "space2comment,randomcase",
    "Barracuda": "percentage,randomcase,space2comment",
    "AWS WAF": "charencode,randomcase,between,space2comment",
    "Fortinet FortiWeb": "space2comment,randomcase,charencode",
    "Citrix NetScaler": "space2comment,between,randomcase",
}


class DetectorWAF:
    """Detecta e identifica WAFs a partir de respostas HTTP."""

    def __init__(self, timeout: int = 10, verificar_ssl: bool = False):
        self.timeout = timeout
        self.verificar_ssl = verificar_ssl
        self.sessao = requests.Session()
        self.sessao.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _requisicao(self, url: str) -> requests.Response:
        """Realiza requisição HTTP com tratamento de erros."""
        try:
            return self.sessao.get(
                url,
                timeout=self.timeout,
                verify=self.verificar_ssl,
                allow_redirects=True
            )
        except requests.RequestException:
            return None

    def _fingerprint(self, resposta) -> list:
        """Identifica WAF a partir de uma resposta HTTP."""
        if resposta is None:
            return []

        cabecalhos = {k.lower(): v.lower() for k, v in resposta.headers.items()}
        corpo = resposta.text.lower()
        cookies = [c.lower() for c in resposta.cookies.keys()]
        detectados = []

        for nome_waf, assinaturas in ASSINATURAS_WAF.items():
            pontuacao = 0

            for nome_cab, valor_cab in assinaturas.get("cabecalhos", []):
                if nome_cab in cabecalhos:
                    if valor_cab is None or valor_cab in cabecalhos[nome_cab]:
                        pontuacao += 3

            for padrao in assinaturas.get("corpo", []):
                if re.search(padrao.lower(), corpo):
                    pontuacao += 2

            for nome_cookie in assinaturas.get("cookies", []):
                if nome_cookie.lower() in cookies:
                    pontuacao += 2

            if resposta.status_code in assinaturas.get("codigos_status", []):
                pontuacao += 1

            if pontuacao >= 3:
                detectados.append((nome_waf, pontuacao))

        return sorted(detectados, key=lambda x: x[1], reverse=True)

    def detectar(self, url: str, modo_probe: bool = False) -> list:
        """Detecta WAFs no alvo."""
        resposta_base = self._requisicao(url)
        todos_detectados = {}

        if modo_probe:
            respostas = [resposta_base] if resposta_base else []
            for payload in PAYLOADS_PROBE:
                url_teste = url + payload if "?" in url else url + "?id=" + payload
                resp = self._requisicao(url_teste)
                if resp:
                    respostas.append(resp)
                    time.sleep(0.3)
        else:
            respostas = [resposta_base] if resposta_base else []

        for resp in respostas:
            for nome_waf, pontuacao in self._fingerprint(resp):
                if nome_waf not in todos_detectados or pontuacao > todos_detectados[nome_waf]:
                    todos_detectados[nome_waf] = pontuacao

        return list(todos_detectados.keys())

    def obter_recomendacao_tamper(self, wafs: list) -> str:
        """Retorna chain de tampers recomendados para os WAFs detectados."""
        for waf in wafs:
            if waf in RECOMENDACOES_TAMPER:
                return RECOMENDACOES_TAMPER[waf]
        return "space2comment,randomcase"

    def obter_info_tecnologia(self, url: str) -> dict:
        """Obtém informações de tecnologia do servidor."""
        resposta = self._requisicao(url)
        if not resposta:
            return {}

        info = {}
        cabecalhos = {k.lower(): v for k, v in resposta.headers.items()}

        # Detectar tecnologia web
        poweredby = cabecalhos.get("x-powered-by", "")
        server = cabecalhos.get("server", "")

        if "php" in poweredby.lower():
            info["tecnologia"] = poweredby
        elif "asp.net" in poweredby.lower():
            info["tecnologia"] = poweredby

        if server:
            info["servidor"] = server

        # Inferir DBMS pela tecnologia
        if "asp.net" in poweredby.lower() or "iis" in server.lower():
            info["dbms"] = "MSSQL (provável)"
        elif "php" in poweredby.lower():
            info["dbms"] = "MySQL (provável)"

        return info


def main():
    parser = argparse.ArgumentParser(
        description="Detector de WAF — Vlad Volkov",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplo: python utils/detector_waf.py --alvo 'http://alvo.com/?id=1' --probe"
    )
    parser.add_argument("--alvo", required=True, help="URL do alvo")
    parser.add_argument("--probe", action="store_true", help="Envia payloads para provocar o WAF")
    parser.add_argument("--recomendar", action="store_true", help="Mostra tampers recomendados")
    args = parser.parse_args()

    console.print()
    console.print(Panel(
        f"[bold white]Analisando:[/bold white] [cyan]{args.alvo}[/cyan]",
        title="[bold red]VLAD VOLKOV — Detector de WAF[/bold red]",
        border_style="red"
    ))

    detector = DetectorWAF()

    with console.status("[bold cyan]Detectando WAF...[/bold cyan]", spinner="dots"):
        wafs = detector.detectar(args.alvo, modo_probe=args.probe)

    console.print()

    if wafs:
        tabela = Table(title="WAFs Detectados", box=box.ROUNDED, border_style="yellow")
        tabela.add_column("WAF", style="bold yellow")
        tabela.add_column("Tampers Recomendados", style="cyan")

        for waf in wafs:
            tampers = RECOMENDACOES_TAMPER.get(waf, "space2comment,randomcase")
            tabela.add_row(waf, tampers)

        console.print(tabela)

        if args.recomendar:
            chain = detector.obter_recomendacao_tamper(wafs)
            console.print()
            console.print(f"[bold green]Comando SQLMap sugerido:[/bold green]")
            console.print(
                f'  [dim]sqlmap -u "{args.alvo}" --tamper={chain} '
                f'--random-agent --delay=2 --batch[/dim]'
            )
    else:
        console.print("[bold green]Nenhum WAF detectado[/bold green] (ou WAF não reconhecido)")


if __name__ == "__main__":
    main()
