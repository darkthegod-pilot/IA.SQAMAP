"""
Seletor de Tampers — Vlad Volkov
Auto-seleciona scripts de tamper ideais baseado no WAF e DBMS.

Uso:
    python utils/seletor_tamper.py --waf cloudflare --dbms mysql
    python utils/seletor_tamper.py --waf modsecurity --dbms postgresql
    python utils/seletor_tamper.py --listar-wafs
"""

import argparse
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# Mapeamento WAF → Tampers por DBMS
MAPA_WAF_TAMPER = {
    "cloudflare": {
        "all": ["space2comment", "randomcase", "charencode"],
        "mysql": ["space2comment", "randomcase", "charencode"],
        "mssql": ["space2comment", "randomcase", "charencode"],
        "postgresql": ["space2comment", "randomcase", "charencode"],
        "oracle": ["space2comment", "randomcase", "charencode"],
    },
    "modsecurity": {
        "all": ["space2comment", "randomcase", "between"],
        "mysql": ["modsecurityzeroversioned", "space2comment", "randomcase"],
        "mssql": ["space2mssqlblank", "randomcase", "between"],
        "postgresql": ["space2comment", "randomcase", "between"],
        "oracle": ["space2comment", "randomcase"],
    },
    "imperva": {
        "all": ["space2comment", "randomcase", "between", "charencode"],
        "mysql": ["space2comment", "randomcase", "between", "greatest", "charencode"],
        "mssql": ["space2mssqlblank", "randomcase", "between", "charencode"],
        "postgresql": ["space2comment", "randomcase", "between", "greatest", "charencode"],
        "oracle": ["space2comment", "randomcase", "between", "charencode"],
    },
    "f5": {
        "all": ["randomcase", "charencode", "space2randomblank"],
        "mysql": ["randomcase", "charencode", "space2randomblank"],
        "mssql": ["randomcase", "charencode", "space2mssqlblank"],
        "postgresql": ["randomcase", "charencode", "space2randomblank"],
        "oracle": ["randomcase", "charencode", "space2randomblank"],
    },
    "akamai": {
        "all": ["between", "chardoubleencode", "randomcase", "space2comment"],
        "mysql": ["between", "chardoubleencode", "randomcase", "space2comment"],
        "mssql": ["between", "chardoubleencode", "randomcase", "space2mssqlblank"],
        "postgresql": ["between", "chardoubleencode", "randomcase", "space2comment"],
        "oracle": ["between", "chardoubleencode", "randomcase"],
    },
    "sucuri": {
        "all": ["space2comment", "randomcase"],
        "mysql": ["space2comment", "randomcase"],
        "mssql": ["space2mssqlblank", "randomcase"],
        "postgresql": ["space2comment", "randomcase"],
        "oracle": ["space2comment", "randomcase"],
    },
    "barracuda": {
        "all": ["percentage", "randomcase", "space2comment"],
        "mysql": ["space2comment", "randomcase"],
        "mssql": ["percentage", "randomcase", "space2mssqlblank"],
        "postgresql": ["space2comment", "randomcase"],
        "oracle": ["space2comment", "randomcase"],
    },
    "aws": {
        "all": ["charencode", "randomcase", "between", "space2comment"],
        "mysql": ["charencode", "randomcase", "between", "space2comment"],
        "mssql": ["charencode", "randomcase", "between", "space2mssqlblank"],
        "postgresql": ["charencode", "randomcase", "between", "space2comment"],
        "oracle": ["charencode", "randomcase", "between"],
    },
    "fortinet": {
        "all": ["space2comment", "randomcase", "charencode"],
        "mysql": ["space2comment", "randomcase", "charencode"],
        "mssql": ["space2mssqlblank", "randomcase", "charencode"],
        "postgresql": ["space2comment", "randomcase", "charencode"],
        "oracle": ["space2comment", "randomcase"],
    },
    "generico": {
        "all": ["space2comment", "randomcase"],
        "mysql": ["space2comment", "randomcase"],
        "mssql": ["space2mssqlblank", "randomcase"],
        "postgresql": ["space2comment", "randomcase"],
        "oracle": ["space2comment", "randomcase"],
        "sqlite": ["space2comment", "randomcase"],
    },
}

# Tampers incompatíveis por DBMS
INCOMPATIVEIS_DBMS = {
    "modsecurityzeroversioned": ["mssql", "postgresql", "oracle", "sqlite"],
    "modsecurityversioned": ["mssql", "postgresql", "oracle", "sqlite"],
    "versionedkeywords": ["mssql", "postgresql", "oracle", "sqlite"],
    "halfversionedmorekeywords": ["mssql", "postgresql", "oracle", "sqlite"],
    "randomcomments": ["mssql", "postgresql", "oracle", "sqlite"],
    "space2hash": ["mssql", "postgresql", "oracle", "sqlite"],
    "space2mysqlblank": ["mssql", "postgresql", "oracle", "sqlite"],
    "greatest": ["mssql", "sqlite"],
    "ifnull2ifisnull": ["mssql", "postgresql", "oracle", "sqlite"],
    "concat2concatws": ["mssql", "postgresql", "oracle", "sqlite"],
    "space2mssqlblank": ["mysql", "postgresql", "oracle", "sqlite"],
    "space2mssqlhash": ["mysql", "postgresql", "oracle", "sqlite"],
    "percentage": ["mysql", "postgresql", "oracle", "sqlite"],
    "symboliclogical": ["mssql", "postgresql", "oracle", "sqlite"],
}

# Descrições dos tampers em PT-BR
DESCRICOES_TAMPER = {
    "space2comment": "Substitui espaços por /**/",
    "randomcase": "Aleatoriza maiúsculas/minúsculas",
    "charencode": "Codifica caracteres em URL encoding",
    "chardoubleencode": "Dupla codificação URL",
    "between": "Substitui > por NOT BETWEEN 0 AND",
    "greatest": "Substitui > por GREATEST() (MySQL)",
    "modsecurityzeroversioned": "Comentário /*!00000*/ (ModSecurity/MySQL)",
    "space2mssqlblank": "Espaços alternativos para MSSQL",
    "space2randomblank": "Substitui espaços por caracteres brancos aleatórios",
    "apostrophemask": "Substitui ' por equivalente UTF-8",
    "equaltolike": "Substitui = por LIKE",
    "base64encode": "Codifica payload em Base64",
    "percentage": "Insere % entre caracteres (MSSQL)",
}


class SeletorTamper:
    """Seleciona tampers otimizados para WAF/DBMS específicos."""

    def _normalizar_waf(self, nome_waf: str) -> str:
        mapeamentos = {
            "cloudflare": "cloudflare", "cf": "cloudflare",
            "modsecurity": "modsecurity", "mod_security": "modsecurity",
            "imperva": "imperva", "incapsula": "imperva",
            "f5": "f5", "bigip": "f5", "big-ip": "f5",
            "akamai": "akamai",
            "sucuri": "sucuri",
            "barracuda": "barracuda",
            "aws": "aws", "awswaf": "aws",
            "fortinet": "fortinet", "fortiweb": "fortinet",
        }
        return mapeamentos.get(nome_waf.lower(), "generico")

    def _normalizar_dbms(self, nome_dbms: str) -> str:
        mapeamentos = {
            "mysql": "mysql", "mariadb": "mysql",
            "mssql": "mssql", "sqlserver": "mssql",
            "postgresql": "postgresql", "postgres": "postgresql",
            "oracle": "oracle",
            "sqlite": "sqlite",
        }
        return mapeamentos.get(nome_dbms.lower(), "all")

    def _validar_tampers(self, tampers: list, dbms: str):
        """Remove tampers incompatíveis com o DBMS."""
        validos, removidos = [], []
        for t in tampers:
            incomp = INCOMPATIVEIS_DBMS.get(t, [])
            if dbms in incomp:
                removidos.append(t)
            else:
                validos.append(t)
        return validos, removidos

    def selecionar(self, waf: str, dbms: str = "all", verboso: bool = False) -> list:
        """Seleciona tampers ideais para a combinação WAF + DBMS."""
        waf_key = self._normalizar_waf(waf)
        dbms_key = self._normalizar_dbms(dbms)

        if waf_key not in MAPA_WAF_TAMPER:
            waf_key = "generico"

        perfis = MAPA_WAF_TAMPER[waf_key]
        tampers = perfis.get(dbms_key, perfis.get("all", []))

        validos, removidos = self._validar_tampers(tampers, dbms_key)

        if verboso and removidos:
            console.print(
                f"  [yellow]![/yellow] Tampers removidos (incompatível com {dbms}): "
                f"[dim]{', '.join(removidos)}[/dim]"
            )

        return validos

    def construir_chain(self, waf: str, dbms: str = "all", nivel: str = "standard") -> str:
        """Constrói a string de tamper chain."""
        tampers = self.selecionar(waf, dbms, verboso=True)

        if nivel == "light":
            tampers = tampers[:2]
        elif nivel == "heavy" and len(tampers) < 4:
            extras = ["charencode", "between"]
            for e in extras:
                if e not in tampers:
                    tampers.append(e)

        return ",".join(tampers)

    def listar_wafs(self) -> list:
        return list(MAPA_WAF_TAMPER.keys())


def main():
    parser = argparse.ArgumentParser(
        description="Seletor de Tampers — Vlad Volkov",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplo: python utils/seletor_tamper.py --waf cloudflare --dbms mysql"
    )
    parser.add_argument("--waf", help="WAF detectado (cloudflare, modsecurity, imperva...)")
    parser.add_argument("--dbms", default="all", help="Banco de dados (mysql, mssql, postgresql, oracle)")
    parser.add_argument("--nivel", choices=["leve", "padrao", "pesado"], default="padrao")
    parser.add_argument("--listar-wafs", action="store_true", help="Lista WAFs suportados")
    parser.add_argument("--alvo", help="URL alvo (para mostrar comando completo)")
    args = parser.parse_args()

    seletor = SeletorTamper()

    if args.listar_wafs:
        tabela = Table(title="WAFs Suportados", box=box.ROUNDED)
        tabela.add_column("WAF", style="bold yellow")
        for waf in seletor.listar_wafs():
            tabela.add_row(waf)
        console.print(tabela)
        return

    if not args.waf:
        parser.print_help()
        sys.exit(1)

    niveis_map = {"leve": "light", "padrao": "standard", "pesado": "heavy"}
    nivel_en = niveis_map.get(args.nivel, "standard")

    console.print()
    chain = seletor.construir_chain(args.waf, args.dbms, nivel_en)
    tampers = seletor.selecionar(args.waf, args.dbms, verboso=True)

    tabela = Table(
        title=f"Tampers: WAF={args.waf} | DBMS={args.dbms} | Nível={args.nivel}",
        box=box.ROUNDED, border_style="cyan"
    )
    tabela.add_column("Tamper", style="cyan", width=30)
    tabela.add_column("Função", style="white")

    for t in tampers:
        tabela.add_row(t, DESCRICOES_TAMPER.get(t, "Técnica de evasão"))

    console.print(tabela)
    console.print()
    console.print(f"[bold green]Chain:[/bold green] [yellow]--tamper={chain}[/yellow]")

    if args.alvo:
        console.print()
        console.print(f"[bold green]Comando SQLMap:[/bold green]")
        console.print(
            f'  [dim]sqlmap -u "{args.alvo}" --tamper={chain} '
            f'--dbms={args.dbms} --random-agent --delay=2 --batch[/dim]'
        )


if __name__ == "__main__":
    main()
