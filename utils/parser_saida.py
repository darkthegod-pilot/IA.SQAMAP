"""
Parser de Saída SQLMap — Vlad Volkov
Analisa e exibe a saída do SQLMap de forma rica e legível.

Uso:
    from utils.parser_saida import ParserSaida
    parser = ParserSaida()
    resultado = parser.analisar(output_sqlmap)
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


@dataclass
class ResultadoSQLMap:
    """Resultado parseado de uma execução do SQLMap."""
    injetavel: bool = False
    tecnicas_encontradas: List[str] = field(default_factory=list)
    dbms: Optional[str] = None
    dbms_versao: Optional[str] = None
    sistema_op: Optional[str] = None
    usuario_db: Optional[str] = None
    eh_dba: bool = False
    banco_atual: Optional[str] = None
    bancos: List[str] = field(default_factory=list)
    tabelas: List[str] = field(default_factory=list)
    colunas: List[str] = field(default_factory=list)
    dados_extraidos: List[Dict] = field(default_factory=list)
    parametros_injetaveis: List[str] = field(default_factory=list)
    waf_detectado: Optional[str] = None
    tampers_usados: List[str] = field(default_factory=list)
    erros: List[str] = field(default_factory=list)
    avisos: List[str] = field(default_factory=list)
    raw: str = ""


# Padrões de regex para parsing
PADROES = {
    "injetavel": re.compile(
        r"(Parameter|parameter)\s+['\"]?(\w+)['\"]?\s+(is|appears to be)\s+(?:dynamic\s+and\s+)?(?:vulnerable|injectable)",
        re.IGNORECASE
    ),
    "tecnica": re.compile(
        r"---\s*\n.*?Type:\s*(.+?)\n.*?Title:\s*(.+?)\n",
        re.DOTALL
    ),
    "dbms": re.compile(
        r"(?:back-end DBMS|DBMS):\s*(.+?)(?:\n|$)",
        re.IGNORECASE
    ),
    "dbms_versao": re.compile(
        r"(?:web application|web server)\s+(?:technology|operating system):.+?(?:\n|$)|"
        r"banner:\s*'(.+?)'",
        re.IGNORECASE
    ),
    "sistema_op": re.compile(
        r"(?:operating system|web server OS):\s*(.+?)(?:\n|$)",
        re.IGNORECASE
    ),
    "usuario": re.compile(
        r"current user:\s*'?(.+?)'?(?:\n|$)",
        re.IGNORECASE
    ),
    "dba": re.compile(
        r"current user is DBA",
        re.IGNORECASE
    ),
    "banco_atual": re.compile(
        r"current database(?:\s+\(fingerprintable\))?:\s*'?(.+?)'?(?:\n|$)",
        re.IGNORECASE
    ),
    "bancos": re.compile(
        r"\[\*\]\s+(\w+)(?:\s*\(current\))?(?:\n|$)"
    ),
    "tabelas": re.compile(
        r"\|\s+(\w+)\s+\|"
    ),
    "waf": re.compile(
        r"(?:WAF/IPS|web application firewall).*?identified:\s*(.+?)(?:\n|$)",
        re.IGNORECASE
    ),
    "parametro_injetavel": re.compile(
        r"Parameter:\s*['\"]?(\w+)['\"]?\s+\((GET|POST|Cookie|Header)\)",
        re.IGNORECASE
    ),
    "erro": re.compile(
        r"\[ERROR\]\s*(.+?)(?:\n|$)",
        re.IGNORECASE
    ),
    "aviso": re.compile(
        r"\[WARNING\]\s*(.+?)(?:\n|$)",
        re.IGNORECASE
    ),
    "dados_linha": re.compile(
        r"\|\s+(.+?)\s+\|\s+(.+?)\s+\|"
    ),
}

# Mapeamento de técnicas para nomes PT-BR
NOMES_TECNICA = {
    "Boolean-based blind": "Boolean-based Blind (B)",
    "Time-based blind": "Time-based Blind (T)",
    "Error-based": "Error-based (E)",
    "UNION query": "UNION-based (U)",
    "Stacked queries": "Stacked Queries (S)",
    "Out-of-band": "Out-of-band DNS (Q)",
}


class ParserSaida:
    """Parseia a saída do SQLMap e extrai informações relevantes."""

    def analisar(self, saida: str) -> ResultadoSQLMap:
        """Analisa a saída completa do SQLMap."""
        resultado = ResultadoSQLMap(raw=saida)

        self._extrair_injetabilidade(saida, resultado)
        self._extrair_tecnicas(saida, resultado)
        self._extrair_dbms(saida, resultado)
        self._extrair_sistema(saida, resultado)
        self._extrair_usuario(saida, resultado)
        self._extrair_banco(saida, resultado)
        self._extrair_bancos(saida, resultado)
        self._extrair_parametros(saida, resultado)
        self._extrair_waf(saida, resultado)
        self._extrair_erros_avisos(saida, resultado)

        return resultado

    def _extrair_injetabilidade(self, saida: str, resultado: ResultadoSQLMap):
        match = PADROES["injetavel"].search(saida)
        if match or "is vulnerable" in saida.lower() or "injectable" in saida.lower():
            resultado.injetavel = True
        if "sqlmap identified the following injection" in saida.lower():
            resultado.injetavel = True

    def _extrair_tecnicas(self, saida: str, resultado: ResultadoSQLMap):
        for padrao_nome, nome_pt in NOMES_TECNICA.items():
            if padrao_nome.lower() in saida.lower():
                if nome_pt not in resultado.tecnicas_encontradas:
                    resultado.tecnicas_encontradas.append(nome_pt)

    def _extrair_dbms(self, saida: str, resultado: ResultadoSQLMap):
        match = PADROES["dbms"].search(saida)
        if match:
            resultado.dbms = match.group(1).strip()

        # Tentar extrair versão do banner
        banner_match = re.search(r"banner:\s*'(.+?)'", saida, re.IGNORECASE)
        if banner_match:
            resultado.dbms_versao = banner_match.group(1).strip()

    def _extrair_sistema(self, saida: str, resultado: ResultadoSQLMap):
        match = PADROES["sistema_op"].search(saida)
        if match:
            resultado.sistema_op = match.group(1).strip()

    def _extrair_usuario(self, saida: str, resultado: ResultadoSQLMap):
        match = PADROES["usuario"].search(saida)
        if match:
            resultado.usuario_db = match.group(1).strip().strip("'")

        if PADROES["dba"].search(saida):
            resultado.eh_dba = True

    def _extrair_banco(self, saida: str, resultado: ResultadoSQLMap):
        match = PADROES["banco_atual"].search(saida)
        if match:
            resultado.banco_atual = match.group(1).strip().strip("'")

    def _extrair_bancos(self, saida: str, resultado: ResultadoSQLMap):
        # Detectar seção de bancos
        if "available databases" in saida.lower() or "Database:" in saida:
            matches = re.findall(r"\[\*\]\s+(\w+)", saida)
            resultado.bancos = [m for m in matches if m not in ("WARNING", "ERROR", "INFO", "CRITICAL")]

        # Tabelas
        if "Database tables" in saida or "tables" in saida.lower():
            tabela_matches = re.findall(r"\|\s+(\w[\w\s]*\w)\s+\|", saida)
            for t in tabela_matches:
                t = t.strip()
                if t and t not in resultado.tabelas and len(t) < 60:
                    resultado.tabelas.append(t)

    def _extrair_parametros(self, saida: str, resultado: ResultadoSQLMap):
        matches = PADROES["parametro_injetavel"].findall(saida)
        for param, metodo in matches:
            entrada = f"{param} ({metodo})"
            if entrada not in resultado.parametros_injetaveis:
                resultado.parametros_injetaveis.append(entrada)

    def _extrair_waf(self, saida: str, resultado: ResultadoSQLMap):
        match = PADROES["waf"].search(saida)
        if match:
            resultado.waf_detectado = match.group(1).strip()

        # Detectar tampers sugeridos
        tamper_matches = re.findall(r"--tamper=([^\s]+)", saida)
        resultado.tampers_usados = tamper_matches

    def _extrair_erros_avisos(self, saida: str, resultado: ResultadoSQLMap):
        erros = PADROES["erro"].findall(saida)
        resultado.erros = erros[:10]  # Limitar a 10

        avisos = PADROES["aviso"].findall(saida)
        resultado.avisos = [a for a in avisos[:5] if "might not be" not in a]

    def exibir_resultado(self, resultado: ResultadoSQLMap) -> None:
        """Exibe o resultado parseado em formato rico."""
        console.print()

        if resultado.injetavel:
            status_text = Text("VULNERÁVEL — INJEÇÃO SQL CONFIRMADA", style="bold white on red")
            border = "red"
        else:
            status_text = Text("Nenhuma injeção detectada", style="bold green")
            border = "green"

        console.print(Panel(status_text, border_style=border, box=box.DOUBLE_EDGE))

        # Tabela de informações
        tabela_info = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        tabela_info.add_column("Campo", style="bold cyan", width=22)
        tabela_info.add_column("Valor", style="white")

        if resultado.parametros_injetaveis:
            tabela_info.add_row(
                "Parâmetros Injetáveis",
                ", ".join(resultado.parametros_injetaveis)
            )

        if resultado.tecnicas_encontradas:
            tabela_info.add_row("Técnicas", "\n".join(resultado.tecnicas_encontradas))

        if resultado.dbms:
            dbms_val = resultado.dbms
            if resultado.dbms_versao:
                dbms_val += f" ({resultado.dbms_versao})"
            tabela_info.add_row("DBMS", dbms_val)

        if resultado.sistema_op:
            tabela_info.add_row("Sistema Operacional", resultado.sistema_op)

        if resultado.usuario_db:
            user_val = resultado.usuario_db
            if resultado.eh_dba:
                user_val += " [bold red](DBA)[/bold red]"
            tabela_info.add_row("Usuário do Banco", user_val)

        if resultado.banco_atual:
            tabela_info.add_row("Banco Atual", resultado.banco_atual)

        if resultado.waf_detectado:
            tabela_info.add_row("WAF Detectado", resultado.waf_detectado)

        console.print(tabela_info)

        # Bancos de dados
        if resultado.bancos:
            console.print()
            console.print("[bold yellow]Bancos de Dados Encontrados:[/bold yellow]")
            for banco in resultado.bancos:
                marcador = "[bold red]►[/bold red]" if banco == resultado.banco_atual else "  •"
                console.print(f"  {marcador} {banco}")

        # Tabelas
        if resultado.tabelas:
            console.print()
            console.print("[bold yellow]Tabelas Encontradas:[/bold yellow]")
            for tabela in resultado.tabelas[:20]:
                console.print(f"  • {tabela}")
            if len(resultado.tabelas) > 20:
                console.print(f"  [dim]... e mais {len(resultado.tabelas) - 20} tabelas[/dim]")

        # Avisos
        if resultado.avisos:
            console.print()
            console.print("[bold yellow]Avisos:[/bold yellow]")
            for aviso in resultado.avisos:
                console.print(f"  [yellow]![/yellow] {aviso[:100]}")

        # Erros
        if resultado.erros:
            console.print()
            console.print("[bold red]Erros:[/bold red]")
            for erro in resultado.erros:
                console.print(f"  [red]✗[/red] {erro[:100]}")

    def resumo_para_relatorio(self, resultado: ResultadoSQLMap) -> dict:
        """Converte resultado em dicionário para o relatório."""
        return {
            "injetavel": resultado.injetavel,
            "tecnicas": resultado.tecnicas_encontradas,
            "dbms": resultado.dbms,
            "dbms_versao": resultado.dbms_versao,
            "sistema_op": resultado.sistema_op,
            "usuario_db": resultado.usuario_db,
            "eh_dba": resultado.eh_dba,
            "banco_atual": resultado.banco_atual,
            "bancos": resultado.bancos,
            "tabelas": resultado.tabelas,
            "parametros_injetaveis": resultado.parametros_injetaveis,
            "waf_detectado": resultado.waf_detectado,
        }
