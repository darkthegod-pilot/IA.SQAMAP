"""
Conselheiro de Técnicas — Vlad Volkov
Wizard interativo para seleção da melhor técnica de injeção SQL.

Uso:
    python utils/conselheiro_tecnica.py
    python utils/conselheiro_tecnica.py --alvo "http://alvo.com/?id=1"
"""

import argparse
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

console = Console()

# Definição das técnicas SQLMap
TECNICAS = {
    "B": {
        "nome": "Boolean-based Blind",
        "descricao": "Infere dados pela diferença entre respostas verdadeiras/falsas",
        "velocidade": "Lenta",
        "confiabilidade": "Alta",
        "requer_diferenca_resposta": True,
        "requer_resposta_erro": False,
        "requer_union": False,
        "funciona_sem_output": True,
        "dificuldade_evasao": "Media",
        "quando_usar": [
            "Aplicação responde diferente para condições TRUE/FALSE",
            "Sem output visível de dados",
            "WAF bloqueia UNION SELECT",
        ],
    },
    "T": {
        "nome": "Time-based Blind",
        "descricao": "Infere dados por atrasos de tempo (SLEEP, WAITFOR)",
        "velocidade": "Muito Lenta",
        "confiabilidade": "Media",
        "requer_diferenca_resposta": False,
        "requer_resposta_erro": False,
        "requer_union": False,
        "funciona_sem_output": True,
        "dificuldade_evasao": "Alta",
        "quando_usar": [
            "Nenhuma diferença visível na resposta",
            "Aplicação mostra mesma página para erro/sucesso",
            "Último recurso quando outras técnicas falham",
        ],
    },
    "E": {
        "nome": "Error-based",
        "descricao": "Extrai dados através de mensagens de erro do banco",
        "velocidade": "Rápida",
        "confiabilidade": "Alta",
        "requer_diferenca_resposta": False,
        "requer_resposta_erro": True,
        "requer_union": False,
        "funciona_sem_output": False,
        "dificuldade_evasao": "Baixa",
        "quando_usar": [
            "Erros SQL visíveis na resposta",
            "Mensagens de banco de dados expostas",
            "Desenvolvimento/debug ativo no servidor",
        ],
    },
    "U": {
        "nome": "UNION-based",
        "descricao": "Extrai dados injetando cláusula UNION SELECT",
        "velocidade": "Muito Rápida",
        "confiabilidade": "Alta",
        "requer_diferenca_resposta": False,
        "requer_resposta_erro": False,
        "requer_union": True,
        "funciona_sem_output": False,
        "dificuldade_evasao": "Media",
        "quando_usar": [
            "Dados da consulta são refletidos na resposta",
            "Página exibe resultados de queries SELECT",
            "Número de colunas identificável",
        ],
    },
    "S": {
        "nome": "Stacked Queries",
        "descricao": "Executa múltiplos comandos SQL separados por ponto e vírgula",
        "velocidade": "Media",
        "confiabilidade": "Media",
        "requer_diferenca_resposta": False,
        "requer_resposta_erro": False,
        "requer_union": False,
        "funciona_sem_output": True,
        "dificuldade_evasao": "Media",
        "quando_usar": [
            "DBMS suporta múltiplos statements (MSSQL, PostgreSQL)",
            "Necessidade de DDL/DML (INSERT, UPDATE, DROP)",
            "Execução de comandos OS via xp_cmdshell (MSSQL)",
        ],
    },
    "Q": {
        "nome": "Out-of-band (DNS/HTTP)",
        "descricao": "Exfiltra dados via requisições DNS ou HTTP externas",
        "velocidade": "Media",
        "confiabilidade": "Baixa",
        "requer_diferenca_resposta": False,
        "requer_resposta_erro": False,
        "requer_union": False,
        "funciona_sem_output": True,
        "dificuldade_evasao": "Alta",
        "quando_usar": [
            "Todas as outras técnicas bloqueadas",
            "Servidor tem acesso de saída DNS/HTTP",
            "Ambiente com firewall de saída permissivo",
        ],
    },
}

# Combinações de técnicas recomendadas por cenário
PERFIS_TECNICA = {
    "rapido": {
        "nome": "Scan Rápido",
        "descricao": "Detecção inicial veloz, técnicas mais comuns",
        "tecnicas": "EU",
        "nivel": 1,
        "threads": 5,
        "risco": 1,
    },
    "padrao": {
        "nome": "Scan Padrão",
        "descricao": "Equilíbrio entre velocidade e cobertura",
        "tecnicas": "BEUST",
        "nivel": 3,
        "threads": 3,
        "risco": 2,
    },
    "completo": {
        "nome": "Scan Completo",
        "descricao": "Todas as técnicas, máxima detecção",
        "tecnicas": "BEUSTQ",
        "nivel": 5,
        "threads": 1,
        "risco": 3,
    },
    "furtivo": {
        "nome": "Scan Furtivo",
        "descricao": "Mínimo ruído, evita detecção",
        "tecnicas": "BT",
        "nivel": 1,
        "threads": 1,
        "risco": 1,
    },
    "waf_evasao": {
        "nome": "Evasão de WAF",
        "descricao": "Otimizado para bypassar WAFs",
        "tecnicas": "BEUST",
        "nivel": 2,
        "threads": 2,
        "risco": 2,
    },
}

# Flags SQLMap por técnica
FLAGS_SQLMAP = {
    "B": "--technique=B",
    "T": "--technique=T",
    "E": "--technique=E",
    "U": "--technique=U",
    "S": "--technique=S",
    "Q": "--technique=Q",
    "BEUST": "--technique=BEUST",
    "BEUSTQ": "--technique=BEUSTQ",
    "EU": "--technique=EU",
    "BT": "--technique=BT",
}


class ConselheiroTecnica:
    """Aconselha sobre a melhor técnica de injeção SQL para cada cenário."""

    def aconselhar(self, contexto: dict) -> dict:
        """
        Retorna técnicas recomendadas baseado no contexto.

        contexto pode conter:
            - diferenca_resposta: bool — resposta muda para TRUE/FALSE
            - erros_visiveis: bool — erros SQL na página
            - dados_refletidos: bool — dados da query aparecem na resposta
            - suporta_stacked: bool — DBMS suporta múltiplos statements
            - waf_presente: bool — WAF detectado
            - dbms: str — banco de dados identificado
            - prioridade: str — "velocidade", "furtividade", "cobertura"
        """
        tecnicas_recomendadas = []
        raciocinio = []

        diferenca = contexto.get("diferenca_resposta", False)
        erros = contexto.get("erros_visiveis", False)
        refletidos = contexto.get("dados_refletidos", False)
        stacked = contexto.get("suporta_stacked", False)
        waf = contexto.get("waf_presente", False)
        dbms = contexto.get("dbms", "").lower()
        prioridade = contexto.get("prioridade", "cobertura")

        if erros:
            tecnicas_recomendadas.insert(0, "E")
            raciocinio.append("Error-based: erros SQL visíveis → extração direta e rápida")

        if refletidos:
            tecnicas_recomendadas.insert(0, "U")
            raciocinio.append("UNION-based: dados refletidos → técnica mais rápida disponível")

        if diferenca:
            if "E" not in tecnicas_recomendadas and "U" not in tecnicas_recomendadas:
                tecnicas_recomendadas.insert(0, "B")
            else:
                tecnicas_recomendadas.append("B")
            raciocinio.append("Boolean-blind: diferença de resposta detectada → confiável como fallback")

        if stacked or dbms in ("mssql", "postgresql"):
            tecnicas_recomendadas.append("S")
            raciocinio.append("Stacked Queries: DBMS suporta múltiplos statements → útil para DDL/DML")

        tecnicas_recomendadas.append("T")
        raciocinio.append("Time-blind: sempre incluída como último recurso")

        if waf:
            if "U" in tecnicas_recomendadas:
                raciocinio.append("Aviso: WAF detectado pode bloquear UNION SELECT — tenha tampers prontos")
            raciocinio.append("Evasão WAF: use --level=2 --risk=1 com tampers selecionados")

        if prioridade == "velocidade":
            tecnicas_recomendadas = [t for t in ["U", "E", "B", "S", "T"] if t in tecnicas_recomendadas]
        elif prioridade == "furtividade":
            if "T" in tecnicas_recomendadas:
                tecnicas_recomendadas = ["B", "T"]
                raciocinio.append("Furtividade: limitando a Boolean e Time-blind para menos ruído")

        chain = "".join(dict.fromkeys(tecnicas_recomendadas))

        return {
            "tecnicas": chain,
            "flag_sqlmap": f"--technique={chain}",
            "raciocinio": raciocinio,
            "detalhes": {t: TECNICAS[t] for t in chain if t in TECNICAS},
        }

    def wizard_interativo(self) -> dict:
        """Wizard interativo em PT-BR para selecionar técnica."""
        console.print()
        console.print(Panel(
            "[bold white]Wizard de Seleção de Técnica[/bold white]\n"
            "[dim]Responda as perguntas para obter a técnica ideal[/dim]",
            title="[bold cyan]VLAD VOLKOV — Conselheiro[/bold cyan]",
            border_style="cyan"
        ))
        console.print()

        contexto = {}

        contexto["erros_visiveis"] = Confirm.ask(
            "  [cyan]?[/cyan] A página exibe erros SQL ou mensagens do banco de dados?",
            default=False
        )

        contexto["dados_refletidos"] = Confirm.ask(
            "  [cyan]?[/cyan] Os dados da query aparecem refletidos na resposta?",
            default=False
        )

        contexto["diferenca_resposta"] = Confirm.ask(
            "  [cyan]?[/cyan] A resposta muda entre condições TRUE e FALSE?",
            default=True
        )

        contexto["suporta_stacked"] = Confirm.ask(
            "  [cyan]?[/cyan] DBMS suporta múltiplos statements (MSSQL, PostgreSQL)?",
            default=False
        )

        contexto["waf_presente"] = Confirm.ask(
            "  [cyan]?[/cyan] WAF detectado no alvo?",
            default=False
        )

        dbms_opcoes = ["mysql", "mssql", "postgresql", "oracle", "sqlite", "desconhecido"]
        console.print("  [cyan]?[/cyan] Qual é o DBMS?")
        for i, op in enumerate(dbms_opcoes, 1):
            console.print(f"     [{i}] {op}")

        escolha_dbms = Prompt.ask("  Opção", default="6")
        try:
            idx = int(escolha_dbms) - 1
            contexto["dbms"] = dbms_opcoes[idx] if 0 <= idx < len(dbms_opcoes) else "desconhecido"
        except ValueError:
            contexto["dbms"] = "desconhecido"

        console.print("  [cyan]?[/cyan] Prioridade do scan?")
        console.print("     [1] Velocidade (resultados rápidos)")
        console.print("     [2] Cobertura (máxima detecção)")
        console.print("     [3] Furtividade (mínimo ruído)")
        escolha_prio = Prompt.ask("  Opção", default="2")
        mapa_prio = {"1": "velocidade", "2": "cobertura", "3": "furtividade"}
        contexto["prioridade"] = mapa_prio.get(escolha_prio, "cobertura")

        return self.aconselhar(contexto)

    def obter_flags_perfil(self, perfil: str) -> dict:
        """Retorna flags SQLMap para um perfil predefinido."""
        return PERFIS_TECNICA.get(perfil.lower(), PERFIS_TECNICA["padrao"])

    def listar_tecnicas(self) -> list:
        """Retorna lista de todas as técnicas disponíveis."""
        return list(TECNICAS.keys())


def _exibir_resultado(resultado: dict, alvo: str = None):
    """Exibe resultado do conselheiro em formato rico."""
    chain = resultado["tecnicas"]
    flag = resultado["flag_sqlmap"]

    console.print()
    tabela = Table(
        title=f"Técnicas Recomendadas",
        box=box.ROUNDED, border_style="green"
    )
    tabela.add_column("Cód", style="bold cyan", width=5)
    tabela.add_column("Técnica", style="white", width=24)
    tabela.add_column("Velocidade", style="yellow", width=14)
    tabela.add_column("Confiabilidade", style="green", width=16)
    tabela.add_column("Descrição", style="dim")

    for cod in chain:
        if cod in TECNICAS:
            t = TECNICAS[cod]
            tabela.add_row(
                cod, t["nome"], t["velocidade"],
                t["confiabilidade"], t["descricao"]
            )

    console.print(tabela)
    console.print()

    if resultado.get("raciocinio"):
        console.print("[bold yellow]Raciocínio:[/bold yellow]")
        for r in resultado["raciocinio"]:
            console.print(f"  • {r}")
        console.print()

    console.print(f"[bold green]Flag SQLMap:[/bold green] [yellow]{flag}[/yellow]")

    if alvo:
        console.print()
        console.print(f"[bold green]Comando:[/bold green]")
        console.print(f"  [dim]sqlmap -u \"{alvo}\" {flag} --random-agent --batch[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="Conselheiro de Técnicas — Vlad Volkov",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplo: python utils/conselheiro_tecnica.py --alvo 'http://alvo.com/?id=1'"
    )
    parser.add_argument("--alvo", help="URL do alvo (para gerar comando completo)")
    parser.add_argument("--perfil", choices=["rapido", "padrao", "completo", "furtivo", "waf_evasao"],
                        help="Perfil predefinido")
    parser.add_argument("--listar", action="store_true", help="Lista todas as técnicas")
    args = parser.parse_args()

    conselheiro = ConselheiroTecnica()

    if args.listar:
        tabela = Table(title="Técnicas SQLMap", box=box.ROUNDED)
        tabela.add_column("Cód", style="bold cyan", width=5)
        tabela.add_column("Técnica", style="white", width=24)
        tabela.add_column("Velocidade", style="yellow")
        tabela.add_column("Quando Usar", style="dim")
        for cod, t in TECNICAS.items():
            quando = t["quando_usar"][0] if t["quando_usar"] else ""
            tabela.add_row(cod, t["nome"], t["velocidade"], quando)
        console.print(tabela)
        return

    if args.perfil:
        perfil = conselheiro.obter_flags_perfil(args.perfil)
        p = PERFIS_TECNICA[args.perfil]
        chain = p["tecnicas"]
        resultado = {
            "tecnicas": chain,
            "flag_sqlmap": f"--technique={chain}",
            "raciocinio": [f"Perfil '{p['nome']}': {p['descricao']}"],
            "detalhes": {},
        }
        _exibir_resultado(resultado, args.alvo)
        return

    resultado = conselheiro.wizard_interativo()
    _exibir_resultado(resultado, args.alvo)


if __name__ == "__main__":
    main()
