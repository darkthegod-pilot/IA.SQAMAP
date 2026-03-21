#!/usr/bin/env python3
"""
VLAD VOLKOV — Pentester Web Especialista
Ponto de entrada principal do agente.

Uso:
    python vlad.py scan --alvo "http://alvo.com/?id=1"
    python vlad.py auto --alvo "http://alvo.com/?id=1"
    python vlad.py web --alvo "http://alvo.com" --tipo xss
    python vlad.py waf --alvo "http://alvo.com"
    python vlad.py tamper --waf cloudflare --dbms mysql
    python vlad.py tecnica
    python vlad.py instalar
"""

import argparse
import sys
import os

# Garantir que o diretório raiz está no path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


def cmd_scan(args):
    """Scan SQLMap automatizado."""
    from core.banner import exibir_banner
    from core.engine import VladEngine

    exibir_banner()

    opcoes = {
        "perfil": args.modo,
        "dbms": args.dbms,
        "tamper": args.tamper,
        "parametros": args.params,
        "data": args.data,
        "cookie": args.cookie,
        "proxy": args.proxy,
        "enum": args.enum or [],
        "nivel": args.nivel,
        "risco": args.risco,
        "threads": args.threads,
        "delay": args.delay,
        "verboso": args.verboso,
    }

    engine = VladEngine()
    relatorio = engine.scan_sqlmap_direto(args.alvo, opcoes)
    relatorio.exibir_resumo_terminal()

    if args.salvar:
        caminho_json = relatorio.salvar_json()
        caminho_md = relatorio.salvar_markdown()
        console.print(f"\n[bold green]Relatório salvo:[/bold green]")
        console.print(f"  JSON: {caminho_json}")
        console.print(f"  Markdown: {caminho_md}")


def cmd_auto(args):
    """Modo automático: recon + SQLi + web + relatório."""
    from core.banner import exibir_banner
    from core.engine import VladEngine

    exibir_banner()

    opcoes = {
        "perfil": args.modo if hasattr(args, "modo") else "padrao",
        "enum": ["bancos", "tabelas", "usuarios"] if args.enum_completo else [],
    }

    engine = VladEngine()
    relatorio = engine.escanear_automatico(args.alvo, opcoes)
    relatorio.exibir_resumo_terminal()

    caminho_json = relatorio.salvar_json()
    caminho_md = relatorio.salvar_markdown()
    console.print(f"\n[bold green]Relatório salvo:[/bold green]")
    console.print(f"  JSON: {caminho_json}")
    console.print(f"  Markdown: {caminho_md}")


def cmd_web(args):
    """Testes de vulnerabilidades web."""
    from core.banner import exibir_banner
    from core.engine import VladEngine

    exibir_banner()

    tipos = args.tipo if args.tipo else ["xss", "lfi", "ssrf", "cmd", "traversal"]

    engine = VladEngine()
    relatorio = engine.testar_web(args.alvo, tipos)
    relatorio.exibir_resumo_terminal()

    if args.salvar:
        caminho = relatorio.salvar_json()
        console.print(f"\n[bold green]Relatório salvo:[/bold green] {caminho}")


def cmd_waf(args):
    """Detectar e identificar WAF."""
    from core.banner import exibir_banner
    from utils.detector_waf import DetectorWAF

    exibir_banner(silencioso=True)

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
        from utils.detector_waf import RECOMENDACOES_TAMPER
        tabela = Table(title="WAFs Detectados", box=box.ROUNDED, border_style="yellow")
        tabela.add_column("WAF", style="bold yellow")
        tabela.add_column("Tampers Recomendados", style="cyan")

        for waf in wafs:
            tampers = RECOMENDACOES_TAMPER.get(waf, "space2comment,randomcase")
            tabela.add_row(waf, tampers)

        console.print(tabela)

        chain = detector.obter_recomendacao_tamper(wafs)
        console.print()
        console.print(f"[bold green]Flag SQLMap:[/bold green] [yellow]--tamper={chain}[/yellow]")
        console.print()
        console.print(f"[bold green]Comando sugerido:[/bold green]")
        console.print(
            f'  [dim]sqlmap -u "{args.alvo}" --tamper={chain} '
            f'--random-agent --delay=2 --batch[/dim]'
        )
    else:
        console.print("[bold green]Nenhum WAF detectado[/bold green] (ou WAF não reconhecido)")


def cmd_tamper(args):
    """Selecionar tampers para WAF/DBMS."""
    from core.banner import exibir_banner
    from utils.seletor_tamper import SeletorTamper, DESCRICOES_TAMPER

    exibir_banner(silencioso=True)

    seletor = SeletorTamper()

    if args.listar_wafs:
        tabela = Table(title="WAFs Suportados", box=box.ROUNDED)
        tabela.add_column("WAF", style="bold yellow")
        for waf in seletor.listar_wafs():
            tabela.add_row(waf)
        console.print(tabela)
        return

    if not args.waf:
        console.print("[bold red]Erro:[/bold red] --waf é obrigatório")
        sys.exit(1)

    niveis_map = {"leve": "light", "padrao": "standard", "pesado": "heavy"}
    nivel_en = niveis_map.get(args.nivel or "padrao", "standard")

    console.print()
    chain = seletor.construir_chain(args.waf, args.dbms or "all", nivel_en)
    tampers = seletor.selecionar(args.waf, args.dbms or "all", verboso=True)

    tabela = Table(
        title=f"Tampers: WAF={args.waf} | DBMS={args.dbms or 'all'} | Nível={args.nivel or 'padrao'}",
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
            f'--dbms={args.dbms or "mysql"} --random-agent --delay=2 --batch[/dim]'
        )


def cmd_tecnica(args):
    """Wizard de seleção de técnica."""
    from core.banner import exibir_banner
    from utils.conselheiro_tecnica import ConselheiroTecnica, _exibir_resultado, PERFIS_TECNICA

    exibir_banner(silencioso=True)
    conselheiro = ConselheiroTecnica()

    if args.perfil:
        p = PERFIS_TECNICA.get(args.perfil, PERFIS_TECNICA["padrao"])
        chain = p["tecnicas"]
        resultado = {
            "tecnicas": chain,
            "flag_sqlmap": f"--technique={chain}",
            "raciocinio": [f"Perfil '{p['nome']}': {p['descricao']}"],
        }
        _exibir_resultado(resultado, args.alvo)
    else:
        resultado = conselheiro.wizard_interativo()
        _exibir_resultado(resultado, args.alvo)


def cmd_relatorio(args):
    """Gerenciar relatórios de sessão."""
    from pathlib import Path
    import json

    dir_relatorios = Path("relatorios")

    if not dir_relatorios.exists():
        console.print("[bold red]Nenhum relatório encontrado.[/bold red]")
        return

    relatorios = sorted(dir_relatorios.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not relatorios:
        console.print("[bold red]Nenhum relatório JSON encontrado.[/bold red]")
        return

    if args.sessao == "ultima" or args.sessao is None:
        arquivo = relatorios[0]
    else:
        matches = [r for r in relatorios if args.sessao in r.name]
        if not matches:
            console.print(f"[bold red]Relatório não encontrado:[/bold red] {args.sessao}")
            return
        arquivo = matches[0]

    console.print(f"\n[bold cyan]Carregando:[/bold cyan] {arquivo.name}")

    with open(arquivo, encoding="utf-8") as f:
        dados = json.load(f)

    tabela = Table(title="Relatório", box=box.ROUNDED, border_style="cyan")
    tabela.add_column("Campo", style="bold cyan", width=24)
    tabela.add_column("Valor", style="white")

    campos = ["alvo", "duracao", "severidade_maxima", "waf", "dbms",
              "sistema_operacional", "usuario_db"]
    for campo in campos:
        valor = dados.get(campo)
        if valor:
            tabela.add_row(campo.replace("_", " ").title(), str(valor))

    console.print(tabela)

    vulns = dados.get("vulnerabilidades", [])
    if vulns:
        console.print()
        console.print(f"[bold red]Vulnerabilidades ({len(vulns)}):[/bold red]")
        for v in vulns:
            console.print(
                f"  [{v.get('severidade', '?').upper()}] {v.get('tipo', '?')} "
                f"— {v.get('parametro', '?')}"
            )

    if args.listar:
        console.print()
        console.print("[bold cyan]Todos os relatórios:[/bold cyan]")
        for r in relatorios[:20]:
            console.print(f"  • {r.name}")


def cmd_instalar(args):
    """Verificar dependências e configurar ambiente."""
    from core.banner import exibir_banner
    import subprocess

    exibir_banner(silencioso=True)

    console.print()
    console.print(Panel(
        "[bold white]Verificação de Dependências[/bold white]",
        title="[bold cyan]VLAD VOLKOV — Instalação[/bold cyan]",
        border_style="cyan"
    ))

    dependencias = {
        "Python 3.8+": ("python3", "--version"),
        "SQLMap": ("sqlmap", "--version"),
        "pip": ("pip3", "--version"),
    }

    modulos_python = ["rich", "requests", "colorama", "dnspython"]

    tabela = Table(box=box.ROUNDED)
    tabela.add_column("Dependência", style="bold cyan")
    tabela.add_column("Status", style="white")
    tabela.add_column("Versão", style="dim")

    for nome, (cmd, flag) in dependencias.items():
        try:
            result = subprocess.run([cmd, flag], capture_output=True, text=True, timeout=5)
            versao = result.stdout.strip().split("\n")[0][:40] if result.returncode == 0 else "?"
            status = "[bold green]✓ OK[/bold green]" if result.returncode == 0 else "[bold red]✗ Não encontrado[/bold red]"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            status = "[bold red]✗ Não encontrado[/bold red]"
            versao = "-"
        tabela.add_row(nome, status, versao)

    for modulo in modulos_python:
        try:
            __import__(modulo)
            status = "[bold green]✓ OK[/bold green]"
            versao = __import__(modulo).__version__ if hasattr(__import__(modulo), "__version__") else "instalado"
        except ImportError:
            status = "[bold red]✗ Não instalado[/bold red]"
            versao = "-"
        tabela.add_row(f"Python: {modulo}", status, versao)

    console.print(tabela)
    console.print()
    console.print("[bold green]Para instalar dependências Python:[/bold green]")
    console.print("  [dim]pip3 install -r requirements.txt[/dim]")
    console.print()
    console.print("[bold green]Para instalar SQLMap:[/bold green]")
    console.print("  [dim]apt-get install sqlmap  # Debian/Ubuntu[/dim]")
    console.print("  [dim]pip3 install sqlmap      # Via pip[/dim]")


def criar_parser():
    """Cria o parser de argumentos principal."""
    parser = argparse.ArgumentParser(
        prog="vlad",
        description="VLAD VOLKOV — Pentester Web Especialista",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python vlad.py scan --alvo "http://alvo.com/?id=1"
  python vlad.py auto --alvo "http://alvo.com/?id=1" --enum-completo
  python vlad.py web --alvo "http://alvo.com" --tipo xss lfi
  python vlad.py waf --alvo "http://alvo.com" --probe
  python vlad.py tamper --waf cloudflare --dbms mysql
  python vlad.py tecnica --alvo "http://alvo.com/?id=1"
  python vlad.py relatorio --sessao ultima
        """
    )

    subparsers = parser.add_subparsers(dest="comando", help="Subcomando")

    # --- SCAN ---
    scan_p = subparsers.add_parser("scan", help="Scan SQLMap automatizado")
    scan_p.add_argument("--alvo", required=True, help="URL do alvo")
    scan_p.add_argument("--modo", choices=["rapido", "padrao", "profundo", "furtivo", "agressivo"],
                        default="padrao", help="Perfil de scan")
    scan_p.add_argument("--waf", help="WAF detectado (para seleção automática de tampers)")
    scan_p.add_argument("--dbms", help="Banco de dados")
    scan_p.add_argument("--tamper", help="Tampers manuais")
    scan_p.add_argument("--params", help="Parâmetros específicos")
    scan_p.add_argument("--data", help="POST data")
    scan_p.add_argument("--cookie", help="Cookies")
    scan_p.add_argument("--proxy", help="Proxy")
    scan_p.add_argument("--enum", nargs="+",
                        choices=["bancos", "tabelas", "colunas", "dump", "usuarios",
                                 "senhas", "privilegios", "dba", "hostname", "banner"],
                        help="Enumerações a realizar")
    scan_p.add_argument("--nivel", type=int, choices=[1, 2, 3, 4, 5], help="Nível de teste")
    scan_p.add_argument("--risco", type=int, choices=[1, 2, 3], help="Nível de risco")
    scan_p.add_argument("--threads", type=int, help="Número de threads")
    scan_p.add_argument("--delay", type=float, help="Delay entre requisições (seg)")
    scan_p.add_argument("--verboso", type=int, default=0, choices=range(7), help="Verbosidade (0-6)")
    scan_p.add_argument("--salvar", action="store_true", help="Salvar relatório")

    # --- AUTO ---
    auto_p = subparsers.add_parser("auto", help="Modo automático: recon + sqli + web + relatório")
    auto_p.add_argument("--alvo", required=True, help="URL do alvo")
    auto_p.add_argument("--modo", choices=["rapido", "padrao", "profundo"], default="padrao")
    auto_p.add_argument("--enum-completo", action="store_true", dest="enum_completo",
                        help="Enumerar bancos, tabelas e usuários automaticamente")

    # --- WEB ---
    web_p = subparsers.add_parser("web", help="Testes de vulnerabilidades web")
    web_p.add_argument("--alvo", required=True, help="URL do alvo")
    web_p.add_argument("--tipo", nargs="+",
                       choices=["xss", "lfi", "ssrf", "cmd", "traversal", "auth", "subdominio"],
                       help="Tipos de teste")
    web_p.add_argument("--salvar", action="store_true", help="Salvar relatório")

    # --- WAF ---
    waf_p = subparsers.add_parser("waf", help="Detectar e identificar WAF")
    waf_p.add_argument("--alvo", required=True, help="URL do alvo")
    waf_p.add_argument("--probe", action="store_true", help="Enviar payloads para provocar WAF")

    # --- TAMPER ---
    tamper_p = subparsers.add_parser("tamper", help="Selecionar tampers para WAF/DBMS")
    tamper_p.add_argument("--waf", help="WAF detectado")
    tamper_p.add_argument("--dbms", help="Banco de dados")
    tamper_p.add_argument("--nivel", choices=["leve", "padrao", "pesado"], default="padrao")
    tamper_p.add_argument("--alvo", help="URL alvo (para gerar comando completo)")
    tamper_p.add_argument("--listar-wafs", action="store_true", dest="listar_wafs")

    # --- TECNICA ---
    tec_p = subparsers.add_parser("tecnica", help="Wizard de seleção de técnica SQLi")
    tec_p.add_argument("--alvo", help="URL do alvo")
    tec_p.add_argument("--perfil",
                       choices=["rapido", "padrao", "completo", "furtivo", "waf_evasao"],
                       help="Usar perfil predefinido")

    # --- RELATORIO ---
    rel_p = subparsers.add_parser("relatorio", help="Gerenciar relatórios")
    rel_p.add_argument("--sessao", default="ultima", help="Nome/ID da sessão (ou 'ultima')")
    rel_p.add_argument("--listar", action="store_true", help="Listar todos os relatórios")

    # --- INSTALAR ---
    subparsers.add_parser("instalar", help="Verificar dependências e configurar VPS")

    return parser


def main():
    parser = criar_parser()
    args = parser.parse_args()

    if not args.comando:
        from core.banner import exibir_banner
        exibir_banner()
        parser.print_help()
        sys.exit(0)

    comandos = {
        "scan": cmd_scan,
        "auto": cmd_auto,
        "web": cmd_web,
        "waf": cmd_waf,
        "tamper": cmd_tamper,
        "tecnica": cmd_tecnica,
        "relatorio": cmd_relatorio,
        "instalar": cmd_instalar,
    }

    func = comandos.get(args.comando)
    if func:
        try:
            func(args)
        except KeyboardInterrupt:
            console.print("\n\n[bold yellow]Interrompido pelo usuário.[/bold yellow]")
            sys.exit(0)
        except Exception as e:
            console.print(f"\n[bold red]Erro:[/bold red] {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
