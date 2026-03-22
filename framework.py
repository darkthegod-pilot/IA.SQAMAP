#!/usr/bin/env python3
# framework.py
# Vlad Volkov v2.1 — Framework Interativo de Pentest Web
#
# USO: python framework.py [--alvo URL] [--lista arquivo.txt] [--modulo N]
#
# - Número (1-9, 0) → navega para módulo
# - URL (http://...) → scan rápido com seleção de modo
# - Texto livre → Chat com Vlad IA (GPT)
# - q → sair

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

# ── Ajusta path para imports relativos ───────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

console = Console()

VERSAO = "2.2.0"


# ─────────────────────────── HELPERS DE INPUT ────────────────────────────────

def _pedir_inteiro(prompt: str, default: int, min_val: int = 1,
                   max_val: int = 99999) -> int:
    """Prompt seguro para inteiro com validação de range. Nunca crasha."""
    while True:
        raw = Prompt.ask(prompt, default=str(default)).strip()
        try:
            valor = int(raw)
            if min_val <= valor <= max_val:
                return valor
            console.print(f"  [yellow]⚠ Entre {min_val} e {max_val}.[/]")
        except ValueError:
            console.print(f"  [yellow]⚠ '{raw}' não é número.[/]")


def _pedir_url(prompt: str = "  Alvo") -> Optional[str]:
    """Retorna URL válida ou None se vazio (voltar)."""
    raw = Prompt.ask(f"{prompt} [dim][Enter=voltar][/]", default="").strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw


def _pausar() -> None:
    """Pausa antes de voltar ao menu — evita menu relâmpago no mobile."""
    try:
        Prompt.ask("\n  [dim]Enter para continuar...[/]", default="")
    except (EOFError, KeyboardInterrupt):
        pass


def _selecionar(prompt: str, validas: list, default: str = "0") -> str:
    """Prompt de seleção com validação. Retorna a opção escolhida."""
    while True:
        val = Prompt.ask(prompt, default=default).strip().lower()
        if val in validas:
            return val
        console.print(f"  [yellow]⚠ Opções: {', '.join(validas)}[/]")

def exibir_banner() -> None:
    console.print(Panel(
        f"[bold red]VLAD VOLKOV[/]  [dim]v{VERSAO}[/]\n"
        "[bold white]Framework de Pentest Web[/]\n"
        "[dim]Apenas para uso autorizado.[/]",
        box=box.DOUBLE_EDGE,
        border_style="red",
        padding=(0, 1),
        expand=False,
    ))


def exibir_menu_principal(ia_disponivel: bool = False,
                           furtivo_ativo: bool = False) -> None:
    ia_tag = "[green]IA✓[/]" if ia_disponivel else "[dim]IA✗[/]"
    furtivo_tag = " [yellow]FURTIVO[/]" if furtivo_ativo else ""

    console.print()
    console.print(Panel(
        "\n".join([
            "[bold red][1][/] Scan Completo",
            "[bold red][2][/] SQLMap",
            "[bold red][3][/] Scanner Web",
            "[bold red][4][/] WAF + Tampers",
            "[bold red][5][/] Enumeração Web",
            "[bold red][6][/] Subdomínios",
            "[bold red][7][/] Range de Sites",
            "[bold red][8][/] Relatórios",
            "[bold red][9][/] Configurações",
            f"[bold red][0][/] Chat IA  {ia_tag}",
            f"[bold red][A][/] Atualizar",
            f"[bold red][F][/] Modo Furtivo{furtivo_tag}",
            "[bold red][q][/] Sair",
        ]),
        title="[bold]VLAD[/]",
        box=box.ROUNDED,
        border_style="red",
        padding=(0, 1),
        expand=False,
    ))
    console.print()


# ─────────────────────────── MÓDULOS ─────────────────────────────────────────

def modulo_scan_completo() -> None:
    """Módulo 1 — Scan completo automático."""
    console.print(Panel("[bold red]◉ SCAN COMPLETO[/]", border_style="red", expand=False))

    url = _pedir_url()
    if not url:
        return

    console.print()
    console.print("  Módulos:")
    console.print("    [a] Todos")
    console.print("    [s] Selecionar")
    console.print("    [0] Voltar")
    escolha = _selecionar("  Escolha", ["a", "s", "0"], default="a")
    if escolha == "0":
        return

    modulos_selecionados = None
    if escolha == "s":
        disponiveis = {
            "1": ("waf", "WAF"),
            "2": ("enum_web", "Enum Web"),
            "3": ("subdominios", "Subdomínios"),
            "4": ("sqli", "SQLi"),
            "5": ("xss", "XSS"),
            "6": ("lfi", "LFI"),
            "7": ("traversal", "Traversal"),
            "8": ("ssrf", "SSRF"),
            "9": ("cmd", "Cmd Inject"),
            "0": ("auth", "Auth Bypass"),
        }
        console.print()
        for k, (_, nome) in disponiveis.items():
            console.print(f"    [{k}] {nome}")
        nums = Prompt.ask("  Números (ex: 1,3,5)", default="").strip()
        modulos_selecionados = []
        for n in nums.split(","):
            n = n.strip()
            if n in disponiveis:
                modulos_selecionados.append(disponiveis[n][0])
        if not modulos_selecionados:
            console.print("  [yellow]Nenhum módulo selecionado.[/]")
            return

    from modulos.scanner_completo import ScannerCompleto
    scanner = ScannerCompleto(verboso=True)
    scanner.escanear_site(url, modulos=modulos_selecionados)


def modulo_sqlmap() -> None:
    """Módulo 2 — SQLMap."""
    console.print(Panel("[bold red]◉ SQLMAP[/]", border_style="red", expand=False))

    url = _pedir_url("  URL (ex: http://site.com/?id=1)")
    if not url:
        return

    console.print()
    console.print("  Modo:")
    console.print("    [1] Automático")
    console.print("    [2] Semi-auto")
    console.print("    [3] Manual (só monta comando)")
    console.print("    [4] Avançado")
    console.print("    [0] Voltar")

    modo = _selecionar("  Modo", ["1", "2", "3", "4", "0"], default="1")

    if modo == "0":
        return
    elif modo == "1":
        _sqlmap_automatico(url)
    elif modo == "2":
        _sqlmap_semi_auto(url)
    elif modo == "3":
        _sqlmap_manual(url)
    elif modo == "4":
        _sqlmap_avancado(url)


def _sqlmap_automatico(url: str) -> None:
    from core.engine import VladEngine
    engine = VladEngine(verboso=True)
    relatorio = engine.escanear_automatico(url, opcoes={"modo": "padrao", "enum_completo": True})
    if relatorio:
        relatorio.exibir_resumo_terminal()


def _sqlmap_semi_auto(url: str) -> None:
    console.print("\n  [bold cyan]Modo Semi-Automático[/]")
    from core.engine import VladEngine
    from utils import DetectorWAF, SeletorTamper

    engine = VladEngine(verboso=True)

    # Etapa 1: WAF
    if Confirm.ask("  [1/4] Detectar WAF?", default=True):
        engine.detectar_waf(url)

    # Etapa 2: Técnica
    waf = Prompt.ask("  [2/4] WAF detectado (ou vazio)", default="").strip() or None
    dbms = Prompt.ask("  [3/4] DBMS suspeito (mysql/mssql/postgresql/oracle ou vazio)", default="").strip() or "all"

    if waf and Confirm.ask(f"  Selecionar tampers para {waf}?", default=True):
        engine.selecionar_tampers(waf, dbms)

    # Etapa 4: Scan
    if Confirm.ask("  [4/4] Executar SQLMap agora?", default=True):
        opcoes = {"modo": "padrao", "enum_completo": True}
        if waf:
            opcoes["waf"] = waf
        if dbms and dbms != "all":
            opcoes["dbms"] = dbms
        relatorio = engine.scan_sqlmap_direto(url, opcoes=opcoes)
        if relatorio:
            relatorio.exibir_resumo_terminal()


def _sqlmap_manual(url: str) -> None:
    from utils import ConstrutorComando, DetectorWAF, SeletorTamper, ConselheiroTecnica

    console.print("\n  [bold cyan]Construtor de Comando SQLMap[/]")
    waf = Prompt.ask("  WAF (cloudflare/modsecurity/imperva/vazio)", default="").strip()
    dbms = Prompt.ask("  DBMS (mysql/mssql/postgresql/oracle/vazio)", default="").strip() or "all"
    modo = Prompt.ask("  Perfil (rapido/padrao/profundo/furtivo/agressivo)", default="padrao").strip()

    tampers = ""
    if waf:
        seletor = SeletorTamper()
        lista = seletor.selecionar(waf, dbms)
        tampers = ",".join(lista) if lista else ""

    construtor = ConstrutorComando()
    cmd = construtor.construir_cmd_completo(url, dbms if dbms != "all" else None, tampers, "output/")

    console.print()
    console.print(Panel(
        f"[bold green]{cmd}[/]",
        title="Comando SQLMap",
        border_style="green",
        box=box.ROUNDED,
    ))
    console.print("  [dim]Copie e execute o comando acima.[/]")


def _sqlmap_avancado(url: str) -> None:
    console.print("\n  [bold cyan]Configuração Avançada[/]")
    nivel = Prompt.ask("  Nível [1-5]", default="3").strip()
    risco = Prompt.ask("  Risco [1-3]", default="2").strip()
    threads = Prompt.ask("  Threads", default="3").strip()
    delay = Prompt.ask("  Delay (segundos)", default="0").strip()
    proxy = Prompt.ask("  Proxy (vazio = sem proxy)", default="").strip()
    cookie = Prompt.ask("  Cookie (vazio = sem cookie)", default="").strip()
    enum = Prompt.ask(
        "  Enumerar [bancos/tabelas/colunas/dump/usuarios/senhas]",
        default="bancos",
    ).strip()

    cmd_parts = [f"sqlmap -u '{url}'"]
    cmd_parts.append(f"--level={nivel} --risk={risco} --threads={threads}")
    if delay and delay != "0":
        cmd_parts.append(f"--delay={delay}")
    if proxy:
        cmd_parts.append(f"--proxy={proxy}")
    if cookie:
        cmd_parts.append(f"--cookie='{cookie}'")
    if enum:
        for e in enum.split(","):
            e = e.strip()
            if e == "bancos":
                cmd_parts.append("--dbs")
            elif e == "tabelas":
                cmd_parts.append("--tables")
            elif e == "colunas":
                cmd_parts.append("--columns")
            elif e == "dump":
                cmd_parts.append("--dump")
            elif e == "usuarios":
                cmd_parts.append("--users")
            elif e == "senhas":
                cmd_parts.append("--passwords")

    cmd = " ".join(cmd_parts)
    console.print()
    console.print(Panel(f"[bold green]{cmd}[/]", title="Comando SQLMap Avançado",
                        border_style="green", box=box.ROUNDED))


def modulo_scanner_web() -> None:
    """Módulo 3 — Scanner Web."""
    console.print(Panel("[bold red]◉ SCANNER WEB[/]", border_style="red", expand=False))

    url = _pedir_url()
    if not url:
        return

    console.print()
    console.print("  Tipo de scan:")
    console.print("    [1] Todos")
    console.print("    [2] XSS")
    console.print("    [3] LFI")
    console.print("    [4] SSRF")
    console.print("    [5] Cmd Inject")
    console.print("    [6] Traversal")
    console.print("    [7] Auth Bypass")
    console.print("    [0] Voltar")

    tipo = _selecionar("  Tipo", ["1","2","3","4","5","6","7","0"], default="1")
    if tipo == "0":
        return

    mapa = {
        "2": ["xss"],
        "3": ["lfi"],
        "4": ["ssrf"],
        "5": ["cmd"],
        "6": ["traversal"],
        "7": ["auth"],
    }
    tipos = mapa.get(tipo, ["xss", "lfi", "ssrf", "cmd", "traversal", "auth"])

    from core.engine import VladEngine
    engine = VladEngine(verboso=True)
    relatorio = engine.testar_web(url, tipos=tipos)
    if relatorio:
        relatorio.exibir_resumo_terminal()


def modulo_waf() -> None:
    """Módulo 4 — WAF + Tampers."""
    console.print(Panel("[bold red]◉ WAF + TAMPERS[/]", border_style="red", expand=False))

    url = _pedir_url()
    if not url:
        return

    from core.engine import VladEngine
    engine = VladEngine(verboso=True)
    engine.detectar_waf(url)

    console.print()
    if Confirm.ask("  Selecionar tampers?", default=True):
        waf = Prompt.ask("  WAF (cloudflare/modsecurity/imperva/f5/akamai)", default="").strip()
        if not waf:
            return
        dbms = Prompt.ask("  DBMS (mysql/mssql/postgresql/oracle/all)", default="all").strip()
        nivel = Prompt.ask("  Nível (leve/padrao/pesado)", default="padrao").strip()
        engine.selecionar_tampers(waf, dbms, nivel)


def modulo_enum_web() -> None:
    """Módulo 5 — Enumeração Web."""
    console.print(Panel("[bold red]◉ ENUMERAÇÃO WEB[/]", border_style="red", expand=False))

    url = _pedir_url()
    if not url:
        return

    from modulos.enumerador_web import EnumeradorWeb
    enum = EnumeradorWeb()
    enum.escanear(url, verboso=True)
    enum.exibir_resultado()


def modulo_subdominios() -> None:
    """Módulo 6 — Subdominios."""
    console.print(Panel("[bold red]◉ SUBDOMÍNIOS[/]", border_style="red", expand=False))

    raw = Prompt.ask("  Domínio [dim](ex: site.com)[/]\n  [dim][Enter=voltar][/]", default="").strip()
    if not raw:
        return

    # Remove protocolo e caminhos, deixa só o domínio
    dominio = raw.replace("https://", "").replace("http://", "").split("/")[0].strip()
    if not dominio:
        console.print("  [red]Domínio inválido.[/]")
        return

    threads = _pedir_inteiro("  Threads", default=30, min_val=1, max_val=100)

    from modulos.enum_subdominios import EnumeradorSubdominios
    enum = EnumeradorSubdominios(threads=threads)
    enum.escanear(dominio, verboso=True)
    enum.exibir_resultado()


def modulo_range() -> None:
    """Módulo 7 — Range de Sites com navegação por seleção."""
    console.print(Panel("[bold red]◉ RANGE DE SITES[/]", border_style="red"))

    console.print()
    console.print("  Origem dos alvos:")
    console.print("    [1] Digitar lista separada por vírgula")
    console.print("    [2] Arquivo .txt (um por linha)")
    console.print("    [3] Range de IP (ex: 192.168.1.1-254 ou 192.168.1.0/24)")

    origem = Prompt.ask("  Origem", default="1").strip()

    from modulos.scanner_completo import ScannerCompleto, _parsear_selecao_range
    scanner = ScannerCompleto(verboso=False)
    alvos: list[str] = []

    if origem == "1":
        lista_str = Prompt.ask("  URLs separadas por vírgula").strip()
        alvos = [u.strip() for u in lista_str.split(",") if u.strip()]
        alvos = [("http://" + u if not u.startswith("http") else u) for u in alvos]
    elif origem == "2":
        arquivo = Prompt.ask("  Caminho do arquivo").strip()
        alvos = scanner.carregar_alvos_arquivo(arquivo)
    elif origem == "3":
        range_ip = Prompt.ask("  Range de IP").strip()
        porta = _pedir_inteiro("  Porta", default=80, min_val=1, max_val=65535)
        alvos = scanner.carregar_alvos_range_ip(range_ip, porta)

    if not alvos:
        console.print("  [red]Nenhum alvo válido.[/]")
        return

    # ── Exibir lista numerada ─────────────────────────────────────────────────
    console.print()
    console.print(f"  [bold]Alvos carregados ({len(alvos)}):[/]")
    for i, a in enumerate(alvos, 1):
        console.print(f"    [dim][{i}][/] {a}")

    console.print()
    console.print(
        "  [dim]Quais escanear?[/]  "
        "[cyan]3[/]=só o 3  "
        "[cyan]1-7[/]=range  "
        "[cyan]1,3,5[/]=específicos  "
        "[cyan]Enter[/]=todos"
    )
    selecao = Prompt.ask("  Seleção", default="todos").strip()
    indices = _parsear_selecao_range(selecao, len(alvos))
    alvos_selecionados = [alvos[i] for i in indices]

    console.print(f"  [dim]→ {len(alvos_selecionados)} alvo(s) selecionado(s).[/]")

    # ── Módulos ───────────────────────────────────────────────────────────────
    console.print()
    console.print("  Módulos a executar:")
    console.print("    [1] Scan completo (todos)")
    console.print("    [2] Só SQLi")
    console.print("    [3] Só Web (XSS/LFI/SSRF/CMD/Auth)")
    console.print("    [4] Só Enumeração (dirs/techs/robots)")
    modulo_escolha = Prompt.ask("  Módulo", default="1").strip()

    mapa_modulos = {
        "1": None,
        "2": ["sqli"],
        "3": ["xss", "lfi", "ssrf", "cmd", "traversal", "auth"],
        "4": ["enum_web", "subdominios"],
    }
    modulos_range = mapa_modulos.get(modulo_escolha)

    threads = _pedir_inteiro("  Threads simultâneas", default=3, min_val=1, max_val=20)

    scanner.escanear_range(alvos_selecionados, modulos=modulos_range, threads=threads)


def modulo_relatorios() -> None:
    """Módulo 8 — Relatórios."""
    console.print(Panel("[bold red]◉ RELATÓRIOS[/]", border_style="red"))

    dir_rel = Path("relatorios")
    if not dir_rel.exists():
        console.print("  [dim]Nenhum relatório encontrado.[/]")
        return

    arquivos = sorted(dir_rel.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not arquivos:
        console.print("  [dim]Nenhum relatório encontrado em relatorios/.[/]")
        return

    tabela = Table(title="Relatórios Disponíveis", box=box.ROUNDED, border_style="cyan")
    tabela.add_column("#", style="dim", justify="right")
    tabela.add_column("Arquivo", style="cyan")
    tabela.add_column("Tamanho", justify="right")
    tabela.add_column("Data", style="dim")

    for i, f in enumerate(arquivos[:20], 1):
        stat = f.stat()
        data = datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M")
        tabela.add_row(str(i), f.name, f"{stat.st_size // 1024}KB", data)

    console.print(tabela)

    num = Prompt.ask(
        "\n  Digite o número para ver o relatório (Enter para voltar)", default=""
    ).strip()
    if not num:
        return

    try:
        idx = int(num) - 1
        arquivo = arquivos[idx]
        dados = json.loads(arquivo.read_text())

        console.print()
        console.print(Panel(
            json.dumps(dados, indent=2, ensure_ascii=False)[:3000],
            title=f"[bold]{arquivo.name}[/]",
            border_style="cyan",
            box=box.ROUNDED,
        ))
    except (ValueError, IndexError):
        console.print("  [red]Número inválido.[/]")
    except Exception as e:
        console.print(f"  [red]Erro:[/] {e}")


def modulo_configuracoes(agente: "AgenteIA",  # type: ignore[name-defined]
                          furtivo=None) -> None:
    """Módulo 9 — Configurações."""
    console.print(Panel("[bold red]◉ CONFIGURAÇÕES[/]", border_style="red"))

    cfg = agente.carregar_config_completa()

    while True:
        console.print()
        api_key_status = agente.chave_mascarada()
        proxy_atual = cfg.get("proxy", "não configurado")
        timeout_atual = cfg.get("timeout", 10)
        delay_atual = cfg.get("delay", 1)
        threads_atual = cfg.get("threads_range", 3)
        furtivo_status = "[yellow]ATIVO[/]" if (furtivo and furtivo.ativo) else "[dim]inativo[/]"
        proxy_furtivo = cfg.get("proxy_furtivo", "não configurado")

        console.print(Panel(
            "\n".join([
                f"  [1] API Key OpenAI    [dim]{api_key_status}[/]",
                f"  [2] Proxy             [dim]{proxy_atual}[/]",
                f"  [3] Timeout padrão    [dim]{timeout_atual}s[/]",
                f"  [4] Delay requests    [dim]{delay_atual}s[/]",
                f"  [5] Threads range     [dim]{threads_atual}[/]",
                f"  [6] Proxy furtivo     [dim]{proxy_furtivo}[/]",
                f"  [7] Modo Furtivo      {furtivo_status}",
                "  [8] Salvar e sair",
                "  [0] Voltar sem salvar",
            ]),
            title="Configurações",
            box=box.ROUNDED,
            border_style="yellow",
        ))

        op = Prompt.ask("  Opção", default="0").strip()

        if op == "1":
            nova_key = Prompt.ask("  Nova API Key OpenAI [dim](Enter para cancelar)[/]",
                                  default="", password=True).strip()
            if nova_key:
                if agente.configurar_chave(nova_key):
                    cfg["openai_api_key"] = nova_key
                    console.print("  [green]✓ API key configurada![/]")
                else:
                    console.print("  [red]Erro ao salvar a key.[/]")
        elif op == "2":
            cfg["proxy"] = Prompt.ask("  Proxy (ex: http://127.0.0.1:8080, Enter=limpar)",
                                       default="").strip() or None
        elif op == "3":
            cfg["timeout"] = _pedir_inteiro("  Timeout (segundos)", default=timeout_atual,
                                            min_val=1, max_val=300)
        elif op == "4":
            cfg["delay"] = _pedir_inteiro("  Delay (segundos)", default=delay_atual,
                                          min_val=0, max_val=60)
        elif op == "5":
            cfg["threads_range"] = _pedir_inteiro("  Threads para range", default=threads_atual,
                                                  min_val=1, max_val=20)
        elif op == "6":
            novo_proxy = Prompt.ask(
                "  Proxy furtivo [dim](ex: http://127.0.0.1:8080 ou socks5://..., Enter=limpar)[/]",
                default="",
            ).strip()
            cfg["proxy_furtivo"] = novo_proxy or None
            if furtivo is not None:
                furtivo.proxy = novo_proxy or None
            console.print(f"  [green]✓ Proxy furtivo {'configurado' if novo_proxy else 'removido'}.[/]")
        elif op == "7":
            if furtivo is not None:
                if furtivo.ativo:
                    furtivo.desativar()
                    console.print("  [dim]Modo furtivo desativado.[/]")
                else:
                    furtivo.ativar()
                    console.print("  [yellow]Modo furtivo ativado.[/]")
            else:
                console.print("  [dim]Modo furtivo não disponível nesta sessão.[/]")
        elif op == "8":
            agente.salvar_config_completa(cfg)
            console.print("  [green]✓ Configurações salvas em ~/.vlad/config.json[/]")
            break
        elif op == "0":
            break


def modulo_chat_ia(agente: "AgenteIA") -> None:  # type: ignore[name-defined]
    """Módulo 0 — Chat com Vlad IA."""
    if not agente.disponivel():
        console.print(Panel(
            "[yellow]⚠  IA não configurada.[/]\n\n"
            "Configure a API key via:\n"
            "  • Menu [9] Configurações → [1] API Key OpenAI\n"
            "  • Ou: export OPENAI_API_KEY=sk-proj-...",
            title="Chat com Vlad IA",
            border_style="yellow",
        ))
        return

    console.print(Panel(
        "[bold cyan]Chat com Vlad IA[/]  [dim](GPT-4o-mini)[/]\n"
        "[dim]Digite 'limpar' para novo contexto, 'sair' para voltar ao menu.[/]",
        border_style="cyan",
    ))

    while True:
        console.print()
        try:
            msg = Prompt.ask("[bold cyan]Você[/]").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not msg:
            continue
        if msg.lower() in ("sair", "voltar", "exit", "quit", "q"):
            break
        if msg.lower() in ("limpar", "clear", "novo"):
            agente.limpar_historico()
            console.print("  [dim]Histórico limpo.[/]")
            continue

        with console.status("[dim]Vlad está pensando...[/]"):
            resposta = agente.chat(msg)

        console.print()
        console.print(Panel(
            resposta,
            title="[bold red]Vlad[/]",
            border_style="red",
            box=box.ROUNDED,
        ))


# ─────────────────────── PROCESSAMENTO RÁPIDO DE URL ─────────────────────────

def processar_url_direta(url: str, agente: "AgenteIA") -> None:  # type: ignore[name-defined]
    """Quando o usuário digita uma URL diretamente no prompt principal."""
    console.print()
    console.print(f"  [cyan]Alvo:[/] {url}")
    console.print()
    console.print("  O que fazer?")
    console.print("    [1] Scan Completo")
    console.print("    [2] SQLMap")
    console.print("    [3] Scanner Web")
    console.print("    [4] Enumeração")
    console.print("    [5] Perguntar ao Vlad IA")
    console.print("    [0] Voltar")

    op = _selecionar("  Opção", ["1","2","3","4","5","0"], default="1")

    if op == "1":
        from modulos.scanner_completo import ScannerCompleto
        ScannerCompleto(verboso=True).escanear_site(url)
    elif op == "2":
        _sqlmap_automatico(url)
    elif op == "3":
        from core.engine import VladEngine
        engine = VladEngine(verboso=True)
        relatorio = engine.testar_web(url)
        if relatorio:
            relatorio.exibir_resumo_terminal()
    elif op == "4":
        from modulos.enumerador_web import EnumeradorWeb
        enum = EnumeradorWeb()
        enum.escanear(url, verboso=True)
        enum.exibir_resultado()
    elif op == "5":
        if agente.disponivel():
            with console.status("[dim]Vlad analisando...[/]"):
                resposta = agente.chat(
                    f"Preciso testar o site: {url}. Por onde devo começar e qual o comando mais adequado?"
                )
            console.print()
            console.print(Panel(resposta, title="[bold red]Vlad[/]", border_style="red", expand=False))
        else:
            console.print("  [yellow]IA não configurada. Configure em [9].[/]")
    # op == "0" → só retorna


# ─────────────────────────── LOOP PRINCIPAL ──────────────────────────────────

def loop_principal(agente, furtivo=None, conhecimento=None) -> None:  # type: ignore
    """Loop interativo principal do framework."""
    ia_ok = agente.disponivel()
    furtivo_ativo = furtivo.ativo if furtivo else False
    exibir_menu_principal(ia_ok, furtivo_ativo)

    while True:
        try:
            entrada = Prompt.ask(
                "[bold red]vlad>[/]"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [dim]Saindo...[/]")
            break

        if not entrada:
            continue

        entrada_lower = entrada.lower()

        # Sair
        if entrada_lower in ("q", "quit", "exit", "sair"):
            console.print("\n  [bold red]Vlad Volkov desconectado.[/]")
            break

        # [A] — Auto-update
        if entrada_lower == "a":
            try:
                from core.atualizador import Atualizador
                atualizador = Atualizador()
                atualizador.exibir_status()
                info = atualizador.verificar_atualizacao()
                if info.get("ok") and not info.get("atualizado"):
                    if Confirm.ask(
                        f"  Há {info.get('commits_novos', '?')} commit(s) novo(s). Atualizar agora?",
                        default=True,
                    ):
                        ok = atualizador.atualizar()
                        if ok:
                            console.print("  [green]✓ Vlad atualizado! Reinicie para aplicar as mudanças.[/]")
                        else:
                            console.print("  [red]✗ Atualização falhou. Verifique os logs acima.[/]")
                elif info.get("atualizado"):
                    console.print("  [dim]Vlad já está na versão mais recente.[/]")
            except KeyboardInterrupt:
                console.print("\n  [dim]Atualização cancelada.[/]")
            except Exception as e:
                console.print(f"  [red]Erro ao atualizar:[/] {e}")
            exibir_menu_principal(agente.disponivel(), furtivo.ativo if furtivo else False)
            continue

        # [F] — Toggle modo furtivo
        if entrada_lower == "f":
            if furtivo is not None:
                if furtivo.ativo:
                    furtivo.desativar()
                    console.print("  [dim]Modo furtivo desativado.[/]")
                else:
                    furtivo.ativar()
                    console.print("  [yellow]⚠  Modo furtivo ativado — delays aleatórios, UA rotation.[/]")
            else:
                console.print("  [dim]Modo furtivo não disponível nesta sessão.[/]")
            exibir_menu_principal(agente.disponivel(), furtivo.ativo if furtivo else False)
            continue

        # URL direta
        if entrada.startswith(("http://", "https://", "www.")):
            url = entrada if entrada.startswith("http") else "http://" + entrada
            try:
                processar_url_direta(url, agente)
            except KeyboardInterrupt:
                console.print("\n  [yellow]Interrompido.[/]")
            except Exception as e:
                console.print(f"\n  [red]Erro:[/] {e}")
            _pausar()
            exibir_menu_principal(agente.disponivel(), furtivo.ativo if furtivo else False)
            continue

        # Navegação por número
        if entrada in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "0"):
            try:
                acao = {
                    "1": modulo_scan_completo,
                    "2": modulo_sqlmap,
                    "3": modulo_scanner_web,
                    "4": modulo_waf,
                    "5": modulo_enum_web,
                    "6": modulo_subdominios,
                    "7": modulo_range,
                    "8": modulo_relatorios,
                    "9": lambda: modulo_configuracoes(agente, furtivo),
                    "0": lambda: modulo_chat_ia(agente),
                }[entrada]
                acao()
            except KeyboardInterrupt:
                console.print("\n  [yellow]Módulo interrompido.[/]")
            except Exception as e:
                console.print(f"\n  [red]Erro:[/] {e}")

            _pausar()
            exibir_menu_principal(agente.disponivel(), furtivo.ativo if furtivo else False)
            continue

        # Texto livre → Vlad IA
        if agente.disponivel():
            with console.status("[dim]Vlad está pensando...[/]"):
                resposta = agente.chat(entrada)
            console.print()
            console.print(Panel(
                resposta,
                title="[bold red]Vlad IA[/]",
                border_style="red",
                box=box.ROUNDED,
                expand=False,
            ))
        else:
            console.print(
                "  [dim]Digite um número (1-9, 0) ou configure IA via [9].[/]"
            )

        exibir_menu_principal(agente.disponivel(), furtivo.ativo if furtivo else False)


# ─────────────────────────── MAIN ────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vlad Volkov v2.1 — Framework Interativo de Pentest Web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--alvo", metavar="URL",
                        help="Alvo direto (pula menu, executa scan)")
    parser.add_argument("--lista", metavar="ARQUIVO",
                        help="Arquivo com lista de URLs (uma por linha)")
    parser.add_argument("--modulo", metavar="N", default="1",
                        help="Módulo a usar no range (1=completo, 2=sqli, 3=web, 4=enum)")
    parser.add_argument("--threads", type=int, default=3,
                        help="Threads para range de sites (padrão: 3)")
    parser.add_argument("--silencioso", action="store_true",
                        help="Sem banner, menos output")

    args = parser.parse_args()

    if not args.silencioso:
        exibir_banner()

    # Inicializa agente IA
    from core.agente_ia import AgenteIA
    agente = AgenteIA()

    # Inicializa base de conhecimento e injeta no agente IA
    conhecimento = None
    try:
        from core.conhecimento import BaseConhecimento
        conhecimento = BaseConhecimento()
        agente.set_conhecimento(conhecimento)
    except Exception:
        pass  # Conhecimento é opcional; framework funciona sem ele

    # Inicializa modo furtivo
    furtivo = None
    try:
        from core.modo_furtivo import ModoFurtivo
        furtivo = ModoFurtivo()
        # Aplica proxy furtivo da configuração, se houver
        cfg_proxy = agente.carregar_config_completa().get("proxy_furtivo")
        if cfg_proxy:
            furtivo.proxy = cfg_proxy
    except Exception:
        pass  # Modo furtivo é opcional; framework funciona sem ele

    # Modo não-interativo: --alvo ou --lista
    if args.alvo:
        agente.set_alvo(args.alvo)
        processar_url_direta(args.alvo, agente)
        return

    if args.lista:
        from modulos.scanner_completo import ScannerCompleto
        scanner = ScannerCompleto(verboso=True)
        alvos = scanner.carregar_alvos_arquivo(args.lista)
        if not alvos:
            console.print("[red]Nenhum alvo no arquivo.[/]")
            return

        mapa = {
            "1": None,
            "2": ["sqli"],
            "3": ["xss", "lfi", "ssrf", "cmd", "traversal", "auth"],
            "4": ["enum_web", "subdominios"],
        }
        modulos = mapa.get(args.modulo)
        scanner.escanear_range(alvos, modulos=modulos, threads=args.threads)
        return

    # Modo interativo
    loop_principal(agente, furtivo=furtivo, conhecimento=conhecimento)


if __name__ == "__main__":
    main()
