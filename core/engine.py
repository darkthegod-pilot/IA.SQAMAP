"""
Motor principal do Vlad Volkov — orquestrador de todos os scans.
"""

import shlex
import subprocess
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TimeRemainingColumn, TaskProgressColumn
)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.live import Live
from rich.columns import Columns

from core.reporter import Relatorio
from core.logger import obter_logger
from utils.detector_waf import DetectorWAF
from utils.seletor_tamper import SeletorTamper
from utils.conselheiro_tecnica import ConselheiroTecnica
from utils.construtor_comando import ConstrutorComando
from utils.parser_saida import ParserSaida

console = Console()
log = obter_logger()

DIR_SAIDA = Path("saidas")
DIR_SAIDA.mkdir(exist_ok=True)


def _imprimir_fase(nome: str, icone: str = "◉") -> None:
    """Imprime cabeçalho de fase."""
    console.print()
    console.print(f"[bold cyan]{icone}[/bold cyan] [bold white]{nome}[/bold white]")
    console.print("[dim]" + "─" * 55 + "[/dim]")


def _imprimir_ok(mensagem: str, detalhe: str = "") -> None:
    """Imprime mensagem de sucesso."""
    if detalhe:
        console.print(f"  [bold green]✓[/bold green] {mensagem} [dim]{detalhe}[/dim]")
    else:
        console.print(f"  [bold green]✓[/bold green] {mensagem}")


def _imprimir_aviso(mensagem: str) -> None:
    """Imprime aviso."""
    console.print(f"  [bold yellow]![/bold yellow] {mensagem}")


def _imprimir_erro(mensagem: str) -> None:
    """Imprime erro."""
    console.print(f"  [bold red]✗[/bold red] {mensagem}")


def _imprimir_info(mensagem: str) -> None:
    """Imprime informação."""
    console.print(f"  [bold blue]→[/bold blue] {mensagem}")


class VladEngine:
    """Motor principal do Vlad Volkov."""

    def __init__(self, verboso: bool = False, modo_silencioso: bool = False):
        self.verboso = verboso
        self.modo_silencioso = modo_silencioso
        self.detector_waf = DetectorWAF()
        self.seletor_tamper = SeletorTamper()
        self.conselheiro = ConselheiroTecnica()
        self.construtor = ConstrutorComando()
        self.parser = ParserSaida()

    def _verificar_sqlmap(self) -> bool:
        """Verifica se o sqlmap está instalado."""
        return shutil.which("sqlmap") is not None

    def escanear_automatico(self, alvo: str, opcoes: dict = None) -> Relatorio:
        """
        Modo automático total: recon → WAF → SQLi → web attacks → relatório.
        """
        opcoes = opcoes or {}
        relatorio = Relatorio(alvo=alvo)

        console.print()
        console.print(Panel(
            f"[bold white]Alvo:[/bold white] [bold cyan]{alvo}[/bold cyan]\n"
            f"[bold white]Modo:[/bold white] [bold green]AUTOMÁTICO TOTAL[/bold green]",
            title="[bold red]VLAD VOLKOV — INICIANDO[/bold red]",
            border_style="red",
            box=box.DOUBLE_EDGE
        ))

        # Fase 1: Reconhecimento
        waf, dbms, tampers = self._fase_reconhecimento(alvo, relatorio)

        # Fase 2: SQLMap automatizado (especialidade principal)
        if not opcoes.get("pular_sqli"):
            self._fase_sqlmap(alvo, waf, tampers, dbms, relatorio, opcoes)

        # Fase 3: Testes web adicionais
        if not opcoes.get("pular_web"):
            self._fase_testes_web(alvo, relatorio)

        # Finalizar relatório
        relatorio.fim = datetime.now()
        relatorio.exibir_resumo_terminal()

        # Salvar
        caminho_json = relatorio.salvar_json()
        caminho_md = relatorio.salvar_markdown()
        console.print()
        _imprimir_ok(f"Relatório JSON: [cyan]{caminho_json}[/cyan]")
        _imprimir_ok(f"Relatório MD:   [cyan]{caminho_md}[/cyan]")

        return relatorio

    def _fase_reconhecimento(self, alvo: str, relatorio: Relatorio):
        """Fase de reconhecimento: WAF + DBMS + parâmetros."""
        _imprimir_fase("FASE 1 — RECONHECIMENTO", "🔍")

        waf_detectado = None
        dbms_detectado = None
        tampers_recomendados = "space2comment,randomcase"

        # Detectar WAF
        with console.status("[bold cyan]Detectando WAF do alvo...[/bold cyan]", spinner="dots"):
            time.sleep(0.5)
            wafs = self.detector_waf.detectar(alvo)

        if wafs:
            waf_detectado = wafs[0]
            relatorio.waf_detectado = waf_detectado
            tampers_recomendados = self.detector_waf.obter_recomendacao_tamper(wafs)
            _imprimir_ok(f"WAF detectado: [bold yellow]{waf_detectado}[/bold yellow]",
                          f"(tampers: {tampers_recomendados})")
        else:
            _imprimir_info("Nenhum WAF detectado (ou não identificado)")

        # Obter informações de tecnologia
        with console.status("[bold cyan]Identificando tecnologia do servidor...[/bold cyan]", spinner="dots"):
            time.sleep(0.3)
            info_tech = self.detector_waf.obter_info_tecnologia(alvo)

        if info_tech.get("dbms"):
            dbms_detectado = info_tech["dbms"]
            relatorio.dbms = dbms_detectado
            _imprimir_ok(f"DBMS identificado: [bold magenta]{dbms_detectado}[/bold magenta]")
        if info_tech.get("tecnologia"):
            relatorio.tecnologia_web = info_tech["tecnologia"]
            _imprimir_info(f"Tecnologia: {info_tech['tecnologia']}")

        _imprimir_ok("Reconhecimento concluído")
        return waf_detectado, dbms_detectado, tampers_recomendados

    def _fase_sqlmap(self, alvo: str, waf: Optional[str], tampers: str,
                      dbms: Optional[str], relatorio: Relatorio, opcoes: dict) -> None:
        """Fase principal: SQLMap automatizado."""
        _imprimir_fase("FASE 2 — SQLMap AUTOMATIZADO (Especialidade do Vlad)", "💉")

        if not self._verificar_sqlmap():
            _imprimir_erro("sqlmap não encontrado! Instale com: apt-get install sqlmap")
            _imprimir_aviso("Pulando fase SQLMap...")
            return

        # Determinar perfil de scan
        if waf:
            perfil = f"waf_{waf.lower().split()[0]}"
        else:
            perfil = "scan_rapido"

        cfg_path = Path(f"configs/{perfil}.cfg")
        if not cfg_path.exists():
            cfg_path = Path("configs/scan_rapido.cfg")

        _imprimir_info(f"Perfil de scan: [cyan]{cfg_path.name}[/cyan]")
        if tampers and tampers != "space2comment,randomcase":
            _imprimir_info(f"Tampers ativos: [yellow]{tampers}[/yellow]")

        # Construir comando sqlmap
        cmd_args = {
            "alvo": alvo,
            "dbms": dbms,
            "tampers": tampers if waf else None,
        }
        cmd = self.construtor.construir_scan_basico(**cmd_args)
        _imprimir_info(f"Executando: [dim]{cmd[:70]}...[/dim]" if len(cmd) > 70 else f"Executando: [dim]{cmd}[/dim]")

        # Progresso das etapas do SQLMap
        etapas = [
            ("Testando conectividade e baseline...", 0.15),
            ("Detectando pontos de injeção...", 0.30),
            ("Testando Booleano-cego (B)...", 0.10),
            ("Testando Baseado-em-Erro (E)...", 0.10),
            ("Testando UNION-based (U)...", 0.10),
            ("Testando Tempo-cego (T)...", 0.10),
            ("Analisando resultados...", 0.15),
        ]

        with Progress(
            SpinnerColumn(spinner_name="dots12", style="bold cyan"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        ) as progress:
            tarefa = progress.add_task("[cyan]Iniciando SQLMap...[/cyan]", total=100)

            progresso_atual = 0
            for descricao, pct in etapas:
                progress.update(tarefa, description=f"[cyan]{descricao}[/cyan]")
                alvo_pct = int(progresso_atual + pct * 100)
                while progresso_atual < alvo_pct:
                    time.sleep(0.05)
                    progresso_atual = min(progresso_atual + 2, alvo_pct)
                    progress.update(tarefa, completed=progresso_atual)

            progress.update(tarefa, completed=100, description="[bold green]SQLMap concluído![/bold green]")

        # Executar sqlmap real (não-bloqueante, modo batch)
        saida_dir = DIR_SAIDA / f"sqlmap_{int(time.time())}"
        cmd_real = self.construtor.construir_cmd_completo(
            alvo=alvo,
            dbms=dbms,
            tampers=tampers if waf else None,
            dir_saida=str(saida_dir),
        )

        proc = None
        try:
            # Usar shlex.split para evitar shell injection (sem shell=True)
            try:
                cmd_parts = shlex.split(cmd_real)
            except ValueError:
                # Fallback: split simples se shlex falhar
                cmd_parts = cmd_real.split()

            proc = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(timeout=300)
            saida_texto = stdout + stderr

            # Parsear saída
            achado = self.parser.analisar(saida_texto)

            if achado.injetavel:
                parametros = achado.parametros_injetaveis or ["parâmetro detectado"]
                for pi in parametros:
                    relatorio.adicionar_vuln(
                        tipo="SQL Injection",
                        severidade="critico" if achado.eh_dba else "alto",
                        parametro=pi,
                        descricao=(
                            f"Injeção SQL via {pi}. "
                            f"Técnicas: {', '.join(achado.tecnicas_encontradas) or 'não identificadas'}"
                        ),
                        evidencia=pi,
                        recomendacao="Use consultas parametrizadas (prepared statements)"
                    )
                _imprimir_ok(
                    f"[bold red]INJEÇÃO SQL CONFIRMADA![/bold red] "
                    f"{len(parametros)} ponto(s) vulnerável(eis)"
                )
            else:
                _imprimir_info("Nenhuma injeção SQL detectada neste parâmetro")

            if achado.dbms and not relatorio.dbms:
                relatorio.dbms = achado.dbms
            if achado.sistema_op and not relatorio.sistema_op:
                relatorio.sistema_op = achado.sistema_op
            if achado.usuario_db:
                relatorio.usuario_db = achado.usuario_db
            if achado.eh_dba:
                relatorio.eh_dba = True
            if achado.bancos:
                relatorio.bancos_encontrados = achado.bancos
            if achado.dados_extraidos:
                relatorio.credenciais_extraidas = len(achado.dados_extraidos)

        except subprocess.TimeoutExpired:
            # Encerrar processo que ainda está rodando
            if proc is not None:
                try:
                    proc.kill()
                    proc.communicate()
                except Exception:
                    pass
            _imprimir_aviso("SQLMap excedeu o tempo limite (5 min). Considere usar scan mais focado.")
        except FileNotFoundError:
            _imprimir_erro("sqlmap não encontrado no PATH. Instale com: pip3 install sqlmap")
        except Exception as e:
            _imprimir_aviso(f"Erro ao executar SQLMap: {e}")

    def _fase_testes_web(self, alvo: str, relatorio: Relatorio) -> None:
        """Fase de testes web adicionais."""
        _imprimir_fase("FASE 3 — TESTES DE VULNERABILIDADES WEB", "🌐")

        try:
            from modulos.xss_scanner import ScannerXSS
            from modulos.lfi_scanner import ScannerLFI
            from modulos.traversal_scanner import ScannerTraversal
        except ImportError as e:
            _imprimir_aviso(f"Módulo não disponível: {e}")
            return

        testes = [
            ("XSS Refletido", ScannerXSS, "xss"),
            ("LFI/RFI", ScannerLFI, "lfi"),
            ("Directory Traversal", ScannerTraversal, "traversal"),
        ]

        for nome_teste, ClasseScanner, tipo in testes:
            with console.status(f"[bold cyan]Testando {nome_teste}...[/bold cyan]", spinner="dots"):
                try:
                    scanner = ClasseScanner(alvo)
                    resultados = scanner.escanear()

                    if resultados:
                        for r in resultados:
                            relatorio.adicionar_vuln(
                                tipo=nome_teste,
                                severidade=r.get("severidade", "medio"),
                                parametro=r.get("parametro", "desconhecido"),
                                descricao=r.get("descricao", nome_teste),
                                evidencia=r.get("payload", ""),
                                recomendacao=r.get("recomendacao", "Validar e sanitizar entrada")
                            )
                        _imprimir_ok(
                            f"[bold red]{nome_teste}[/bold red] detectado! "
                            f"{len(resultados)} ocorrência(s)"
                        )
                    else:
                        _imprimir_ok(f"{nome_teste}: nenhuma vulnerabilidade detectada")
                except Exception as e:
                    _imprimir_aviso(f"{nome_teste}: erro durante teste — {e}")

    def scan_sqlmap_direto(self, alvo: str, opcoes: dict = None) -> Relatorio:
        """
        Executa apenas o SQLMap (sem testes web adicionais).
        Modo principal da especialidade do Vlad.
        """
        opcoes = opcoes or {}
        relatorio = Relatorio(alvo=alvo)
        opcoes["pular_web"] = True

        console.print()
        console.print(Panel(
            f"[bold white]Alvo:[/bold white] [bold cyan]{alvo}[/bold cyan]\n"
            f"[bold white]Modo:[/bold white] [bold yellow]SQLMap Automatizado[/bold yellow]",
            title="[bold red]VLAD VOLKOV — SQLMap[/bold red]",
            border_style="cyan",
            box=box.ROUNDED
        ))

        waf, dbms, tampers = self._fase_reconhecimento(alvo, relatorio)
        self._fase_sqlmap(alvo, waf, tampers, dbms, relatorio, opcoes)

        relatorio.fim = datetime.now()
        relatorio.exibir_resumo_terminal()

        caminho_json = relatorio.salvar_json()
        _imprimir_ok(f"Relatório salvo: [cyan]{caminho_json}[/cyan]")

        return relatorio

    def testar_web(self, alvo: str, tipos: List[str] = None) -> Relatorio:
        """
        Executa apenas os testes de vulnerabilidades web.
        """
        relatorio = Relatorio(alvo=alvo)

        tipos_disponiveis = ["xss", "lfi", "traversal", "ssrf", "cmd", "auth"]
        tipos_ativos = tipos if tipos else tipos_disponiveis

        console.print()
        console.print(Panel(
            f"[bold white]Alvo:[/bold white] [bold cyan]{alvo}[/bold cyan]\n"
            f"[bold white]Testes:[/bold white] [bold yellow]{', '.join(tipos_ativos)}[/bold yellow]",
            title="[bold red]VLAD VOLKOV — Testes Web[/bold red]",
            border_style="blue",
            box=box.ROUNDED
        ))

        self._fase_testes_web(alvo, relatorio)

        relatorio.fim = datetime.now()
        relatorio.exibir_resumo_terminal()

        caminho_json = relatorio.salvar_json()
        _imprimir_ok(f"Relatório salvo: [cyan]{caminho_json}[/cyan]")

        return relatorio

    def detectar_waf(self, alvo: str) -> None:
        """Detecta e exibe informações sobre WAF do alvo."""
        _imprimir_fase("DETECÇÃO DE WAF", "🛡")

        with console.status("[bold cyan]Analisando o alvo...[/bold cyan]", spinner="bouncingBar"):
            wafs = self.detector_waf.detectar(alvo, modo_probe=True)
            info = self.detector_waf.obter_info_tecnologia(alvo)

        if wafs:
            for waf in wafs:
                _imprimir_ok(f"WAF detectado: [bold yellow]{waf}[/bold yellow]")
            tampers = self.detector_waf.obter_recomendacao_tamper(wafs)
            console.print()
            _imprimir_info(f"Tampers recomendados: [yellow]{tampers}[/yellow]")
            console.print()
            _imprimir_info(
                f"Comando SQLMap: [dim]sqlmap -u \"{alvo}\" "
                f"--tamper={tampers} --random-agent --delay=2 --batch[/dim]"
            )
        else:
            _imprimir_info("Nenhum WAF identificado (ou WAF não reconhecido)")

        if info:
            console.print()
            tabela = Table(box=box.SIMPLE, show_header=False)
            tabela.add_column("Campo", style="bold cyan", width=20)
            tabela.add_column("Valor")
            for k, v in info.items():
                if v:
                    tabela.add_row(k.capitalize(), str(v))
            console.print(tabela)

    def selecionar_tampers(self, waf: str, dbms: str = "all", nivel: str = "padrao") -> None:
        """Seleciona e exibe tampers recomendados."""
        _imprimir_fase("SELEÇÃO DE TAMPERS", "🔧")

        niveis_map = {"leve": "light", "padrao": "standard", "pesado": "heavy"}
        nivel_en = niveis_map.get(nivel, "standard")

        chain = self.seletor_tamper.construir_chain(waf, dbms, nivel_en)
        tampers = self.seletor_tamper.selecionar(waf, dbms, verboso=True)

        tabela = Table(title=f"Tampers para WAF: {waf} | DBMS: {dbms}", box=box.ROUNDED)
        tabela.add_column("Tamper", style="cyan")
        tabela.add_column("Função")

        descricoes = {
            "space2comment": "Substitui espaços por /**/",
            "randomcase": "Aleatoriza maiúsculas/minúsculas",
            "charencode": "Codifica payload em URL encoding",
            "between": "Substitui > por NOT BETWEEN",
            "greatest": "Substitui > por GREATEST()",
            "modsecurityzeroversioned": "Comenta versão zero (ModSecurity)",
            "chardoubleencode": "Codifica duplo URL",
            "apostrophemask": "Substitui aspas por UTF-8",
        }

        for t in tampers:
            tabela.add_row(t, descricoes.get(t, "Técnica de evasão de WAF"))

        console.print(tabela)
        console.print()
        _imprimir_ok(f"Chain completa: [yellow]--tamper={chain}[/yellow]")
