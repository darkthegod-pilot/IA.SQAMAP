# modulos/scanner_completo.py
# Vlad Volkov — Scanner Completo (orquestra todos os módulos)
# Suporte a site único ou range paralelo com ThreadPoolExecutor

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich import box

console = Console()


class ScannerCompleto:
    """Orquestra todos os módulos do Vlad Volkov para scan total de um alvo ou range."""

    def __init__(self, verboso: bool = True) -> None:
        self.verboso = verboso
        self.threads_range = 3  # threads para range de sites

    # ─────────────────────── SITE ÚNICO ──────────────────────────────────────

    def escanear_site(self, url: str, modulos: Optional[List[str]] = None) -> dict:
        """
        Executa scan completo em um único alvo.
        modulos: lista de módulos a executar. None = todos.
        Retorna dict consolidado com todos os resultados.
        """
        url = self._normalizar_url(url)
        inicio = datetime.now()

        console.print()
        console.print(Panel(
            f"[bold red]◉ SCAN COMPLETO[/]  →  [cyan]{url}[/]",
            box=box.DOUBLE_EDGE,
            border_style="red",
        ))

        resultados_totais: dict = {
            "alvo": url,
            "inicio": inicio.isoformat(),
            "waf": [],
            "tecnologias": [],
            "subdominios": [],
            "diretorios": [],
            "arquivos_sensiveis": [],
            "headers_seguranca": [],
            "sqli": [],
            "xss": [],
            "lfi": [],
            "traversal": [],
            "ssrf": [],
            "cmd": [],
            "auth": [],
            "vulnerabilidades_totais": 0,
        }

        todos_modulos = ["waf", "enum_web", "subdominios", "sqli", "xss", "lfi",
                         "traversal", "ssrf", "cmd", "auth"]
        executar = modulos if modulos else todos_modulos

        # ── 1. Detecção de WAF ────────────────────────────────────────────────
        if "waf" in executar:
            self._fase("WAF", "Detectando Web Application Firewall")
            try:
                from utils import DetectorWAF
                detector = DetectorWAF()
                wafs = detector.detectar(url)
                resultados_totais["waf"] = wafs
                if wafs:
                    console.print(f"    [yellow]⚠  WAF detectado:[/] {', '.join(wafs)}")
                else:
                    console.print("    [green]✓[/] Nenhum WAF detectado")
            except Exception as e:
                console.print(f"    [dim]WAF: {e}[/]")

        # ── 2. Enumeração Web ─────────────────────────────────────────────────
        if "enum_web" in executar:
            self._fase("ENUM WEB", "Enumerando recursos, tecnologias e arquivos")
            try:
                from modulos.enumerador_web import EnumeradorWeb
                enum = EnumeradorWeb()
                resultados_enum = enum.escanear(url, verboso=self.verboso)

                for r in resultados_enum:
                    tipo = r.get("tipo", "")
                    if tipo == "tecnologia":
                        resultados_totais["tecnologias"].append(r.get("item", ""))
                    elif tipo in ("diretorio_encontrado",):
                        resultados_totais["diretorios"].append(r)
                    elif tipo in ("arquivo_sensivel", "segredo_exposto"):
                        resultados_totais["arquivos_sensiveis"].append(r)
                    elif tipo == "header_ausente":
                        resultados_totais["headers_seguranca"].append(r)

                if self.verboso:
                    enum.exibir_resultado()

            except Exception as e:
                console.print(f"    [dim]Enum web: {e}[/]")

        # ── 3. Subdominios ────────────────────────────────────────────────────
        if "subdominios" in executar:
            self._fase("SUBDOMINIOS", "Enumerando subdominios via DNS")
            try:
                from modulos.enum_subdominios import EnumeradorSubdominios
                enum_sub = EnumeradorSubdominios()
                subs = enum_sub.escanear(url, verboso=self.verboso)
                resultados_totais["subdominios"] = subs
                if self.verboso and subs:
                    enum_sub.exibir_resultado()
                elif self.verboso:
                    console.print("    [dim]Nenhum subdominio encontrado.[/]")
            except Exception as e:
                console.print(f"    [dim]Subdominios: {e}[/]")

        # ── 4. SQLMap ─────────────────────────────────────────────────────────
        if "sqli" in executar:
            self._fase("SQL INJECTION", "Testando SQLMap com detecção automática")
            try:
                from core.engine import VladEngine
                engine = VladEngine(verboso=self.verboso)

                # Detecta tampers baseado no WAF encontrado
                waf_str = resultados_totais["waf"][0] if resultados_totais["waf"] else None
                opcoes = {"modo": "padrao", "enum_completo": True}
                if waf_str:
                    opcoes["waf"] = waf_str

                relatorio = engine.scan_sqlmap_direto(url, opcoes=opcoes)

                if relatorio and relatorio.vulnerabilidades:
                    for v in relatorio.vulnerabilidades:
                        resultados_totais["sqli"].append({
                            "tipo": v.tipo,
                            "severidade": v.severidade,
                            "parametro": v.parametro,
                            "descricao": v.descricao,
                            "evidencia": v.evidencia,
                        })
                    console.print(
                        f"    [red]⚡ {len(relatorio.vulnerabilidades)} vulnerabilidade(s) SQLi encontrada(s)![/]"
                    )
                else:
                    console.print("    [green]✓[/] Nenhuma SQLi detectada")
            except Exception as e:
                console.print(f"    [dim]SQLi: {e}[/]")

        # ── 5. XSS ───────────────────────────────────────────────────────────
        if "xss" in executar:
            self._fase("XSS", "Testando Cross-Site Scripting")
            try:
                from modulos import ScannerXSS
                scanner = ScannerXSS()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["xss"] = vulns
                if vulns:
                    console.print(f"    [red]⚡ {len(vulns)} XSS encontrado(s)![/]")
                    if self.verboso:
                        scanner.exibir_resultado()
                else:
                    console.print("    [green]✓[/] Nenhum XSS detectado")
            except Exception as e:
                console.print(f"    [dim]XSS: {e}[/]")

        # ── 6. LFI ───────────────────────────────────────────────────────────
        if "lfi" in executar:
            self._fase("LFI", "Testando Local File Inclusion")
            try:
                from modulos import ScannerLFI
                scanner = ScannerLFI()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["lfi"] = vulns
                if vulns:
                    console.print(f"    [red]⚡ {len(vulns)} LFI encontrado(s)![/]")
                    if self.verboso:
                        scanner.exibir_resultado()
                else:
                    console.print("    [green]✓[/] Nenhum LFI detectado")
            except Exception as e:
                console.print(f"    [dim]LFI: {e}[/]")

        # ── 7. Directory Traversal ────────────────────────────────────────────
        if "traversal" in executar:
            self._fase("TRAVERSAL", "Testando Directory Traversal")
            try:
                from modulos import ScannerTraversal
                scanner = ScannerTraversal()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["traversal"] = vulns
                if vulns:
                    console.print(f"    [red]⚡ {len(vulns)} Traversal encontrado(s)![/]")
                else:
                    console.print("    [green]✓[/] Nenhum Traversal detectado")
            except Exception as e:
                console.print(f"    [dim]Traversal: {e}[/]")

        # ── 8. SSRF ───────────────────────────────────────────────────────────
        if "ssrf" in executar:
            self._fase("SSRF", "Testando Server-Side Request Forgery")
            try:
                from modulos import ScannerSSRF
                scanner = ScannerSSRF()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["ssrf"] = vulns
                if vulns:
                    console.print(f"    [red]⚡ {len(vulns)} SSRF encontrado(s)![/]")
                else:
                    console.print("    [green]✓[/] Nenhum SSRF detectado")
            except Exception as e:
                console.print(f"    [dim]SSRF: {e}[/]")

        # ── 9. Command Injection ──────────────────────────────────────────────
        if "cmd" in executar:
            self._fase("CMD INJECTION", "Testando Command Injection")
            try:
                from modulos import ScannerInjecaoCmd
                scanner = ScannerInjecaoCmd()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["cmd"] = vulns
                if vulns:
                    console.print(f"    [red]⚡ {len(vulns)} Command Injection encontrado(s)![/]")
                else:
                    console.print("    [green]✓[/] Nenhum Command Injection detectado")
            except Exception as e:
                console.print(f"    [dim]CMD: {e}[/]")

        # ── 10. Auth Bypass ───────────────────────────────────────────────────
        if "auth" in executar:
            self._fase("AUTH BYPASS", "Testando bypass de autenticação")
            try:
                from modulos import ScannerBypassAuth
                scanner = ScannerBypassAuth()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["auth"] = vulns
                if vulns:
                    console.print(f"    [red]⚡ {len(vulns)} Auth Bypass encontrado(s)![/]")
                else:
                    console.print("    [green]✓[/] Nenhum Auth Bypass detectado")
            except Exception as e:
                console.print(f"    [dim]Auth: {e}[/]")

        # ── Totais ────────────────────────────────────────────────────────────
        fim = datetime.now()
        resultados_totais["fim"] = fim.isoformat()
        resultados_totais["duracao_s"] = (fim - inicio).total_seconds()

        total_vulns = sum([
            len(resultados_totais["sqli"]),
            len(resultados_totais["xss"]),
            len(resultados_totais["lfi"]),
            len(resultados_totais["traversal"]),
            len(resultados_totais["ssrf"]),
            len(resultados_totais["cmd"]),
            len(resultados_totais["auth"]),
            len(resultados_totais["arquivos_sensiveis"]),
        ])
        resultados_totais["vulnerabilidades_totais"] = total_vulns

        self._exibir_resumo(resultados_totais)
        self._salvar_relatorio(resultados_totais)

        return resultados_totais

    # ─────────────────────── RANGE DE SITES ──────────────────────────────────

    def escanear_range(self, alvos: List[str], modulos: Optional[List[str]] = None,
                       threads: int = 3) -> List[dict]:
        """Escaneia lista de sites em paralelo com ThreadPoolExecutor."""
        console.print(Panel(
            f"[bold red]◉ RANGE SCAN[/]  →  [cyan]{len(alvos)} alvos[/]  "
            f"[dim]({threads} threads simultâneas)[/]",
            box=box.DOUBLE_EDGE,
            border_style="red",
        ))

        relatorios: list[dict] = []
        concluidos = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Escaneando alvos[/]"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[atual]}[/]"),
            console=console,
        ) as prog:
            tarefa = prog.add_task("", total=len(alvos), atual="aguardando...")

            def scan_um(url: str) -> dict:
                scanner = ScannerCompleto(verboso=False)
                return scanner.escanear_site(url, modulos=modulos)

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan_um, a): a for a in alvos}
                for fut in as_completed(futures):
                    alvo = futures[fut]
                    concluidos += 1
                    try:
                        r = fut.result()
                        relatorios.append(r)
                    except Exception as e:
                        relatorios.append({"alvo": alvo, "erro": str(e)})
                    prog.update(tarefa, advance=1, atual=alvo)

        self._exibir_resumo_range(relatorios)
        return relatorios

    def carregar_alvos_arquivo(self, caminho: str) -> List[str]:
        """Carrega lista de URLs de um arquivo .txt (um por linha)."""
        try:
            conteudo = Path(caminho).read_text(encoding="utf-8")
            linhas = [l.strip() for l in conteudo.splitlines()]
            return [l for l in linhas if l and not l.startswith("#")]
        except OSError as e:
            console.print(f"[red]Erro ao abrir arquivo:[/] {e}")
            return []

    def carregar_alvos_range_ip(self, range_ip: str, porta: int = 80) -> List[str]:
        """
        Converte range de IP em lista de URLs.
        Exemplos: '192.168.1.1-254', '192.168.1.0/24'
        """
        alvos = []

        try:
            # CIDR notation
            if "/" in range_ip:
                rede = ipaddress.ip_network(range_ip, strict=False)
                for ip in rede.hosts():
                    alvos.append(f"http://{ip}:{porta}")
            # Dash range: 192.168.1.1-254
            elif "-" in range_ip:
                partes = range_ip.rsplit("-", 1)
                base = partes[0]
                fim_octeto = int(partes[1])
                inicio_octeto = int(base.rsplit(".", 1)[-1])
                prefixo = base.rsplit(".", 1)[0]
                for i in range(inicio_octeto, fim_octeto + 1):
                    alvos.append(f"http://{prefixo}.{i}:{porta}")
            else:
                alvos.append(f"http://{range_ip}:{porta}")
        except (ValueError, IndexError) as e:
            console.print(f"[red]Range inválido:[/] {e}")

        return alvos

    # ─────────────────────── HELPERS ─────────────────────────────────────────

    def _normalizar_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")

    def _fase(self, nome: str, descricao: str) -> None:
        if self.verboso:
            console.print(f"\n  [bold yellow]◉ {nome}[/]  [dim]{descricao}[/]")

    def _exibir_resumo(self, r: dict) -> None:
        """Exibe painel de resumo do scan completo."""
        total = r.get("vulnerabilidades_totais", 0)
        duracao = r.get("duracao_s", 0)
        cor = "red" if total > 0 else "green"

        linhas = [
            f"[bold]Alvo:[/]       {r['alvo']}",
            f"[bold]Duração:[/]    {duracao:.1f}s",
            f"[bold]WAF:[/]        {', '.join(r['waf']) if r['waf'] else 'Não detectado'}",
            f"[bold]Techs:[/]      {', '.join(r['tecnologias']) if r['tecnologias'] else '—'}",
            f"[bold]Subdominios:[/] {len(r['subdominios'])} encontrados",
            f"[bold]Diretórios:[/] {len(r['diretorios'])} acessíveis",
            "",
        ]

        categorias = [
            ("SQL Injection", "sqli"),
            ("XSS", "xss"),
            ("LFI", "lfi"),
            ("Traversal", "traversal"),
            ("SSRF", "ssrf"),
            ("Cmd Injection", "cmd"),
            ("Auth Bypass", "auth"),
            ("Arq. Sensíveis", "arquivos_sensiveis"),
        ]

        for nome, chave in categorias:
            cnt = len(r.get(chave, []))
            if cnt:
                linhas.append(f"  [red]⚡ {nome}:[/] {cnt} vulnerabilidade(s)")

        linhas.append("")
        linhas.append(f"[bold {cor}]TOTAL: {total} vulnerabilidade(s) encontrada(s)[/]")

        console.print()
        console.print(Panel(
            "\n".join(linhas),
            title="[bold]RESUMO DO SCAN COMPLETO[/]",
            box=box.DOUBLE_EDGE,
            border_style=cor,
        ))

    def _exibir_resumo_range(self, relatorios: list[dict]) -> None:
        """Exibe tabela de resumo do range scan."""
        console.print()
        tabela = Table(
            title=f"Resumo Range Scan ({len(relatorios)} alvos)",
            box=box.ROUNDED,
            border_style="cyan",
        )
        tabela.add_column("Alvo", style="cyan")
        tabela.add_column("SQLi", style="red", justify="right")
        tabela.add_column("XSS", style="red", justify="right")
        tabela.add_column("LFI", style="red", justify="right")
        tabela.add_column("CMD", style="red", justify="right")
        tabela.add_column("Total", style="bold", justify="right")
        tabela.add_column("Status", style="white")

        for r in relatorios:
            if "erro" in r:
                tabela.add_row(r["alvo"], "—", "—", "—", "—", "—", f"[red]ERRO: {r['erro'][:30]}[/]")
                continue

            total = r.get("vulnerabilidades_totais", 0)
            cor = "red" if total > 0 else "green"
            tabela.add_row(
                r.get("alvo", "?"),
                str(len(r.get("sqli", []))),
                str(len(r.get("xss", []))),
                str(len(r.get("lfi", []))),
                str(len(r.get("cmd", []))),
                f"[{cor}]{total}[/{cor}]",
                "[green]OK[/]" if total == 0 else f"[red]⚡ {total} vuln(s)[/]",
            )

        console.print(tabela)

    def _salvar_relatorio(self, r: dict) -> Optional[str]:
        """Salva relatório em JSON."""
        try:
            import json
            dir_rel = Path("relatorios")
            dir_rel.mkdir(exist_ok=True)
            alvo_slug = r["alvo"].replace("http://", "").replace("https://", "").replace("/", "_")[:40]
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome = dir_rel / f"{alvo_slug}_{ts}_completo.json"

            def _serializar(obj):
                if hasattr(obj, "__dict__"):
                    return obj.__dict__
                return str(obj)

            nome.write_text(json.dumps(r, indent=2, ensure_ascii=False, default=_serializar))
            console.print(f"\n  [dim]Relatório salvo:[/] {nome}")
            return str(nome)
        except Exception:
            return None
