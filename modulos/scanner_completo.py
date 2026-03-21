# modulos/scanner_completo.py
# Vlad Volkov — Scanner Completo (orquestra todos os módulos)
# Suporte a site único ou range com output sequencial prefixado por site

from __future__ import annotations

import ipaddress
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

# Lock global para prints thread-safe no output sequencial
_print_lock = threading.Lock()

# Cores por índice de site (ciclam se > 8 sites)
_CORES_SITE = ["cyan", "green", "yellow", "magenta", "blue", "red", "white", "bright_cyan"]


def _prefixo(n: int, total: int) -> str:
    """Gera prefixo colorido [Site N/T]."""
    cor = _CORES_SITE[(n - 1) % len(_CORES_SITE)]
    return f"[bold {cor}][Site {n}/{total}][/]"


def _print_site(n: int, total: int, msg: str) -> None:
    """Print thread-safe com prefixo de site."""
    with _print_lock:
        console.print(f"{_prefixo(n, total)} {msg}")


def _parsear_selecao_range(entrada: str, total: int) -> List[int]:
    """
    Converte seleção de texto em lista de índices 0-based.

    Exemplos:
      "3"       → [2]
      "1-7"     → [0,1,2,3,4,5,6]
      "1,3,5"   → [0,2,4]
      "" / "todos" / "all" → todos os índices
    """
    entrada = entrada.strip().lower()
    if not entrada or entrada in ("todos", "all", "tudo", "a"):
        return list(range(total))

    indices: List[int] = []

    # Dividir por vírgulas (suporta "1,3,5" e "1-3,5,7-9")
    partes = [p.strip() for p in entrada.split(",")]
    for parte in partes:
        if not parte:
            continue
        if "-" in parte:
            # Range: "1-7"
            seg = parte.split("-", 1)
            try:
                inicio = max(1, int(seg[0]))
                fim = min(total, int(seg[1]))
                for i in range(inicio, fim + 1):
                    idx = i - 1
                    if 0 <= idx < total and idx not in indices:
                        indices.append(idx)
            except (ValueError, IndexError):
                pass
        else:
            # Número único: "3"
            try:
                n = int(parte)
                idx = n - 1
                if 0 <= idx < total and idx not in indices:
                    indices.append(idx)
            except ValueError:
                pass

    return sorted(indices) if indices else list(range(total))


class ScannerCompleto:
    """Orquestra todos os módulos do Vlad Volkov para scan total de um alvo ou range."""

    def __init__(self, verboso: bool = True) -> None:
        self.verboso = verboso
        self.threads_range = 3

    # ─────────────────────── SITE ÚNICO ──────────────────────────────────────

    def escanear_site(self, url: str, modulos: Optional[List[str]] = None,
                      prefixo: str = "") -> dict:
        """
        Executa scan completo em um único alvo.
        prefixo: usado em range scan para identificar o site nos logs.
        """
        url = self._normalizar_url(url)
        inicio = datetime.now()

        def _p(msg: str) -> None:
            if prefixo:
                with _print_lock:
                    console.print(f"{prefixo} {msg}")
            elif self.verboso:
                console.print(msg)

        if not prefixo:
            console.print()
            console.print(Panel(
                f"[bold red]◉ SCAN COMPLETO[/]  →  [cyan]{url}[/]",
                box=box.DOUBLE_EDGE,
                border_style="red",
            ))

        resultados_totais: dict = {
            "alvo": url,
            "inicio": inicio.isoformat(),
            "waf": [], "tecnologias": [], "subdominios": [],
            "diretorios": [], "arquivos_sensiveis": [],
            "headers_seguranca": [], "sqli": [], "xss": [],
            "lfi": [], "traversal": [], "ssrf": [], "cmd": [], "auth": [],
            "vulnerabilidades_totais": 0,
        }

        todos_modulos = ["waf", "enum_web", "subdominios", "sqli", "xss",
                         "lfi", "traversal", "ssrf", "cmd", "auth"]
        executar = modulos if modulos else todos_modulos

        # ── 1. Detecção de WAF ────────────────────────────────────────────────
        if "waf" in executar:
            _p("[yellow]◉ WAF[/] Detectando Web Application Firewall...")
            try:
                from utils import DetectorWAF
                detector = DetectorWAF()
                wafs = detector.detectar(url)
                resultados_totais["waf"] = wafs
                if wafs:
                    _p(f"[yellow]⚠  WAF detectado:[/] {', '.join(wafs)}")
                else:
                    _p("[green]✓[/] Nenhum WAF detectado")
            except Exception as e:
                _p(f"[dim]WAF: {e}[/]")

        # ── 2. Enumeração Web ─────────────────────────────────────────────────
        if "enum_web" in executar:
            _p("[cyan]◉ ENUM WEB[/] Enumerando recursos e tecnologias...")
            try:
                from modulos.enumerador_web import EnumeradorWeb
                enum = EnumeradorWeb(verificar_ssl=True)
                resultados_enum = enum.escanear(url, verboso=False)
                for r in resultados_enum:
                    tipo = r.get("tipo", "")
                    if tipo == "tecnologia":
                        resultados_totais["tecnologias"].append(r.get("item", ""))
                    elif tipo == "diretorio_encontrado":
                        resultados_totais["diretorios"].append(r)
                    elif tipo in ("arquivo_sensivel", "segredo_exposto"):
                        resultados_totais["arquivos_sensiveis"].append(r)
                    elif tipo == "header_ausente":
                        resultados_totais["headers_seguranca"].append(r)
                techs = resultados_totais["tecnologias"]
                dirs_count = len(resultados_totais["diretorios"])
                _p(f"[green]✓[/] Techs: {', '.join(techs) or '—'} | Diretórios: {dirs_count}")
            except Exception as e:
                _p(f"[dim]Enum web: {e}[/]")

        # ── 3. Subdominios ────────────────────────────────────────────────────
        if "subdominios" in executar:
            _p("[cyan]◉ SUBS[/] Enumerando subdominios via DNS...")
            try:
                from modulos.enum_subdominios import EnumeradorSubdominios
                enum_sub = EnumeradorSubdominios()
                subs = enum_sub.escanear(url, verboso=False)
                resultados_totais["subdominios"] = subs
                _p(f"[green]✓[/] Subdominios encontrados: {len(subs)}")
            except Exception as e:
                _p(f"[dim]Subdominios: {e}[/]")

        # ── 4. SQLMap ─────────────────────────────────────────────────────────
        if "sqli" in executar:
            _p("[red]◉ SQLi[/] Testando SQL Injection com SQLMap...")
            try:
                from core.engine import VladEngine
                engine = VladEngine(verboso=not bool(prefixo))
                waf_str = resultados_totais["waf"][0] if resultados_totais["waf"] else None
                opcoes: dict = {"modo": "padrao"}
                if waf_str:
                    opcoes["waf"] = waf_str
                relatorio = engine.scan_sqlmap_direto(url, opcoes=opcoes)
                if relatorio and relatorio.vulnerabilidades:
                    for v in relatorio.vulnerabilidades:
                        resultados_totais["sqli"].append({
                            "tipo": v.tipo, "severidade": v.severidade,
                            "parametro": v.parametro, "descricao": v.descricao,
                        })
                    _p(f"[red]⚡ SQLi: {len(relatorio.vulnerabilidades)} vulnerabilidade(s)![/]")
                else:
                    _p("[green]✓[/] SQLi: nenhuma detectada")
            except Exception as e:
                _p(f"[dim]SQLi: {e}[/]")

        # ── 5. XSS ───────────────────────────────────────────────────────────
        if "xss" in executar:
            _p("[yellow]◉ XSS[/] Testando Cross-Site Scripting...")
            try:
                from modulos import ScannerXSS
                scanner = ScannerXSS()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["xss"] = vulns
                if vulns:
                    _p(f"[red]⚡ XSS: {len(vulns)} encontrado(s)![/]")
                else:
                    _p("[green]✓[/] XSS: nenhum detectado")
            except Exception as e:
                _p(f"[dim]XSS: {e}[/]")

        # ── 6. LFI ───────────────────────────────────────────────────────────
        if "lfi" in executar:
            _p("[yellow]◉ LFI[/] Testando Local File Inclusion...")
            try:
                from modulos import ScannerLFI
                scanner = ScannerLFI()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["lfi"] = vulns
                if vulns:
                    _p(f"[red]⚡ LFI: {len(vulns)} encontrado(s)![/]")
                else:
                    _p("[green]✓[/] LFI: nenhum detectado")
            except Exception as e:
                _p(f"[dim]LFI: {e}[/]")

        # ── 7. Traversal ──────────────────────────────────────────────────────
        if "traversal" in executar:
            _p("[yellow]◉ TRAVERSAL[/] Testando Directory Traversal...")
            try:
                from modulos import ScannerTraversal
                scanner = ScannerTraversal()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["traversal"] = vulns
                if vulns:
                    _p(f"[red]⚡ Traversal: {len(vulns)} encontrado(s)![/]")
                else:
                    _p("[green]✓[/] Traversal: nenhum detectado")
            except Exception as e:
                _p(f"[dim]Traversal: {e}[/]")

        # ── 8. SSRF ───────────────────────────────────────────────────────────
        if "ssrf" in executar:
            _p("[yellow]◉ SSRF[/] Testando Server-Side Request Forgery...")
            try:
                from modulos import ScannerSSRF
                scanner = ScannerSSRF()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["ssrf"] = vulns
                if vulns:
                    _p(f"[red]⚡ SSRF: {len(vulns)} encontrado(s)![/]")
                else:
                    _p("[green]✓[/] SSRF: nenhum detectado")
            except Exception as e:
                _p(f"[dim]SSRF: {e}[/]")

        # ── 9. CMD Injection ──────────────────────────────────────────────────
        if "cmd" in executar:
            _p("[yellow]◉ CMD[/] Testando Command Injection...")
            try:
                from modulos import ScannerInjecaoCmd
                scanner = ScannerInjecaoCmd()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["cmd"] = vulns
                if vulns:
                    _p(f"[red]⚡ CMD: {len(vulns)} encontrado(s)![/]")
                else:
                    _p("[green]✓[/] CMD: nenhum detectado")
            except Exception as e:
                _p(f"[dim]CMD: {e}[/]")

        # ── 10. Auth Bypass ───────────────────────────────────────────────────
        if "auth" in executar:
            _p("[yellow]◉ AUTH[/] Testando bypass de autenticação...")
            try:
                from modulos import ScannerBypassAuth
                scanner = ScannerBypassAuth()
                vulns = scanner.escanear(url, verboso=False)
                resultados_totais["auth"] = vulns
                if vulns:
                    _p(f"[red]⚡ Auth Bypass: {len(vulns)} encontrado(s)![/]")
                else:
                    _p("[green]✓[/] Auth Bypass: nenhum detectado")
            except Exception as e:
                _p(f"[dim]Auth: {e}[/]")

        # ── Totais ────────────────────────────────────────────────────────────
        fim = datetime.now()
        resultados_totais["fim"] = fim.isoformat()
        resultados_totais["duracao_s"] = (fim - inicio).total_seconds()
        total_vulns = sum(
            len(resultados_totais[k])
            for k in ("sqli", "xss", "lfi", "traversal", "ssrf", "cmd", "auth", "arquivos_sensiveis")
        )
        resultados_totais["vulnerabilidades_totais"] = total_vulns

        if not prefixo:
            self._exibir_resumo(resultados_totais)

        self._salvar_relatorio(resultados_totais)
        return resultados_totais

    # ─────────────────────── RANGE DE SITES ──────────────────────────────────

    def escanear_range(self, alvos: List[str], modulos: Optional[List[str]] = None,
                       threads: int = 3) -> List[dict]:
        """
        Escaneia lista de sites em paralelo com output sequencial prefixado.
        [Site 1/3] WAF: Cloudflare
        [Site 2/3] ✓ SQLi: nenhuma
        """
        total = len(alvos)
        console.print(Panel(
            f"[bold red]◉ RANGE SCAN[/]  →  [cyan]{total} alvos[/]  "
            f"[dim]({threads} threads simultâneas)[/]",
            box=box.DOUBLE_EDGE, border_style="red",
        ))

        # Fila de input para perguntas das threads
        fila_input: queue.Queue = queue.Queue()
        relatorios: list[dict] = [{}] * total

        def scan_um(idx: int, url: str) -> dict:
            n = idx + 1
            prefix = _prefixo(n, total)
            _print_site(n, total, f"[dim]Iniciando scan em[/] [cyan]{url}[/]")
            try:
                scanner = ScannerCompleto(verboso=False)
                resultado = scanner.escanear_site(url, modulos=modulos, prefixo=prefix)
                vulns = resultado.get("vulnerabilidades_totais", 0)
                cor = "red" if vulns > 0 else "green"
                _print_site(n, total,
                            f"[{cor}]✓ Concluído:[/] {vulns} vuln(s) | "
                            f"{resultado.get('duracao_s', 0):.0f}s")
                return resultado
            except Exception as e:
                _print_site(n, total, f"[red]✗ Erro:[/] {e}")
                return {"alvo": url, "erro": str(e), "vulnerabilidades_totais": 0}

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_um, i, a): i for i, a in enumerate(alvos)}
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    relatorios[idx] = fut.result()
                except Exception as e:
                    relatorios[idx] = {"alvo": alvos[idx], "erro": str(e)}

        self._exibir_resumo_range(relatorios)
        return relatorios

    # ─────────────────────── CARREGAR ALVOS ──────────────────────────────────

    def carregar_alvos_arquivo(self, caminho: str) -> List[str]:
        """Carrega lista de URLs de um arquivo .txt (um por linha)."""
        try:
            p = Path(caminho)
            if not p.exists():
                console.print(f"[red]Arquivo não encontrado:[/] {caminho}")
                return []
            conteudo = p.read_text(encoding="utf-8", errors="replace")
            linhas = [l.strip() for l in conteudo.splitlines()]
            return [self._normalizar_url(l) for l in linhas if l and not l.startswith("#")]
        except OSError as e:
            console.print(f"[red]Erro ao abrir arquivo:[/] {e}")
            return []

    def carregar_alvos_range_ip(self, range_ip: str, porta: int = 80) -> List[str]:
        """
        Converte range de IP em lista de URLs com validação completa.
        Suporta CIDR (192.168.1.0/24) e range com traço (192.168.1.1-254).
        Limite: máximo 512 IPs por range.
        """
        range_ip = range_ip.strip()
        alvos = []
        LIMITE = 512

        try:
            if "/" in range_ip:
                # Notação CIDR
                rede = ipaddress.ip_network(range_ip, strict=False)
                hosts = list(rede.hosts())
                if len(hosts) > LIMITE:
                    console.print(
                        f"[yellow]⚠  Range CIDR tem {len(hosts)} hosts — limitando a {LIMITE}.[/]"
                    )
                    hosts = hosts[:LIMITE]
                for ip in hosts:
                    alvos.append(f"http://{ip}:{porta}" if porta != 80 else f"http://{ip}")

            elif "-" in range_ip:
                # Range com traço: 192.168.1.1-254
                partes = range_ip.rsplit("-", 1)
                if len(partes) != 2:
                    console.print(f"[red]Formato inválido:[/] use 192.168.1.1-254")
                    return []

                base_str, fim_str = partes[0].strip(), partes[1].strip()

                # Validar que fim é número
                if not fim_str.isdigit():
                    console.print(f"[red]Octeto final inválido:[/] '{fim_str}' não é número")
                    return []

                fim_octeto = int(fim_str)
                if fim_octeto < 0 or fim_octeto > 255:
                    console.print(f"[red]Octeto final fora de range:[/] deve ser 0-255")
                    return []

                # Validar base IP
                partes_base = base_str.split(".")
                if len(partes_base) != 4:
                    console.print(f"[red]IP base inválido:[/] use formato 192.168.1.1")
                    return []

                try:
                    for octeto in partes_base:
                        v = int(octeto)
                        if v < 0 or v > 255:
                            raise ValueError(f"Octeto {octeto} fora de range (0-255)")
                except ValueError as e:
                    console.print(f"[red]IP inválido:[/] {e}")
                    return []

                inicio_octeto = int(partes_base[3])
                prefixo = ".".join(partes_base[:3])

                if fim_octeto < inicio_octeto:
                    console.print(
                        f"[yellow]⚠  Octeto final ({fim_octeto}) < inicial ({inicio_octeto}).[/]"
                    )
                    return []

                count = fim_octeto - inicio_octeto + 1
                if count > LIMITE:
                    console.print(
                        f"[yellow]⚠  Range tem {count} IPs — limitando a {LIMITE}.[/]"
                    )
                    fim_octeto = inicio_octeto + LIMITE - 1

                for i in range(inicio_octeto, fim_octeto + 1):
                    url = f"http://{prefixo}.{i}:{porta}" if porta != 80 else f"http://{prefixo}.{i}"
                    alvos.append(url)

            else:
                # IP único
                try:
                    ipaddress.ip_address(range_ip)
                    alvos.append(f"http://{range_ip}:{porta}" if porta != 80 else f"http://{range_ip}")
                except ValueError:
                    console.print(f"[red]IP inválido:[/] {range_ip}")
                    return []

        except ValueError as e:
            console.print(f"[red]Range inválido:[/] {e}")
        except Exception as e:
            console.print(f"[red]Erro ao processar range:[/] {e}")

        return alvos

    # ─────────────────────── HELPERS ─────────────────────────────────────────

    def _normalizar_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")

    def _exibir_resumo(self, r: dict) -> None:
        total = r.get("vulnerabilidades_totais", 0)
        duracao = r.get("duracao_s", 0)
        cor = "red" if total > 0 else "green"
        linhas = [
            f"[bold]Alvo:[/]        {r['alvo']}",
            f"[bold]Duração:[/]     {duracao:.1f}s",
            f"[bold]WAF:[/]         {', '.join(r['waf']) if r['waf'] else 'Não detectado'}",
            f"[bold]Tecnologias:[/] {', '.join(r['tecnologias']) if r['tecnologias'] else '—'}",
            f"[bold]Subdominios:[/] {len(r['subdominios'])} encontrados",
            f"[bold]Diretórios:[/]  {len(r['diretorios'])} acessíveis",
            "",
        ]
        for nome, chave in [
            ("SQL Injection", "sqli"), ("XSS", "xss"), ("LFI", "lfi"),
            ("Traversal", "traversal"), ("SSRF", "ssrf"), ("CMD", "cmd"),
            ("Auth Bypass", "auth"), ("Arq. Sensíveis", "arquivos_sensiveis"),
        ]:
            cnt = len(r.get(chave, []))
            if cnt:
                linhas.append(f"  [red]⚡ {nome}:[/] {cnt} vulnerabilidade(s)")
        linhas.append("")
        linhas.append(f"[bold {cor}]TOTAL: {total} vulnerabilidade(s)[/]")
        console.print()
        console.print(Panel(
            "\n".join(linhas), title="[bold]RESUMO DO SCAN[/]",
            box=box.DOUBLE_EDGE, border_style=cor,
        ))

    def _exibir_resumo_range(self, relatorios: list) -> None:
        console.print()
        tabela = Table(
            title=f"Resumo Range Scan ({len(relatorios)} alvos)",
            box=box.ROUNDED, border_style="cyan",
        )
        tabela.add_column("#", style="dim", justify="right", width=4)
        tabela.add_column("Alvo", style="cyan")
        tabela.add_column("SQLi", style="red", justify="right")
        tabela.add_column("XSS", style="red", justify="right")
        tabela.add_column("LFI", style="red", justify="right")
        tabela.add_column("CMD", style="red", justify="right")
        tabela.add_column("Total", style="bold", justify="right")
        tabela.add_column("Status")

        for i, r in enumerate(relatorios, 1):
            if not r or "erro" in r:
                err = (r or {}).get("erro", "desconhecido")
                tabela.add_row(
                    str(i), (r or {}).get("alvo", "?"),
                    "—", "—", "—", "—", "—",
                    f"[red]ERRO: {str(err)[:30]}[/]"
                )
                continue
            total = r.get("vulnerabilidades_totais", 0)
            cor = "red" if total > 0 else "green"
            tabela.add_row(
                str(i), r.get("alvo", "?"),
                str(len(r.get("sqli", []))), str(len(r.get("xss", []))),
                str(len(r.get("lfi", []))), str(len(r.get("cmd", []))),
                f"[{cor}]{total}[/{cor}]",
                "[green]OK[/]" if total == 0 else f"[red]⚡ {total} vuln(s)[/]",
            )
        console.print(tabela)

    def _salvar_relatorio(self, r: dict) -> Optional[str]:
        try:
            import json
            dir_rel = Path("relatorios")
            dir_rel.mkdir(exist_ok=True)
            alvo_slug = (r.get("alvo", "alvo")
                         .replace("http://", "").replace("https://", "")
                         .replace("/", "_"))[:40]
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome = dir_rel / f"{alvo_slug}_{ts}_completo.json"

            def _ser(obj):
                if hasattr(obj, "__dict__"):
                    return obj.__dict__
                return str(obj)

            nome.write_text(
                json.dumps(r, indent=2, ensure_ascii=False, default=_ser),
                encoding="utf-8",
            )
            if self.verboso:
                console.print(f"\n  [dim]Relatório salvo:[/] {nome}")
            return str(nome)
        except Exception:
            return None
