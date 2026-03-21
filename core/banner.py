"""
Banner do Vlad Volkov — exibido na inicialização do sistema.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
import sys

console = Console()

VERSAO = "2.0.0"

ASCII_ART = r"""
 __   ____      _     ____    __   ____  __     ___   _  _
 \ \ / /  \\   / \   |    \   \ \ / /  \/  |   / _ \ | \| |
  \ V /| |) | / _ \  | |) | (_) V /| |\/| |  | (_) || .` |
   \_/ |___/ /_/ \_\ |___/      \_/ |_|  |_|   \___/ |_|\_|
"""

def exibir_banner(silencioso: bool = False) -> None:
    """Exibe o banner do Vlad Volkov no terminal."""
    if silencioso:
        return

    console.print()

    # Arte ASCII em vermelho
    texto_arte = Text(ASCII_ART, style="bold red")
    console.print(Align.center(texto_arte))

    # Painel de informações
    info = Text()
    info.append("  VLAD VOLKOV", style="bold red")
    info.append(" — Pentester Web Especialista\n", style="bold white")
    info.append("  Especialidade: ", style="dim white")
    info.append("SQLMap Automatizado + Testes Web Completos\n", style="bold cyan")
    info.append("  Versão: ", style="dim white")
    info.append(f"{VERSAO}", style="bold yellow")
    info.append("  |  Deploy: ", style="dim white")
    info.append("VPS-Ready\n", style="bold green")
    info.append("  ⚠  Somente para uso autorizado e legal.", style="bold yellow")

    console.print(
        Panel(info, border_style="red", box=box.DOUBLE_EDGE, padding=(0, 2)),
        justify="center"
    )
    console.print()


def exibir_aviso_legal() -> None:
    """Exibe aviso legal antes de operações sensíveis."""
    aviso = Text()
    aviso.append("AVISO LEGAL\n", style="bold red")
    aviso.append(
        "Este software é destinado EXCLUSIVAMENTE para testes autorizados.\n"
        "O uso não autorizado é ilegal e antiético.\n"
        "Certifique-se de ter autorização escrita antes de prosseguir.",
        style="yellow"
    )
    console.print(Panel(aviso, border_style="yellow", box=box.ROUNDED))
    console.print()


def exibir_versao() -> None:
    """Exibe apenas a versão do sistema."""
    console.print(f"[bold red]Vlad Volkov[/bold red] v{VERSAO}")


if __name__ == "__main__":
    exibir_banner()
