# core/atualizador.py
# Vlad Volkov — Atualizador Automático via Git
# Verifica e baixa atualizações do repositório remoto

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

# Diretório raiz do projeto (pai de core/)
PROJETO_DIR = Path(__file__).parent.parent


class Atualizador:
    """
    Gerencia atualizações automáticas do Vlad Volkov via git pull.

    Fluxo:
    1. verificar_atualizacao() → fetch silencioso, compara hashes
    2. Se há commits novos → exibe preview do changelog
    3. atualizar() → git pull origin <branch_atual>
    4. Informa o usuário para reiniciar o framework
    """

    def __init__(self) -> None:
        self.dir_projeto = PROJETO_DIR

    def _git(self, *args: str, timeout: int = 30) -> subprocess.CompletedProcess:
        """Executa comando git no diretório do projeto (sem shell=True)."""
        try:
            return subprocess.run(
                ["git"] + list(args),
                cwd=str(self.dir_projeto),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise
        except FileNotFoundError:
            raise FileNotFoundError("git não encontrado no sistema")

    def verificar_atualizacao(self) -> dict:
        """
        Verifica se há atualizações disponíveis sem baixar nada.

        Retorna dict com:
        - ok: bool — operação funcionou
        - atualizado: bool — está na versão mais recente
        - commits_novos: int
        - branch: str
        - preview: str — resumo das mudanças
        - erro: str — mensagem de erro se ok=False
        """
        try:
            # Obter branch atual
            r = self._git("rev-parse", "--abbrev-ref", "HEAD")
            branch = r.stdout.strip() if r.returncode == 0 else "main"
            if not branch or branch == "HEAD":
                branch = "main"

            # Fetch silencioso (só atualiza refs remotas)
            fetch = self._git("fetch", "origin", branch, timeout=20)
            if fetch.returncode != 0:
                return {
                    "ok": False,
                    "atualizado": True,
                    "erro": "Sem conexão com repositório remoto",
                    "branch": branch,
                }

            # Comparar hash local com remoto
            local = self._git("rev-parse", "HEAD")
            remoto = self._git("rev-parse", f"origin/{branch}")

            hash_local = local.stdout.strip() if local.returncode == 0 else ""
            hash_remoto = remoto.stdout.strip() if remoto.returncode == 0 else ""

            if not hash_local or not hash_remoto:
                return {
                    "ok": False,
                    "atualizado": True,
                    "erro": "Não foi possível comparar versões",
                    "branch": branch,
                }

            if hash_local == hash_remoto:
                return {
                    "ok": True,
                    "atualizado": True,
                    "commits_novos": 0,
                    "branch": branch,
                    "preview": "",
                    "hash": hash_local[:8],
                }

            # Há atualizações — obter changelog
            log = self._git("log", "--oneline", f"HEAD..origin/{branch}")
            linhas = [l.strip() for l in log.stdout.strip().splitlines() if l.strip()]

            return {
                "ok": True,
                "atualizado": False,
                "commits_novos": len(linhas),
                "branch": branch,
                "preview": "\n".join(linhas[:8]),
                "hash_local": hash_local[:8],
                "hash_remoto": hash_remoto[:8],
            }

        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "atualizado": True,
                "erro": "Timeout ao verificar atualizações (sem internet?)",
                "branch": "?",
            }
        except FileNotFoundError:
            return {
                "ok": False,
                "atualizado": True,
                "erro": "git não encontrado — não é possível verificar atualizações",
                "branch": "?",
            }
        except Exception as e:
            return {
                "ok": False,
                "atualizado": True,
                "erro": str(e),
                "branch": "?",
            }

    def atualizar(self) -> bool:
        """
        Executa git pull para baixar e aplicar atualizações.
        Retorna True se bem-sucedido.
        """
        try:
            r = self._git("rev-parse", "--abbrev-ref", "HEAD")
            branch = r.stdout.strip() if r.returncode == 0 else "main"
            if not branch or branch == "HEAD":
                branch = "main"

            console.print(f"  [dim]Executando: git pull origin {branch}[/]")
            resultado = self._git("pull", "origin", branch, timeout=90)

            if resultado.returncode == 0:
                saida = resultado.stdout.strip()
                if "Already up to date" in saida or "Já está atualizado" in saida:
                    console.print("  [green]✓ Já está na versão mais recente.[/]")
                else:
                    console.print(f"  [bold green]✓ Atualizado com sucesso![/]")
                    if saida:
                        console.print(f"  [dim]{saida[:300]}[/]")
                return True
            else:
                err = resultado.stderr.strip()
                console.print(f"  [red]✗ Falha ao atualizar:[/] {err[:200]}")
                if "conflict" in err.lower():
                    console.print(
                        "  [yellow]⚠  Há conflitos locais. Resolva manualmente com:[/]\n"
                        "     git stash && git pull && git stash pop"
                    )
                return False

        except subprocess.TimeoutExpired:
            console.print("  [red]✗ Timeout ao baixar atualização.[/]")
            return False
        except FileNotFoundError:
            console.print("  [red]✗ git não encontrado no sistema.[/]")
            return False
        except Exception as e:
            console.print(f"  [red]✗ Erro:[/] {e}")
            return False

    def obter_versao_local(self) -> str:
        """Retorna hash curto do commit atual."""
        try:
            r = self._git("rev-parse", "--short", "HEAD")
            return r.stdout.strip() if r.returncode == 0 else "desconhecido"
        except Exception:
            return "desconhecido"

    def exibir_status(self) -> None:
        """Exibe painel de status de atualização."""
        with console.status("[dim]Verificando atualizações...[/]"):
            info = self.verificar_atualizacao()

        if not info["ok"]:
            console.print(Panel(
                f"[yellow]⚠  {info.get('erro', 'Erro desconhecido')}[/]",
                title="Atualização",
                border_style="yellow",
                box=box.ROUNDED,
            ))
            return

        if info["atualizado"]:
            console.print(Panel(
                f"[green]✓ Você está na versão mais recente[/]\n"
                f"[dim]Branch: {info.get('branch', '?')} | "
                f"Hash: {info.get('hash', '?')}[/]",
                title="Atualização",
                border_style="green",
                box=box.ROUNDED,
            ))
        else:
            n = info.get("commits_novos", 0)
            preview = info.get("preview", "")
            conteudo = (
                f"[yellow]⬆  {n} atualização(ões) disponível(eis)[/]\n"
                f"[dim]Branch: {info.get('branch', '?')} | "
                f"Local: {info.get('hash_local', '?')} → "
                f"Remoto: {info.get('hash_remoto', '?')}[/]\n"
            )
            if preview:
                conteudo += f"\n[dim]Mudanças:\n{preview}[/]"

            console.print(Panel(
                conteudo,
                title="Atualização Disponível",
                border_style="cyan",
                box=box.ROUNDED,
            ))
