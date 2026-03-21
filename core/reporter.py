"""
Gerador de relatórios do Vlad Volkov — PT-BR, com rich output.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

DIR_RELATORIOS = Path("relatorios")
DIR_RELATORIOS.mkdir(exist_ok=True)


NIVEIS_SEVERIDADE = {
    "critico": ("bold white on red", "🔴 CRÍTICO"),
    "alto": ("bold red", "🟠 ALTO"),
    "medio": ("bold yellow", "🟡 MÉDIO"),
    "baixo": ("bold green", "🟢 BAIXO"),
    "informativo": ("bold blue", "🔵 INFO"),
}


@dataclass
class Vulnerabilidade:
    tipo: str
    severidade: str
    parametro: str
    descricao: str
    evidencia: str = ""
    recomendacao: str = ""


@dataclass
class Relatorio:
    alvo: str
    inicio: datetime = field(default_factory=datetime.now)
    fim: Optional[datetime] = None
    vulnerabilidades: List[Vulnerabilidade] = field(default_factory=list)
    dbms: Optional[str] = None
    sistema_op: Optional[str] = None
    tecnologia_web: Optional[str] = None
    waf_detectado: Optional[str] = None
    usuario_db: Optional[str] = None
    eh_dba: bool = False
    bancos_encontrados: List[str] = field(default_factory=list)
    credenciais_extraidas: int = 0
    notas: List[str] = field(default_factory=list)

    def adicionar_vuln(self, tipo: str, severidade: str, parametro: str,
                        descricao: str, evidencia: str = "", recomendacao: str = "") -> None:
        """Adiciona uma vulnerabilidade ao relatório."""
        self.vulnerabilidades.append(Vulnerabilidade(
            tipo=tipo,
            severidade=severidade,
            parametro=parametro,
            descricao=descricao,
            evidencia=evidencia,
            recomendacao=recomendacao
        ))

    def duracao_formatada(self) -> str:
        """Retorna duração do teste formatada."""
        fim = self.fim or datetime.now()
        delta = fim - self.inicio
        total = int(delta.total_seconds())
        minutos, segundos = divmod(total, 60)
        horas, minutos = divmod(minutos, 60)
        if horas:
            return f"{horas}h {minutos}m {segundos}s"
        if minutos:
            return f"{minutos}m {segundos}s"
        return f"{segundos}s"

    def severidade_maxima(self) -> str:
        """Retorna a severidade máxima encontrada."""
        ordem = ["critico", "alto", "medio", "baixo", "informativo"]
        sevs = [v.severidade.lower() for v in self.vulnerabilidades]
        for nivel in ordem:
            if nivel in sevs:
                return nivel
        return "nenhuma"

    def exibir_resumo_terminal(self) -> None:
        """Exibe resumo rico no terminal."""
        sev = self.severidade_maxima()
        estilo_sev, label_sev = NIVEIS_SEVERIDADE.get(sev, ("bold white", "⚪ NENHUMA"))

        # Painel principal
        titulo = Text("RELATÓRIO VLAD VOLKOV — SUMÁRIO", style="bold white")
        console.print()
        console.print(Panel(titulo, border_style="red", box=box.DOUBLE_EDGE))

        # Tabela de informações gerais
        tabela_info = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        tabela_info.add_column("Campo", style="bold cyan", width=22)
        tabela_info.add_column("Valor", style="white")

        alvo_exib = self.alvo[:60] + "..." if len(self.alvo) > 60 else self.alvo
        tabela_info.add_row("Alvo", alvo_exib)
        tabela_info.add_row("Duração", self.duracao_formatada())
        tabela_info.add_row("Severidade Máxima", Text(label_sev, style=estilo_sev))
        if self.waf_detectado:
            tabela_info.add_row("WAF Detectado", self.waf_detectado)
        if self.dbms:
            tabela_info.add_row("DBMS", self.dbms)
        if self.sistema_op:
            tabela_info.add_row("Sistema Operacional", self.sistema_op)
        if self.usuario_db:
            dba_txt = f"{self.usuario_db} [bold red](DBA)[/bold red]" if self.eh_dba else self.usuario_db
            tabela_info.add_row("Usuário do Banco", dba_txt)
        if self.bancos_encontrados:
            tabela_info.add_row("Bancos Encontrados", ", ".join(self.bancos_encontrados))
        if self.credenciais_extraidas > 0:
            tabela_info.add_row("Credenciais Extraídas", str(self.credenciais_extraidas))

        console.print(tabela_info)

        # Tabela de vulnerabilidades
        if self.vulnerabilidades:
            console.print()
            console.print("[bold red]VULNERABILIDADES ENCONTRADAS:[/bold red]")
            tabela_vulns = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            tabela_vulns.add_column("Tipo", width=28)
            tabela_vulns.add_column("Severidade", width=12)
            tabela_vulns.add_column("Parâmetro", width=20)
            tabela_vulns.add_column("Descrição", width=40)

            for v in self.vulnerabilidades:
                sev_style, sev_label = NIVEIS_SEVERIDADE.get(v.severidade.lower(), ("white", v.severidade))
                tabela_vulns.add_row(
                    f"[bold]{v.tipo}[/bold]",
                    Text(sev_label, style=sev_style),
                    f"[cyan]{v.parametro}[/cyan]",
                    v.descricao[:40]
                )

            console.print(tabela_vulns)
        else:
            console.print("\n[bold green]Nenhuma vulnerabilidade encontrada.[/bold green]")

        # Notas
        if self.notas:
            console.print("\n[bold yellow]NOTAS:[/bold yellow]")
            for nota in self.notas:
                console.print(f"  • {nota}")

    def salvar_json(self) -> Path:
        """Salva relatório em JSON."""
        nome = self._nome_arquivo("json")
        caminho = DIR_RELATORIOS / nome

        dados = {
            "alvo": self.alvo,
            "inicio": self.inicio.isoformat(),
            "fim": self.fim.isoformat() if self.fim else None,
            "duracao": self.duracao_formatada(),
            "severidade_maxima": self.severidade_maxima(),
            "waf": self.waf_detectado,
            "dbms": self.dbms,
            "sistema_operacional": self.sistema_op,
            "tecnologia_web": self.tecnologia_web,
            "usuario_db": self.usuario_db,
            "eh_dba": self.eh_dba,
            "bancos": self.bancos_encontrados,
            "credenciais_extraidas": self.credenciais_extraidas,
            "vulnerabilidades": [
                {
                    "tipo": v.tipo,
                    "severidade": v.severidade,
                    "parametro": v.parametro,
                    "descricao": v.descricao,
                    "evidencia": v.evidencia,
                    "recomendacao": v.recomendacao,
                }
                for v in self.vulnerabilidades
            ],
            "notas": self.notas,
        }

        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f, ensure_ascii=False, indent=2)

        return caminho

    def salvar_markdown(self) -> Path:
        """Salva relatório em Markdown."""
        nome = self._nome_arquivo("md")
        caminho = DIR_RELATORIOS / nome

        linhas = [
            f"# Relatório Vlad Volkov\n",
            f"**Alvo:** `{self.alvo}`  ",
            f"**Data:** {self.inicio.strftime('%d/%m/%Y %H:%M')}  ",
            f"**Duração:** {self.duracao_formatada()}  ",
            f"**Severidade Máxima:** {self.severidade_maxima().upper()}\n",
            "## Informações do Alvo\n",
        ]

        if self.waf_detectado:
            linhas.append(f"- **WAF:** {self.waf_detectado}")
        if self.dbms:
            linhas.append(f"- **DBMS:** {self.dbms}")
        if self.sistema_op:
            linhas.append(f"- **SO:** {self.sistema_op}")
        if self.usuario_db:
            dba = " *(DBA)*" if self.eh_dba else ""
            linhas.append(f"- **Usuário DB:** {self.usuario_db}{dba}")
        if self.bancos_encontrados:
            linhas.append(f"- **Bancos:** {', '.join(self.bancos_encontrados)}")

        linhas.append("\n## Vulnerabilidades\n")
        if self.vulnerabilidades:
            for v in self.vulnerabilidades:
                linhas.append(f"### {v.tipo}")
                linhas.append(f"- **Severidade:** {v.severidade.upper()}")
                linhas.append(f"- **Parâmetro:** `{v.parametro}`")
                linhas.append(f"- **Descrição:** {v.descricao}")
                if v.evidencia:
                    linhas.append(f"- **Evidência:** `{v.evidencia}`")
                if v.recomendacao:
                    linhas.append(f"- **Recomendação:** {v.recomendacao}")
                linhas.append("")
        else:
            linhas.append("Nenhuma vulnerabilidade encontrada.")

        with open(caminho, "w", encoding="utf-8") as f:
            f.write("\n".join(linhas))

        return caminho

    def _nome_arquivo(self, extensao: str) -> str:
        """Gera nome de arquivo baseado no alvo e timestamp."""
        alvo_limpo = self.alvo.replace("http://", "").replace("https://", "")
        alvo_limpo = alvo_limpo.split("/")[0].replace(".", "_").replace(":", "_")
        ts = self.inicio.strftime("%Y%m%d_%H%M%S")
        return f"vlad_{alvo_limpo}_{ts}.{extensao}"
