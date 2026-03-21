"""
Logger do Vlad Volkov — logging para VPS (arquivo + terminal).
Funciona tanto em modo interativo quanto headless (sem TTY).
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from rich.logging import RichHandler
from rich.console import Console

# Diretório de logs
DIR_LOGS = Path("logs")
DIR_LOGS.mkdir(exist_ok=True)

_logger_global = None


def configurar_logger(nivel: str = "INFO", silencioso: bool = False) -> logging.Logger:
    """
    Configura o logger do Vlad Volkov.

    Args:
        nivel: Nível de log (DEBUG, INFO, WARNING, ERROR)
        silencioso: Se True, não exibe no terminal (modo VPS headless)
    """
    global _logger_global

    logger = logging.getLogger("vlad")
    logger.setLevel(getattr(logging, nivel.upper(), logging.INFO))

    # Limpar handlers existentes
    logger.handlers.clear()

    # Handler para arquivo (sempre ativo, mesmo em VPS)
    nome_arquivo = DIR_LOGS / f"vlad_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    handler_arquivo = logging.FileHandler(nome_arquivo, encoding="utf-8")
    handler_arquivo.setLevel(logging.DEBUG)
    formato_arquivo = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler_arquivo.setFormatter(formato_arquivo)
    logger.addHandler(handler_arquivo)

    # Handler para terminal (apenas se não silencioso)
    if not silencioso:
        console = Console(stderr=False)
        handler_terminal = RichHandler(
            console=console,
            show_time=False,
            show_level=False,
            show_path=False,
            markup=True,
            rich_tracebacks=True
        )
        handler_terminal.setLevel(logging.INFO)
        logger.addHandler(handler_terminal)

    _logger_global = logger
    return logger


def obter_logger() -> logging.Logger:
    """Retorna o logger configurado, ou cria um padrão."""
    global _logger_global
    if _logger_global is None:
        return configurar_logger()
    return _logger_global
