# core/modo_furtivo.py
# Vlad Volkov — Modo Furtivo / Sistema de Anonimato
# UA rotation, detecção de bloqueio, delays adaptativos, proxy opcional
# Sem dependência de API externa — tudo local

from __future__ import annotations

import random
import time
from typing import Optional

import requests

from rich.console import Console

console = Console()

# ─────────────────────────── USER-AGENTS ─────────────────────────────────────

USER_AGENTS: list[str] = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    # Mobile Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    # Mobile Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    # Chrome Windows antigo (parece legítimo)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    # Firefox mais antigo
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",
    # Vivaldi
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Vivaldi/6.5.3206.63",
    # Chrome ARM macOS (M1/M2)
    "Mozilla/5.0 (Macintosh; ARM Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Tablet Android
    "Mozilla/5.0 (Linux; Android 13; SM-T870) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # iPad
    "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    # Windows Firefox com locale específico
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:120.0) Gecko/20100101 Firefox/120.0",
]

ACCEPT_LANGUAGES: list[str] = [
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "pt-BR,pt;q=0.9",
    "es-ES,es;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.7",
    "en-US,en;q=0.5",
    "pt-PT,pt;q=0.9,en;q=0.8",
]

# Palavras-chave que indicam bloqueio no body
PALAVRAS_BLOQUEIO: list[str] = [
    "blocked", "access denied", "access forbidden", "unusual traffic",
    "bot protection", "security check", "cloudflare", "captcha",
    "ddos protection", "bot detected", "suspicious activity",
    "challenge page", "please verify", "are you human", "your ip",
    "firewall", "waf blocked", "banned", "forbidden",
]


class ModoFurtivo:
    """
    Sistema de anonimato/stealth para o Vlad Volkov.

    Funcionalidades:
    - Rotação de 40+ User-Agents reais (Chrome, Firefox, Safari, Edge, Mobile)
    - Detecção de bloqueio por HTTP status + análise do body
    - Delays adaptativos (normal: 0-0.5s | furtivo: 3-15s)
    - Backoff exponencial após bloqueios consecutivos
    - Proxy opcional (configurado pelo usuário — nunca forçado)
    - Headers completos para parecer browser real

    Política: pergunta ao usuário antes de ativar. Não usa API externa.
    """

    def __init__(self, proxy: Optional[str] = None) -> None:
        self.proxy = proxy
        self.ativo: bool = False
        self._contagem_bloqueios: int = 0
        self._ultimo_ua: str = ""
        self._backoff_nivel: int = 0
        self._delay_min: float = 0.0
        self._delay_max: float = 0.3

    # ─────────────────────────── ATIVAR / DESATIVAR ───────────────────────────

    def ativar(self) -> None:
        """Ativa modo furtivo: delays maiores, rotação de UA a cada request."""
        self.ativo = True
        self._delay_min = 3.0
        self._delay_max = 15.0
        self._backoff_nivel = 0
        console.print("  [bold yellow]⚠  MODO FURTIVO ATIVADO[/] — delays 3-15s, UA rotacionando")

    def desativar(self) -> None:
        """Desativa modo furtivo e volta ao comportamento normal."""
        self.ativo = False
        self._delay_min = 0.0
        self._delay_max = 0.3
        self._contagem_bloqueios = 0
        self._backoff_nivel = 0
        console.print("  [dim]Modo furtivo desativado.[/]")

    # ─────────────────────────── USER-AGENT ──────────────────────────────────

    def obter_ua(self) -> str:
        """Retorna UA aleatório, diferente do anterior."""
        ua = random.choice(USER_AGENTS)
        for _ in range(8):
            if ua != self._ultimo_ua:
                break
            ua = random.choice(USER_AGENTS)
        self._ultimo_ua = ua
        return ua

    def obter_headers_completos(self) -> dict:
        """Retorna conjunto de headers realistas para parecer browser legítimo."""
        ua = self.obter_ua()
        is_mobile = "Mobile" in ua or "Android" in ua or "iPhone" in ua or "iPad" in ua
        return {
            "User-Agent": ua,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            **({"Viewport-Width": "375"} if is_mobile else {}),
        }

    # ─────────────────────────── DETECÇÃO DE BLOQUEIO ────────────────────────

    def registrar_resposta(self, status_code: int, body: str = "") -> bool:
        """
        Registra resposta e detecta se é bloqueio.
        Retorna True se parece bloqueio.
        """
        bloqueado = self._eh_bloqueio(status_code, body)
        if bloqueado:
            self._contagem_bloqueios += 1
        else:
            # Reset progressivo em respostas normais
            if self._contagem_bloqueios > 0:
                self._contagem_bloqueios = max(0, self._contagem_bloqueios - 1)
        return bloqueado

    def _eh_bloqueio(self, status_code: int, body: str = "") -> bool:
        """Detecta se a resposta HTTP indica bloqueio ativo."""
        if status_code == 429:
            return True
        if status_code == 0:
            # Timeout ou conexão recusada reiterada pode indicar ban de IP
            return False
        body_lower = body[:600].lower() if body else ""
        if status_code in (503, 403, 406, 451):
            if any(p in body_lower for p in PALAVRAS_BLOQUEIO):
                return True
        return False

    def esta_sendo_bloqueado(self) -> bool:
        """Retorna True se houve 2+ bloqueios consecutivos."""
        return self._contagem_bloqueios >= 2

    # ─────────────────────────── DELAYS ──────────────────────────────────────

    def aguardar(self) -> None:
        """Aguarda delay adaptativo. Em modo furtivo, adiciona variação aleatória."""
        if self._delay_max <= 0:
            return
        base = random.uniform(self._delay_min, self._delay_max)
        if self.ativo and self._backoff_nivel > 0:
            backoff = min(2 ** self._backoff_nivel, 30)
            base += random.uniform(0, backoff)
        if base > 0:
            time.sleep(base)

    def aguardar_backoff(self) -> None:
        """Backoff exponencial após bloqueio detectado: 2→4→8→16→32s."""
        if self._backoff_nivel < 5:
            self._backoff_nivel += 1
        espera = min(2 ** self._backoff_nivel, 32)
        jitter = random.uniform(0, espera * 0.3)
        time.sleep(espera + jitter)

    def reset_backoff(self) -> None:
        """Reduz gradualmente o backoff após sucesso."""
        if self._backoff_nivel > 0:
            self._backoff_nivel -= 1

    # ─────────────────────────── SESSÃO HTTP ─────────────────────────────────

    def criar_sessao(self, verificar_ssl: bool = True) -> requests.Session:
        """
        Cria sessão requests com headers furtivos.
        Proxy é aplicado SOMENTE se o usuário configurou um.
        SSL é verificado por padrão (seguro).
        """
        sessao = requests.Session()
        sessao.headers.update(self.obter_headers_completos())
        sessao.verify = verificar_ssl

        if self.proxy:
            sessao.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }
        return sessao

    def atualizar_sessao(self, sessao: requests.Session) -> None:
        """Atualiza o UA e headers de uma sessão existente (rotação mid-scan)."""
        novos = self.obter_headers_completos()
        for k, v in novos.items():
            sessao.headers[k] = v

    # ─────────────────────────── STATUS ──────────────────────────────────────

    def status(self) -> dict:
        """Retorna estado atual do modo furtivo."""
        return {
            "ativo": self.ativo,
            "proxy": self.proxy or "não configurado",
            "backoff_nivel": self._backoff_nivel,
            "bloqueios_detectados": self._contagem_bloqueios,
            "delay_range": f"{self._delay_min:.1f}–{self._delay_max:.1f}s",
        }
