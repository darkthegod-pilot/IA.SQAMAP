# core/agente_ia.py
# Vlad Volkov — Agente IA via OpenAI GPT
# API key configurada via menu [9] ou ~/.vlad/config.json (NUNCA hardcoded)

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()

VLAD_CONFIG_DIR = Path.home() / ".vlad"
VLAD_CONFIG_FILE = VLAD_CONFIG_DIR / "config.json"

SYSTEM_PROMPT = """Você é Vlad Volkov, um pentester web especialista com profundo conhecimento
em SQL Injection, XSS, LFI, SSRF, Command Injection, evasão de WAF e automação de testes de segurança.
Você responde SEMPRE em português brasileiro.
Você é direto, técnico e eficiente. Não faz rodeios.

Quando o usuário descrever o que quer testar ou fazer, você sugere o comando exato:
  python vlad.py scan --alvo "URL" --modo profundo
  python framework.py --alvo "URL"

Quando receber dados de vulnerabilidades encontradas, você analisa e recomenda a melhor ação de exploração.
Você conhece profundamente o SQLMap, suas flags, técnicas (B, T, E, U, S, Q) e tampers para WAFs.
Seja como um parceiro técnico de pentest — objetivo, preciso, acionável.
"""


class AgenteIA:
    """Interface com o GPT para assistência de pentest em tempo real."""

    def __init__(self) -> None:
        self._api_key: Optional[str] = None
        self._client = None
        self._historico: list[dict] = []
        self._carregar_configuracao()

    # ─────────────────────────── CONFIG ──────────────────────────────────────

    def _carregar_configuracao(self) -> None:
        """Carrega API key: env var → ~/.vlad/config.json"""
        # Prioridade 1: variável de ambiente
        chave = os.environ.get("OPENAI_API_KEY", "").strip()
        if chave:
            self._api_key = chave
            self._inicializar_cliente()
            return

        # Prioridade 2: arquivo de configuração persistente
        if VLAD_CONFIG_FILE.exists():
            try:
                cfg = json.loads(VLAD_CONFIG_FILE.read_text())
                chave = cfg.get("openai_api_key", "").strip()
                if chave:
                    self._api_key = chave
                    self._inicializar_cliente()
            except (json.JSONDecodeError, OSError):
                pass

    def _inicializar_cliente(self) -> None:
        """Instancia o cliente OpenAI com a chave configurada."""
        try:
            from openai import OpenAI  # type: ignore
            self._client = OpenAI(api_key=self._api_key)
        except ImportError:
            self._client = None

    def configurar_chave(self, chave: str) -> bool:
        """Salva a API key em ~/.vlad/config.json e reinicializa o cliente."""
        chave = chave.strip()
        if not chave:
            return False

        try:
            VLAD_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            cfg: dict = {}
            if VLAD_CONFIG_FILE.exists():
                try:
                    cfg = json.loads(VLAD_CONFIG_FILE.read_text())
                except (json.JSONDecodeError, OSError):
                    cfg = {}
            cfg["openai_api_key"] = chave
            VLAD_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            self._api_key = chave
            self._inicializar_cliente()
            return True
        except OSError:
            return False

    def carregar_config_completa(self) -> dict:
        """Retorna toda a configuração salva."""
        if VLAD_CONFIG_FILE.exists():
            try:
                return json.loads(VLAD_CONFIG_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def salvar_config_completa(self, cfg: dict) -> bool:
        """Salva configuração completa em ~/.vlad/config.json."""
        try:
            VLAD_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            VLAD_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
            return True
        except OSError:
            return False

    # ─────────────────────────── STATUS ──────────────────────────────────────

    def disponivel(self) -> bool:
        """Retorna True se a API key está configurada e o cliente instanciado."""
        return bool(self._api_key and self._client)

    def chave_mascarada(self) -> str:
        """Retorna a chave parcialmente mascarada para exibição."""
        if not self._api_key:
            return "[não configurada]"
        k = self._api_key
        if len(k) <= 12:
            return k[:4] + "****"
        return k[:10] + "..." + k[-4:]

    # ─────────────────────────── CHAT ────────────────────────────────────────

    def chat(self, mensagem: str, contexto_scan: Optional[dict] = None) -> str:
        """Envia mensagem ao GPT e retorna a resposta."""
        if not self.disponivel():
            return (
                "[IA indisponível] Configure a API key via menu [9] Configurações.\n"
                "Você também pode exportar: export OPENAI_API_KEY=sk-proj-..."
            )

        # Injeta contexto do scan se fornecido
        user_content = mensagem
        if contexto_scan:
            ctx_str = json.dumps(contexto_scan, ensure_ascii=False, indent=2)
            user_content = f"[Contexto do último scan]\n{ctx_str}\n\n[Pergunta]\n{mensagem}"

        self._historico.append({"role": "user", "content": user_content})

        try:
            resposta = self._client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "system", "content": SYSTEM_PROMPT}] + self._historico,
                temperature=0.3,
                max_tokens=800,
            )
            texto = resposta.choices[0].message.content or ""
            self._historico.append({"role": "assistant", "content": texto})
            return texto
        except Exception as e:
            return f"[Erro ao contactar o GPT] {e}"

    def analisar_vulnerabilidades(self, relatorio_dict: dict) -> str:
        """Analisa o relatório de scan e recomenda ações."""
        prompt = (
            "Analisando o relatório de vulnerabilidades abaixo, liste em ordem de prioridade "
            "as 3 ações mais impactantes que posso executar agora, com os comandos exatos.\n\n"
            f"Relatório:\n{json.dumps(relatorio_dict, ensure_ascii=False, indent=2)}"
        )
        return self.chat(prompt)

    def sugerir_comando(self, intencao: str, contexto: Optional[dict] = None) -> str:
        """Traduz intenção em linguagem natural para um comando vlad.py."""
        prompt = (
            f"O usuário quer: '{intencao}'\n"
            "Retorne APENAS o comando exato para executar (python vlad.py ... ou python framework.py ...). "
            "Uma linha, sem markdown, sem explicação extra."
        )
        return self.chat(prompt, contexto_scan=contexto)

    def limpar_historico(self) -> None:
        """Limpa o histórico de conversa da sessão."""
        self._historico.clear()
