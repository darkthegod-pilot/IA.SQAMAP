# core/agente_ia.py
# Vlad Volkov — Agente IA via OpenAI GPT
# API key configurada via menu [9] ou ~/.vlad/config.json (NUNCA hardcoded)

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

console = Console()

VLAD_CONFIG_DIR = Path.home() / ".vlad"
VLAD_CONFIG_FILE = VLAD_CONFIG_DIR / "config.json"

SYSTEM_PROMPT_BASE = """Você é Vlad Volkov, um pentester web especialista com profundo conhecimento
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
        self._base_conhecimento = None  # injetada externamente via set_conhecimento()
        self._alvo_atual: str = ""
        self._carregar_configuracao()

    def set_conhecimento(self, base) -> None:
        """Injeta a base de conhecimento para enriquecer o contexto do GPT."""
        self._base_conhecimento = base

    def set_alvo(self, alvo: str) -> None:
        """Define o alvo atual para contextualizar o conhecimento."""
        self._alvo_atual = alvo

    def _obter_system_prompt(self) -> str:
        """Monta system prompt com base de conhecimento injetada."""
        prompt = SYSTEM_PROMPT_BASE
        if self._base_conhecimento is not None:
            try:
                ctx = self._base_conhecimento.obter_contexto_para_ia(self._alvo_atual)
                if ctx:
                    prompt += f"\n\n{ctx}"
            except Exception:
                pass
        return prompt

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
        """Envia mensagem ao GPT e retorna a resposta. Retry 2x em caso de falha de rede."""
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

        # Salvar na base de conhecimento se disponível
        if self._base_conhecimento is not None:
            try:
                self._base_conhecimento.adicionar_contexto_chat("user", mensagem[:400])
            except Exception:
                pass

        system_prompt = self._obter_system_prompt()

        # Retry até 2x para erros de rede/timeout
        ultima_excecao: Optional[Exception] = None
        for tentativa in range(3):
            try:
                resposta = self._client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "system", "content": system_prompt}] + self._historico,
                    temperature=0.3,
                    max_tokens=900,
                    timeout=30,
                )
                texto = resposta.choices[0].message.content or ""
                self._historico.append({"role": "assistant", "content": texto})

                # Salvar resposta na base de conhecimento
                if self._base_conhecimento is not None:
                    try:
                        self._base_conhecimento.adicionar_contexto_chat("assistant", texto[:400])
                    except Exception:
                        pass

                return texto

            except Exception as e:
                ultima_excecao = e
                tipo = type(e).__name__
                # Não fazer retry em erros de autenticação (401) ou quota (429)
                if any(k in tipo.lower() for k in ("auth", "apikey", "permission")):
                    break
                if "401" in str(e) or "403" in str(e) or "invalid_api_key" in str(e).lower():
                    break
                if tentativa < 2:
                    time.sleep(2 ** tentativa)  # backoff: 1s, 2s

        # Remover a mensagem do usuário do histórico após falha
        if self._historico and self._historico[-1]["role"] == "user":
            self._historico.pop()

        err_msg = str(ultima_excecao) if ultima_excecao else "erro desconhecido"
        if "api_key" in err_msg.lower() or "401" in err_msg:
            return "[IA] API key inválida ou expirada. Reconfigure em menu [9] → [1]."
        if "quota" in err_msg.lower() or "429" in err_msg:
            return "[IA] Limite de requisições atingido. Aguarde alguns instantes."
        if "connect" in err_msg.lower() or "timeout" in err_msg.lower():
            return "[IA] Sem conexão com o GPT. Verifique sua internet."
        return f"[IA] Erro ao contactar GPT: {err_msg[:120]}"

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
