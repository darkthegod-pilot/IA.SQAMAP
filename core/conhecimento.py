# core/conhecimento.py
# Vlad Volkov — Base de Auto-Aprendizagem
# Persiste conhecimento de pentests em ~/.vlad/conhecimento.json
# Enriquece automaticamente o contexto GPT com o que já foi aprendido

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

CONHECIMENTO_DIR = Path.home() / ".vlad"
CONHECIMENTO_FILE = CONHECIMENTO_DIR / "conhecimento.json"

_ESTRUTURA: Dict[str, Any] = {
    "waf_tampers": {},            # {waf_key: [tampers]}
    "sqli_tecnicas": {},          # {dbms: [tecnicas]}
    "payloads_xss": {},           # {tecnologia: [payloads]}
    "subdominios_encontrados": {},# {dominio: [subs]}
    "tecnologias_vistas": {},     # {dominio: [techs]}
    "scans_historico": [],        # lista de dicts com resumo de cada scan
    "proxies_funcionaram": [],    # proxies que funcionaram
    "chat_contexto": [],          # últimas 20 mensagens (persistência entre sessões)
    "estatisticas": {
        "total_scans": 0,
        "total_vulns": 0,
    },
}


class BaseConhecimento:
    """
    Base de auto-aprendizagem do Vlad Volkov.

    Aprende automaticamente a partir dos resultados de cada scan:
    - Quais tampers funcionaram para quais WAFs
    - Quais técnicas SQLi funcionaram para quais DBMS
    - Quais payloads XSS funcionaram em quais tecnologias
    - Subdominios e tecnologias por domínio

    Uso na IA: obter_contexto_para_ia() injeta o conhecimento no system
    prompt do GPT para enriquecer recomendações automaticamente.
    """

    def __init__(self) -> None:
        self._dados: Dict[str, Any] = {}
        self._carregar()

    # ─────────────────────────── PERSISTÊNCIA ────────────────────────────────

    def _carregar(self) -> None:
        """Carrega ou inicializa a base de conhecimento."""
        CONHECIMENTO_DIR.mkdir(parents=True, exist_ok=True)
        if CONHECIMENTO_FILE.exists():
            try:
                raw = CONHECIMENTO_FILE.read_text(encoding="utf-8")
                self._dados = json.loads(raw)
                # Migração: garante todas as chaves existem
                for chave, valor_padrao in _ESTRUTURA.items():
                    if chave not in self._dados:
                        if isinstance(valor_padrao, dict):
                            self._dados[chave] = {}
                        elif isinstance(valor_padrao, list):
                            self._dados[chave] = []
                        else:
                            self._dados[chave] = valor_padrao
            except (json.JSONDecodeError, OSError, KeyError):
                self._dados = self._estrutura_vazia()
        else:
            self._dados = self._estrutura_vazia()

    def _estrutura_vazia(self) -> Dict[str, Any]:
        """Retorna estrutura inicial com cópias independentes."""
        return {
            "waf_tampers": {},
            "sqli_tecnicas": {},
            "payloads_xss": {},
            "subdominios_encontrados": {},
            "tecnologias_vistas": {},
            "scans_historico": [],
            "proxies_funcionaram": [],
            "chat_contexto": [],
            "estatisticas": {"total_scans": 0, "total_vulns": 0},
        }

    def _salvar(self) -> None:
        """Persiste no disco. Falha silenciosamente (não crítico)."""
        try:
            CONHECIMENTO_DIR.mkdir(parents=True, exist_ok=True)
            CONHECIMENTO_FILE.write_text(
                json.dumps(self._dados, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    # ─────────────────────────── REGISTRAR ───────────────────────────────────

    def registrar_scan(self, alvo: str, resultado: dict) -> None:
        """Registra resultado de um scan na base e atualiza estatísticas."""
        total_vulns = resultado.get("vulnerabilidades_totais", 0)
        dominio = self._extrair_dominio(alvo)

        # Histórico (máx 100 entradas)
        historico: list = self._dados.setdefault("scans_historico", [])
        historico.append({
            "alvo": alvo,
            "data": datetime.now().strftime("%d/%m/%Y %H:%M"),
            "vulns": total_vulns,
            "waf": resultado.get("waf", []),
            "tecnologias": resultado.get("tecnologias", []),
            "sqli": len(resultado.get("sqli", [])),
            "xss": len(resultado.get("xss", [])),
        })
        if len(historico) > 100:
            historico.pop(0)

        # Estatísticas
        stats = self._dados.setdefault("estatisticas", {})
        stats["total_scans"] = stats.get("total_scans", 0) + 1
        stats["total_vulns"] = stats.get("total_vulns", 0) + total_vulns

        # Tecnologias vistas
        if resultado.get("tecnologias"):
            techs_map: dict = self._dados.setdefault("tecnologias_vistas", {})
            existentes = set(techs_map.get(dominio, []))
            existentes.update(resultado["tecnologias"])
            techs_map[dominio] = list(existentes)

        # Subdominios encontrados
        subs_raw = resultado.get("subdominios", [])
        if subs_raw:
            subs_names = [
                s.get("subdominio", s) if isinstance(s, dict) else str(s)
                for s in subs_raw
                if s
            ]
            if subs_names:
                self.registrar_subdominios(dominio, subs_names)

        self._salvar()

    def registrar_waf_tamper(self, waf: str, tampers_funcionaram: List[str]) -> None:
        """Registra tampers que funcionaram para um WAF específico."""
        if not waf or not tampers_funcionaram:
            return
        waf_key = waf.lower().split()[0]
        mapa: dict = self._dados.setdefault("waf_tampers", {})
        existentes = set(mapa.get(waf_key, []))
        existentes.update(tampers_funcionaram)
        mapa[waf_key] = list(existentes)
        self._salvar()

    def registrar_sqli(self, dbms: str, tecnicas: List[str]) -> None:
        """Registra técnicas SQLi confirmadas para um DBMS."""
        if not dbms or not tecnicas:
            return
        mapa: dict = self._dados.setdefault("sqli_tecnicas", {})
        existentes = set(mapa.get(dbms, []))
        existentes.update(tecnicas)
        mapa[dbms] = list(existentes)
        self._salvar()

    def registrar_xss(self, tecnologia: str, payloads: List[str]) -> None:
        """Registra payloads XSS confirmados para uma tecnologia."""
        if not tecnologia or not payloads:
            return
        mapa: dict = self._dados.setdefault("payloads_xss", {})
        existentes = set(mapa.get(tecnologia, []))
        existentes.update(payloads)
        mapa[tecnologia] = list(existentes)
        self._salvar()

    def registrar_subdominios(self, dominio: str, subs: List[str]) -> None:
        """Registra subdominios descobertos para um domínio."""
        if not dominio or not subs:
            return
        mapa: dict = self._dados.setdefault("subdominios_encontrados", {})
        existentes = set(mapa.get(dominio, []))
        existentes.update(subs)
        mapa[dominio] = list(existentes)
        self._salvar()

    def adicionar_contexto_chat(self, role: str, content: str) -> None:
        """Salva mensagem no histórico de chat para persistência entre sessões."""
        ctx: list = self._dados.setdefault("chat_contexto", [])
        ctx.append({
            "role": role,
            "content": content[:600],  # trunca para economizar espaço
            "ts": datetime.now().strftime("%d/%m %H:%M"),
        })
        if len(ctx) > 20:
            ctx.pop(0)
        self._salvar()

    def registrar_proxy(self, proxy: str) -> None:
        """Registra um proxy que funcionou."""
        if not proxy:
            return
        lista: list = self._dados.setdefault("proxies_funcionaram", [])
        if proxy not in lista:
            lista.append(proxy)
            if len(lista) > 20:
                lista.pop(0)
        self._salvar()

    # ─────────────────────────── SUGESTÕES ───────────────────────────────────

    def sugerir_tampers(self, waf: str) -> List[str]:
        """Tampers que já funcionaram para este WAF."""
        if not waf:
            return []
        waf_key = waf.lower().split()[0]
        return self._dados.get("waf_tampers", {}).get(waf_key, [])

    def sugerir_tecnica_sqli(self, dbms: str) -> List[str]:
        """Técnicas SQLi que já funcionaram para este DBMS."""
        return self._dados.get("sqli_tecnicas", {}).get(dbms, [])

    def sugerir_payloads_xss(self, tecnologia: str) -> List[str]:
        """Payloads XSS que já funcionaram nesta tecnologia."""
        return self._dados.get("payloads_xss", {}).get(tecnologia, [])

    def obter_subs_conhecidos(self, dominio: str) -> List[str]:
        """Subdominios já descobertos para este domínio."""
        return self._dados.get("subdominios_encontrados", {}).get(dominio, [])

    def obter_tecnologias(self, dominio: str) -> List[str]:
        """Tecnologias já identificadas neste domínio."""
        return self._dados.get("tecnologias_vistas", {}).get(dominio, [])

    def obter_contexto_chat(self) -> list:
        """Retorna últimas mensagens salvas para continuar conversa."""
        return self._dados.get("chat_contexto", [])

    # ─────────────────────────── CONTEXTO PARA GPT ───────────────────────────

    def obter_contexto_para_ia(self, alvo: str = "") -> str:
        """
        Gera bloco de texto com o conhecimento acumulado para injetar
        no system prompt do GPT. Torna o Vlad IA mais inteligente com
        o histórico real de pentests realizados.
        """
        linhas: List[str] = []
        dominio = self._extrair_dominio(alvo) if alvo else ""

        # Tecnologias deste domínio
        techs = self.obter_tecnologias(dominio)
        if techs:
            linhas.append(f"Tecnologias já vistas em '{dominio}': {', '.join(techs)}")

        # WAFs e tampers aprendidos
        waf_tampers: dict = self._dados.get("waf_tampers", {})
        if waf_tampers:
            partes = []
            for waf, ts in list(waf_tampers.items())[:6]:
                partes.append(f"{waf}→[{','.join(ts[:4])}]")
            linhas.append(f"Tampers comprovados: {'; '.join(partes)}")

        # Técnicas SQLi por DBMS
        sqli: dict = self._dados.get("sqli_tecnicas", {})
        if sqli:
            partes = [f"{db}→{','.join(ts)}" for db, ts in list(sqli.items())[:5]]
            linhas.append(f"Técnicas SQLi confirmadas: {'; '.join(partes)}")

        # Subdominios do domínio atual
        subs = self.obter_subs_conhecidos(dominio)
        if subs:
            linhas.append(f"Subdominios de '{dominio}': {', '.join(subs[:12])}")

        # Estatísticas gerais
        stats = self._dados.get("estatisticas", {})
        total = stats.get("total_scans", 0)
        vulns = stats.get("total_vulns", 0)
        if total > 0:
            linhas.append(
                f"Base de conhecimento: {total} scans realizados, "
                f"{vulns} vulnerabilidades encontradas no total."
            )

        if not linhas:
            return ""

        return "=== CONHECIMENTO ACUMULADO DO VLAD ===\n" + "\n".join(linhas)

    # ─────────────────────────── ESTATÍSTICAS ────────────────────────────────

    def estatisticas(self) -> dict:
        stats = self._dados.get("estatisticas", {})
        return {
            "total_scans": stats.get("total_scans", 0),
            "total_vulns": stats.get("total_vulns", 0),
            "waf_aprendidos": len(self._dados.get("waf_tampers", {})),
            "dbms_aprendidos": len(self._dados.get("sqli_tecnicas", {})),
            "dominios_vistos": len(self._dados.get("tecnologias_vistas", {})),
            "subdominios_salvos": sum(
                len(v) for v in self._dados.get("subdominios_encontrados", {}).values()
            ),
        }

    # ─────────────────────────── HELPERS ─────────────────────────────────────

    def _extrair_dominio(self, url: str) -> str:
        if not url:
            return ""
        try:
            if url.startswith(("http://", "https://")):
                netloc = urlparse(url).netloc or ""
                return netloc.split(":")[0]
            return url.split("/")[0].split(":")[0].strip()
        except Exception:
            return url[:50]
