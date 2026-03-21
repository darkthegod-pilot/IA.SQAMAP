#!/usr/bin/env bash
# ============================================================
# VLAD VOLKOV v2.2 — Script de Instalação
# Compatível com Ubuntu 20.04+, Debian 10+, Kali Linux
# ============================================================

set -euo pipefail

# ── Cores ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
info() { echo -e "${CYAN}  → $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${NC}"; }
erro() { echo -e "${RED}  ✗ $*${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VLAD_CFG_DIR="$HOME/.vlad"
VLAD_CFG_FILE="$VLAD_CFG_DIR/config.json"
ERROS=0

# ── Banner ───────────────────────────────────────────────────
echo -e "${RED}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  VLAD VOLKOV v2.2 — Instalação                      ║"
echo "║  Framework de Pentest Web  |  PT-BR                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================
# [1/7] Sistema operacional e Python
# ============================================================
echo -e "\n${BOLD}[1/7] Verificando sistema e Python...${NC}"

# Python >= 3.8 obrigatório
if ! command -v python3 &>/dev/null; then
    erro "Python3 não encontrado. Instale com: apt-get install python3"
    exit 1
fi

PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]; }; then
    erro "Python 3.8+ necessário. Versão atual: $(python3 --version)"
    exit 1
fi

ok "Python $(python3 --version | cut -d' ' -f2)"

# Detectar sistema
if [ -f /etc/os-release ]; then
    . /etc/os-release
    ok "Sistema: ${PRETTY_NAME:-Linux}"
else
    ok "Sistema: Linux"
fi

# ============================================================
# [2/7] Conexão com internet
# ============================================================
echo -e "\n${BOLD}[2/7] Verificando conexão com internet...${NC}"

if curl -sf --max-time 5 https://pypi.org > /dev/null 2>&1; then
    ok "Conexão com internet disponível"
elif curl -sf --max-time 5 https://google.com > /dev/null 2>&1; then
    ok "Conexão com internet disponível (PyPI pode estar lenta)"
    warn "Se pip falhar, tente novamente em alguns instantes"
else
    warn "Sem acesso à internet detectado — instalação pode falhar"
    warn "Continue mesmo assim? [S/n]"
    read -r resp
    if [[ "${resp,,}" == "n" ]]; then
        info "Instalação cancelada pelo usuário."
        exit 0
    fi
fi

# ============================================================
# [3/7] Dependências do sistema
# ============================================================
echo -e "\n${BOLD}[3/7] Instalando dependências do sistema...${NC}"

# SQLMap
if command -v sqlmap &>/dev/null; then
    SQLMAP_VER=$(sqlmap --version 2>/dev/null | head -1 || echo "desconhecida")
    ok "sqlmap já instalado: $SQLMAP_VER"
else
    info "Instalando sqlmap..."
    if command -v apt-get &>/dev/null; then
        if apt-get install -y -qq sqlmap 2>/dev/null; then
            ok "sqlmap instalado via apt"
        else
            warn "sqlmap não disponível via apt — tentando pip..."
            if pip3 install --quiet sqlmap 2>/dev/null; then
                ok "sqlmap instalado via pip"
            else
                warn "sqlmap não pôde ser instalado automaticamente"
                warn "Instale manualmente: pip3 install sqlmap  OU  apt-get install sqlmap"
                ERROS=$((ERROS + 1))
            fi
        fi
    else
        if pip3 install --quiet sqlmap 2>/dev/null; then
            ok "sqlmap instalado via pip"
        else
            warn "sqlmap não instalado — instale com: pip3 install sqlmap"
            ERROS=$((ERROS + 1))
        fi
    fi
fi

# Git (necessário para auto-update)
if command -v git &>/dev/null; then
    ok "git disponível"
else
    info "Instalando git..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq git 2>/dev/null && ok "git instalado" || warn "git não pôde ser instalado"
    else
        warn "git não encontrado — instale manualmente para usar auto-update"
    fi
fi

# ============================================================
# [4/7] Pacotes Python
# ============================================================
echo -e "\n${BOLD}[4/7] Instalando pacotes Python...${NC}"

REQ_FILE="$SCRIPT_DIR/requirements.txt"
if [ ! -f "$REQ_FILE" ]; then
    warn "requirements.txt não encontrado — instalando pacotes essenciais..."
    PKGS="rich requests colorama dnspython"
else
    PKGS=""
fi

instalar_pip() {
    local pkg="$1"
    if pip3 install --quiet "$pkg" 2>/dev/null; then
        ok "$pkg"
    elif pip3 install --quiet --break-system-packages "$pkg" 2>/dev/null; then
        ok "$pkg (--break-system-packages)"
    else
        erro "$pkg — falha na instalação"
        ERROS=$((ERROS + 1))
    fi
}

if [ -f "$REQ_FILE" ]; then
    info "Instalando de requirements.txt..."
    if pip3 install --quiet -r "$REQ_FILE" 2>/dev/null || \
       pip3 install --quiet --break-system-packages -r "$REQ_FILE" 2>/dev/null; then
        ok "Todos os pacotes do requirements.txt instalados"
    else
        warn "Falha ao instalar em lote — instalando individualmente..."
        while IFS= read -r linha || [[ -n "$linha" ]]; do
            linha="${linha%%#*}"  # Remove comentários
            linha="${linha//[[:space:]]/}"
            [ -z "$linha" ] && continue
            instalar_pip "$linha"
        done < "$REQ_FILE"
    fi
else
    for pkg in $PKGS; do
        instalar_pip "$pkg"
    done
fi

# openai é opcional (para chat com IA)
if ! python3 -c "import openai" 2>/dev/null; then
    info "Instalando openai (necessário para chat com IA)..."
    instalar_pip "openai>=1.0.0" || true
fi

# ============================================================
# [5/7] Diretórios e permissões
# ============================================================
echo -e "\n${BOLD}[5/7] Configurando diretórios...${NC}"

for d in relatorios logs sessoes saidas; do
    mkdir -p "$SCRIPT_DIR/$d"
    ok "Diretório: $SCRIPT_DIR/$d"
done

# Diretório de configuração do Vlad
mkdir -p "$VLAD_CFG_DIR"
ok "Config dir: $VLAD_CFG_DIR"

# Permissões de execução
chmod +x "$SCRIPT_DIR/framework.py" 2>/dev/null || true
[ -f "$SCRIPT_DIR/vlad.py" ] && chmod +x "$SCRIPT_DIR/vlad.py" 2>/dev/null || true

# Verificar permissão de escrita
if touch "$VLAD_CFG_DIR/.write_test" 2>/dev/null; then
    rm -f "$VLAD_CFG_DIR/.write_test"
    ok "Permissões de escrita OK"
else
    erro "Sem permissão de escrita em $VLAD_CFG_DIR"
    ERROS=$((ERROS + 1))
fi

# ============================================================
# [6/7] API Key OpenAI (opcional)
# ============================================================
echo -e "\n${BOLD}[6/7] Configurando API Key OpenAI (opcional)...${NC}"
echo -e "  ${CYAN}O chat com Vlad IA usa o GPT-4o-mini.${NC}"
echo -e "  ${CYAN}Se não tiver uma key agora, configure depois em: Menu [9] → [1]${NC}"
echo ""
echo -n -e "  ${BOLD}API Key OpenAI [Enter para pular]: ${NC}"

# Leitura silenciosa (sem eco)
if [ -t 0 ]; then
    read -rs OPENAI_KEY || OPENAI_KEY=""
    echo ""
else
    OPENAI_KEY=""
fi

if [ -n "$OPENAI_KEY" ]; then
    # Validação básica: key deve começar com sk-
    if [[ "$OPENAI_KEY" == sk-* ]] && [ "${#OPENAI_KEY}" -gt 20 ]; then
        # Salvar em ~/.vlad/config.json
        if [ -f "$VLAD_CFG_FILE" ]; then
            # Atualizar key existente preservando outras configs
            python3 - <<PYEOF
import json, sys
try:
    cfg = json.loads(open("$VLAD_CFG_FILE").read())
except Exception:
    cfg = {}
cfg["openai_api_key"] = "$OPENAI_KEY"
open("$VLAD_CFG_FILE", "w").write(json.dumps(cfg, indent=2, ensure_ascii=False))
print("OK")
PYEOF
        else
            python3 - <<PYEOF
import json
cfg = {"openai_api_key": "$OPENAI_KEY"}
open("$VLAD_CFG_FILE", "w").write(json.dumps(cfg, indent=2, ensure_ascii=False))
print("OK")
PYEOF
        fi
        # Mascarar key na exibição
        MASKED="${OPENAI_KEY:0:10}...${OPENAI_KEY: -4}"
        ok "API Key salva: $MASKED"
    else
        warn "Formato de key inválido (deve começar com 'sk-' e ter mais de 20 caracteres)"
        warn "Configure depois em: Menu [9] → [1]"
    fi
else
    info "API Key não configurada — chat com IA ficará desativado"
    info "Configure depois: Menu [9] → [1], ou: export OPENAI_API_KEY=sk-proj-..."
fi

# ============================================================
# [7/7] Verificação final
# ============================================================
echo -e "\n${BOLD}[7/7] Verificando instalação...${NC}"

FALHAS_IMPORT=()

for modulo in rich requests; do
    if python3 -c "import $modulo" 2>/dev/null; then
        ok "import $modulo"
    else
        erro "import $modulo — FALHA"
        FALHAS_IMPORT+=("$modulo")
        ERROS=$((ERROS + 1))
    fi
done

# Testar importação do framework principal
if python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR')
from core.agente_ia import AgenteIA
from modulos.enumerador_web import EnumeradorWeb
from modulos.enum_subdominios import EnumeradorSubdominios
print('OK')
" 2>/dev/null | grep -q "OK"; then
    ok "Módulos do framework OK"
else
    warn "Alguns módulos do framework não carregaram — verifique os logs acima"
    ERROS=$((ERROS + 1))
fi

# ── Resumo Final ─────────────────────────────────────────────
echo ""
if [ "$ERROS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   ✓  VLAD VOLKOV v2.2 INSTALADO COM SUCESSO!        ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${CYAN}  Para iniciar:${NC}"
    echo -e "    ${BOLD}python3 $SCRIPT_DIR/framework.py${NC}"
    echo ""
    echo -e "${CYAN}  Ou com alvo direto:${NC}"
    echo -e "    ${BOLD}python3 $SCRIPT_DIR/framework.py --alvo 'http://alvo.com/?id=1'${NC}"
else
    echo -e "${YELLOW}${BOLD}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   ⚠  INSTALAÇÃO CONCLUÍDA COM $ERROS AVISO(S)       ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}  Verifique os avisos acima antes de usar.${NC}"
    echo -e "  Execute: ${BOLD}python3 $SCRIPT_DIR/framework.py${NC}"
fi

echo ""
echo -e "${CYAN}  Configuração da IA depois:${NC}"
echo -e "    Menu [9] → [1]  ou  export OPENAI_API_KEY=sk-proj-..."
echo ""
