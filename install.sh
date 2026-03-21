#!/bin/bash
# ============================================================
# VLAD VOLKOV — Script de Instalação para VPS
# Compatível com Ubuntu 20.04+, Debian 10+
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/vlad-volkov"
SERVICE_USER="vlad"

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  VLAD VOLKOV — Instalação VPS                       ║"
echo "║  Pentester Web Especialista                          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Execute como root: sudo ./install.sh${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Atualizando pacotes...${NC}"
apt-get update -qq

echo -e "${CYAN}[*] Instalando dependências do sistema...${NC}"
apt-get install -y -qq python3 python3-pip git curl wget sqlmap 2>/dev/null || \
    echo -e "${YELLOW}[!] SQLMap não disponível via apt, instalar manualmente${NC}"

echo -e "${CYAN}[*] Instalando dependências Python...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pip3 install -q -r "$SCRIPT_DIR/requirements.txt"

echo -e "${CYAN}[*] Criando diretórios necessários...${NC}"
mkdir -p relatorios logs sessoes

echo -e "${CYAN}[*] Configurando permissões...${NC}"
chmod +x "$SCRIPT_DIR/vlad.py"

# Verificar SQLMap
if command -v sqlmap &>/dev/null; then
    SQLMAP_VER=$(sqlmap --version 2>/dev/null | head -1)
    echo -e "${GREEN}[✓] SQLMap: $SQLMAP_VER${NC}"
else
    echo -e "${YELLOW}[!] SQLMap não encontrado. Instalar:${NC}"
    echo "    pip3 install sqlmap"
    echo "    ou: apt-get install sqlmap"
fi

# Verificar Python
PYTHON_VER=$(python3 --version)
echo -e "${GREEN}[✓] $PYTHON_VER${NC}"

# Verificar módulos
echo -e "${CYAN}[*] Verificando módulos Python...${NC}"
for modulo in rich requests colorama; do
    python3 -c "import $modulo" 2>/dev/null && \
        echo -e "${GREEN}[✓] $modulo${NC}" || \
        echo -e "${RED}[✗] $modulo - FALHA${NC}"
done

# Instalar serviço systemd (opcional)
if [ -f "$SCRIPT_DIR/vlad.service" ]; then
    echo -e "${CYAN}[*] Instalando serviço systemd...${NC}"

    # Atualizar caminho no service file
    sed -i "s|/opt/vlad-volkov|$SCRIPT_DIR|g" "$SCRIPT_DIR/vlad.service"

    cp "$SCRIPT_DIR/vlad.service" /etc/systemd/system/
    systemctl daemon-reload
    echo -e "${GREEN}[✓] Serviço vlad.service instalado${NC}"
    echo "    Para habilitar: systemctl enable vlad"
    echo "    Para iniciar:   systemctl start vlad"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Instalação concluída!                               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Testar instalação:${NC}"
echo "  python3 $SCRIPT_DIR/vlad.py instalar"
echo ""
echo -e "${CYAN}Uso básico:${NC}"
echo "  python3 $SCRIPT_DIR/vlad.py scan --alvo 'http://alvo.com/?id=1'"
echo "  python3 $SCRIPT_DIR/vlad.py auto --alvo 'http://alvo.com/?id=1'"
