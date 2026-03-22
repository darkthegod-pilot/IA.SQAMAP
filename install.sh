#!/bin/bash
set -e

echo "[*] Instalando dependências do sistema..."
apt-get update -qq
apt-get install -y python3 python3-pip sqlmap -qq

echo "[*] Instalando dependências Python..."
pip3 install -r requirements.txt -q

echo ""
echo "[+] Instalação concluída!"
echo "[+] Para iniciar: python3 framework.py"
