#!/bin/bash
set -e

echo "[*] Instalando dependências do sistema..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv sqlmap -qq

echo "[*] Criando ambiente virtual..."
python3 -m venv venv

echo "[*] Instalando dependências Python..."
venv/bin/pip install -r requirements.txt -q

echo ""
echo "[+] Instalação concluída!"
echo "[+] Para iniciar: venv/bin/python3 framework.py"
