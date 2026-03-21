# VLAD VOLKOV — Pentester Web Especialista

> **Sistema de Pentest Web Automatizado**
>
> Agente especializado em SQLMap automatizado com detecção de WAF, seleção inteligente de tampers, e testes abrangentes de vulnerabilidades web. 100% em Português do Brasil.

---

## Aviso Legal

> **USO AUTORIZADO APENAS**
>
> Este sistema é destinado exclusivamente para testes de segurança autorizados. O uso em sistemas sem permissão explícita do proprietário é ilegal. O autor não se responsabiliza por uso indevido.

---

## Visão Geral

```
╔══════════════════════════════════════════════════════╗
║  VLAD VOLKOV — Pentester Web Especialista            ║
║  Especialidade: SQLMap Automatizado                  ║
║  v2.0.0 | Apenas para uso autorizado                 ║
╚══════════════════════════════════════════════════════╝
```

**Vlad Volkov** é um agente de pentest web com foco em automação avançada de SQL Injection via SQLMap, complementado por módulos para XSS, LFI, SSRF, Command Injection, Directory Traversal e Bypass de Autenticação.

---

## Funcionalidades

- **Scan SQLMap Automatizado** com 5 perfis de intensidade
- **Detecção de WAF** com 10 assinaturas conhecidas
- **Seleção Automática de Tampers** baseada em WAF + DBMS
- **Wizard de Técnica** para escolha da estratégia ideal
- **Módulos Web**: XSS, LFI, SSRF, CMD Injection, Traversal, Auth Bypass
- **Relatórios** em JSON e Markdown com severidade por cor
- **Output Rico** com progress bars, spinners e tempo estimado
- **Compatível com VPS** (headless, systemd service)

---

## Instalação

### Dependências do Sistema

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y python3 python3-pip sqlmap

# Verificar sqlmap
sqlmap --version
```

### Dependências Python

```bash
pip3 install -r requirements.txt
```

### Verificar Instalação

```bash
python3 vlad.py instalar
```

---

## Uso Rápido

```bash
# Scan SQLMap simples
python vlad.py scan --alvo "http://alvo.com/produto?id=1"

# Modo automático completo (recon + SQLi + web + relatório)
python vlad.py auto --alvo "http://alvo.com/produto?id=1" --enum-completo

# Detectar WAF
python vlad.py waf --alvo "http://alvo.com" --probe

# Selecionar tampers para WAF + DBMS
python vlad.py tamper --waf cloudflare --dbms mysql

# Wizard de técnica (interativo)
python vlad.py tecnica

# Testes web (XSS, LFI, etc.)
python vlad.py web --alvo "http://alvo.com/?q=teste" --tipo xss lfi

# Ver último relatório
python vlad.py relatorio --sessao ultima
```

---

## Comandos Detalhados

### `scan` — Scan SQLMap

```bash
python vlad.py scan --alvo "http://alvo.com/?id=1" [opções]

Opções:
  --modo       rapido | padrao | profundo | furtivo | agressivo
  --waf        WAF detectado (seleciona tampers automaticamente)
  --dbms       mysql | mssql | postgresql | oracle | sqlite
  --tamper     Tampers manuais (ex: space2comment,randomcase)
  --enum       bancos tabelas usuarios senhas dba banner
  --nivel      1-5 (profundidade dos testes)
  --risco      1-3 (risco de impacto)
  --threads    Número de threads paralelas
  --delay      Delay entre requisições (segundos)
  --cookie     Cookie de sessão autenticada
  --proxy      Proxy (ex: http://127.0.0.1:8080)
  --salvar     Salvar relatório JSON e Markdown
```

**Exemplos:**
```bash
# Scan padrão com detecção automática de WAF
python vlad.py scan --alvo "http://alvo.com/?id=1" --waf cloudflare --dbms mysql

# Scan profundo com enumeração
python vlad.py scan --alvo "http://alvo.com/?id=1" --modo profundo \
  --enum bancos tabelas usuarios senhas --salvar

# Scan com sessão autenticada
python vlad.py scan --alvo "http://painel.com/produtos?id=1" \
  --cookie "PHPSESSID=abc123xyz" --modo padrao
```

### `auto` — Modo Automático Total

```bash
python vlad.py auto --alvo "http://alvo.com/?id=1" [--modo rapido|padrao|profundo] [--enum-completo]
```

Sequência automática:
1. Detecção de WAF
2. Seleção de tampers
3. Scan SQLMap
4. Testes web (XSS, LFI, etc.)
5. Geração de relatório

### `waf` — Detecção de WAF

```bash
python vlad.py waf --alvo "http://alvo.com" [--probe]

--probe    Envia payloads SQL para provocar o WAF (mais preciso)
```

### `tamper` — Seleção de Tampers

```bash
python vlad.py tamper --waf cloudflare --dbms mysql [--nivel padrao] [--alvo URL]
python vlad.py tamper --listar-wafs
```

### `tecnica` — Wizard de Técnica

```bash
python vlad.py tecnica [--alvo URL] [--perfil rapido|padrao|completo|furtivo|waf_evasao]
```

### `web` — Testes de Vulnerabilidades Web

```bash
python vlad.py web --alvo "http://alvo.com/?q=test" --tipo xss lfi ssrf cmd traversal auth
```

### `relatorio` — Gerenciar Relatórios

```bash
python vlad.py relatorio --sessao ultima
python vlad.py relatorio --listar
```

---

## Estrutura do Projeto

```
IA.SQAMAP/
├── vlad.py                     ← Ponto de entrada principal
├── requirements.txt
├── install.sh                  ← Instalação automática VPS
├── vlad.service                ← Systemd service
│
├── core/
│   ├── banner.py               ← Visual e banner
│   ├── engine.py               ← Orquestrador de scans
│   ├── reporter.py             ← Gerador de relatórios PT-BR
│   └── logger.py               ← Logging VPS-friendly
│
├── utils/
│   ├── detector_waf.py         ← Detecção de WAF
│   ├── seletor_tamper.py       ← Seleção de tampers
│   ├── conselheiro_tecnica.py  ← Wizard de técnica SQLi
│   ├── construtor_comando.py   ← Builder de comandos SQLMap
│   └── parser_saida.py         ← Parser de output SQLMap
│
├── modulos/
│   ├── xss_scanner.py          ← Scanner XSS refletido
│   ├── lfi_scanner.py          ← Scanner LFI/RFI
│   ├── ssrf_scanner.py         ← Scanner SSRF
│   ├── injecao_cmd.py          ← Scanner Command Injection
│   ├── traversal_scanner.py    ← Scanner Directory Traversal
│   └── bypass_auth.py          ← Testes de Auth Bypass
│
├── skills/                     ← Base de conhecimento PT-BR
│   ├── 00_reconhecimento/
│   ├── 01_deteccao/
│   ├── 02_evasao_waf/
│   ├── 03_exploracao/
│   ├── 04_web_attacks/
│   └── 05_pos_exploracao/
│
├── configs/                    ← Perfis SQLMap
├── tamper/                     ← Documentação de tampers
│   └── chains/                 ← Chains por WAF
└── docs/
    └── cheatsheets/            ← Referência rápida por DBMS
```

---

## Perfis de Scan

| Perfil | Técnicas | Nível | Threads | Uso |
|--------|----------|-------|---------|-----|
| `rapido` | EU | 1 | 5 | Detecção inicial |
| `padrao` | BEUST | 3 | 3 | Uso geral |
| `profundo` | BEUSTQ | 5 | 1 | Cobertura máxima |
| `furtivo` | BT | 1 | 1 | Evitar detecção |
| `agressivo` | BEUSTQ | 5 | 10 | Velocidade máxima |

---

## WAFs Suportados

| WAF | Tampers Padrão |
|-----|---------------|
| Cloudflare | space2comment, randomcase, charencode |
| ModSecurity | modsecurityzeroversioned, space2comment |
| Imperva | space2comment, between, greatest, charencode |
| F5 BIG-IP | randomcase, charencode, space2randomblank |
| Akamai | between, chardoubleencode, randomcase |
| AWS WAF | charencode, randomcase, between |
| Sucuri | space2comment, randomcase |
| Barracuda | percentage, randomcase |
| Fortinet | space2comment, randomcase, charencode |

---

## Deploy em VPS

```bash
# Instalação automática
chmod +x install.sh
sudo ./install.sh

# Ou manual
git clone <repo> /opt/vlad-volkov
cd /opt/vlad-volkov
pip3 install -r requirements.txt

# Configurar como serviço systemd
sudo cp vlad.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vlad
```

---

## Técnicas SQL Suportadas

| Código | Técnica | Velocidade | Quando Usar |
|--------|---------|-----------|-------------|
| B | Boolean-based Blind | Lenta | Diferença TRUE/FALSE visível |
| T | Time-based Blind | Muito Lenta | Sem diferença visível |
| E | Error-based | Rápida | Erros SQL expostos |
| U | UNION-based | Muito Rápida | Dados refletidos na resposta |
| S | Stacked Queries | Média | MSSQL, PostgreSQL |
| Q | Out-of-band DNS | Média | Último recurso |

---

## Relatórios

Relatórios são salvos automaticamente em `relatorios/`:
- `relatorios/*.json` — Dados estruturados
- `relatorios/*.md` — Markdown legível

```bash
# Ver último relatório
python vlad.py relatorio --sessao ultima

# Listar todos
python vlad.py relatorio --listar
```

---

Desenvolvido para uso exclusivo em testes de segurança autorizados.
