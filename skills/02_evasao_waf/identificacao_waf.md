# Identificação de WAF

## Método Sistemático

### Passo 1: Baseline (requisição normal)
```bash
curl -si "http://alvo.com/?id=1" | head -30
# Registrar: status, cabeçalhos, tamanho da resposta
```

### Passo 2: Payload básico (provocar WAF)
```bash
curl -si "http://alvo.com/?id=1' OR 1=1--" | head -30
# Comparar: mudança de status, novos cabeçalhos, corpo diferente
```

### Passo 3: Análise dos resultados

**Cloudflare**
```
Status: 403 ou 503
Server: cloudflare
CF-Ray: 7abc1234def56789-GRU
Corpo: "Ray ID:", "Attention Required! | Cloudflare"
```

**ModSecurity**
```
Status: 403 ou 406
Corpo: "Mod_Security", "NAXSI", "406 Not Acceptable"
```

**Imperva/Incapsula**
```
Cabeçalho: X-Iinfo: X
Cookies: ___utmvc, visid_incap
Corpo: "Incapsula incident ID"
```

**AWS WAF**
```
Cabeçalho: X-Amzn-RequestID
Status: 403
Corpo: simples "403 Forbidden"
```

**F5 BIG-IP**
```
Cabeçalho: X-WA-Info
Corpo: "The requested URL was rejected"
```

## Usando vlad.py

```bash
# Detecção automática
python vlad.py waf --alvo "http://alvo.com/?id=1"

# Com probe ativo (envia payloads)
python vlad.py waf --alvo "http://alvo.com/?id=1" --probe
```

## Tabela de Referência Rápida

| WAF | Status Típico | Cabeçalho Chave | Tampers Recomendados |
|-----|--------------|-----------------|---------------------|
| Cloudflare | 403/503 | CF-Ray | space2comment,randomcase,charencode |
| ModSecurity | 403/406 | - | modsecurityzeroversioned,space2comment |
| Imperva | 403 | X-Iinfo | space2comment,between,greatest |
| F5 BIG-IP | 403 | X-WA-Info | randomcase,charencode,space2randomblank |
| Akamai | 403 | - | between,chardoubleencode,randomcase |
| Sucuri | 403 | X-Sucuri-ID | space2comment,randomcase |
| AWS WAF | 403 | X-Amzn-RequestID | charencode,randomcase,between |
| Barracuda | 400/403 | X-Barracuda-AppID | percentage,randomcase |
| Fortinet | 403 | - | space2comment,randomcase,charencode |
