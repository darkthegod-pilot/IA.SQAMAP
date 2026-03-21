# Skill: WAF Detection

## Metadata
- Phase: reconnaissance
- Techniques: N/A (pre-injection)
- DB Targets: all
- Risk Level: low
- Prerequisites: target URL

## When to Use

Use this skill when you suspect a Web Application Firewall is present, or when your initial injection attempts are being blocked (HTTP 403, 406, 429, or generic error pages). Identifying the WAF vendor is critical for selecting the right tamper scripts.

## Detection Methods

### 1. SQLMap Built-in WAF Detection
```bash
# SQLMap automatically detects WAFs and prints a warning
sqlmap -u "http://target.com/page.php?id=1" --batch --identify-waf
```

### 2. Python Utility (waf_detector.py)
```bash
python utils/waf_detector.py --target "http://target.com/page.php?id=1"
```

### 3. Manual WAF Fingerprinting from Response Headers

Send a deliberate malicious payload and inspect the response:

```bash
curl -i "http://target.com/page.php?id=1' OR 1=1--"
```

WAF indicators by vendor:

| Vendor | Response Code | Headers/Body Clues |
|--------|---------------|-------------------|
| Cloudflare | 403 | `Server: cloudflare`, `CF-RAY` header, "Cloudflare" in body |
| ModSecurity | 403 | `Mod_Security` or `NAXSI` in body |
| Imperva (Incapsula) | 403 | `X-Cdn: Incapsula`, "Incapsula" in body |
| F5 BIG-IP ASM | 403 | `X-WA-Info` header, "The requested URL was rejected" |
| AWS WAF | 403 | `x-amzn-RequestId` header |
| Akamai | 403 | `AkamaiGHost` header, "Reference #" in body |
| Sucuri | 403 | `X-Sucuri-ID` header |
| Barracuda | 403 | "Barracuda" in body, `barra_counter_session` cookie |
| Fortinet FortiWeb | 403 | "FortiWeb" in body |
| Citrix NetScaler | 403 | `Via: NS-CACHE` header |
| Generic/Unknown | 403/406 | No identifying markers |

### 4. wafw00f Tool
```bash
wafw00f http://target.com
```

### 5. HTTP Status Code Analysis
| Status | Meaning |
|--------|---------|
| 200 OK | No WAF or WAF allows |
| 400 Bad Request | Input validation |
| 403 Forbidden | WAF blocking (most common) |
| 406 Not Acceptable | WAF blocking content type |
| 429 Too Many Requests | Rate limiting active |
| 503 Service Unavailable | Challenge page or overload |
| Redirect to captcha | JS challenge (Cloudflare Bot Fight) |

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --identify-waf --batch
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --identify-waf \
  --random-agent \
  --batch \
  -v 3
```

## Expected Output
```
[WARNING] heuristic (basic) test shows that the target might be protected by some kind of WAF/IPS
[CRITICAL] sqlmap identified the following WAF/IPS:
           Cloudflare (Cloudflare Inc.)
```

## Red Flags
- If SQLMap proceeds without WAF warnings, there may be no WAF (or it's not signature-detectable)
- Some WAFs silently pass through traffic (transparent mode) - behavioral analysis needed

## Follow-Up
- WAF identified -> [Tamper Selection Guide](../02_waf_evasion/tamper_selection_guide.md)
- No WAF detected -> [Quick Scan](../01_detection/quick_scan.md)
- Rate limiting (429) -> [Stealth Scan config](../../configs/stealth_scan.cfg)
