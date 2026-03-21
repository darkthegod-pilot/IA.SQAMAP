# Skill: Parameter Discovery

## Metadata
- Phase: reconnaissance
- Techniques: N/A (pre-injection)
- DB Targets: all
- Risk Level: low
- Prerequisites: target URL, authorization

## When to Use

Use this skill at the very beginning of an engagement, before running any injection tests. Identifying the right parameters to test saves significant time and reduces noise. Manual or semi-automated parameter discovery is always more reliable than letting sqlmap guess.

## Approach

### 1. Manual Browsing (Highest Value)
Manually browse the target application with Burp Suite intercepting all traffic. Identify:
- GET parameters: `?id=1&category=books`
- POST bodies: form submissions, JSON APIs
- Cookies: session IDs, tracking values
- Headers: `X-User-ID`, `X-Forwarded-For`

### 2. Burp Suite Spider/Crawler
```
Target -> Site Map -> Spider this host
```
Then filter requests with parameters in Burp's HTTP history.

### 3. SQLMap Form Parsing
```bash
# Auto-discover and test forms on a page
sqlmap -u "http://target.com/login" --forms --batch

# Crawl and find parameters
sqlmap -u "http://target.com/" --crawl=3 --forms --batch
```

### 4. Google Dorking for Parameters
```
site:target.com inurl:"?id="
site:target.com inurl:"?user="
site:target.com inurl:"?page="
site:target.com inurl:"?cat="
site:target.com inurl:"?search="
```

### 5. Common High-Value Parameter Names
These parameter names are historically vulnerable:
```
id, uid, user_id, item_id, product_id, order_id
category, cat, type, sort
page, p, pg
search, q, query, keyword
name, username, email
token, session, auth
redirect, url, next, returnUrl
```

## High-Value Targets

Prioritize parameters that:
- Accept numeric IDs (most likely vulnerable to SQL injection)
- Control what data is displayed (category, filter, search)
- Are used in database lookups (user profile, product detail)
- Are hidden in POST bodies (registration, login, checkout)
- Appear in cookies (session tracking, user preferences)

## Minimum Viable Command

```bash
# Test specific discovered parameter
sqlmap -u "http://target.com/page.php?id=1" -p id --batch
```

## Recommended Full Command

```bash
# Comprehensive form discovery and parameter mapping
sqlmap -u "http://target.com/" \
  --crawl=3 \
  --forms \
  --batch \
  --level=1 \
  --risk=1 \
  --output-dir=./output/
```

## Expected Output
```
[*] starting @ 12:00:00
[INFO] testing connection to the target URL
[INFO] searching for forms
[INFO] found 3 targets
[INFO] testing URL 'http://target.com/login' (POST)
[INFO] testing parameter 'username'
[INFO] testing parameter 'password'
```

## Red Flags (wrong skill)
- If you already know the parameter, skip to detection skills
- If app has no parameters, test POST bodies and cookies with `--level=2`

## Follow-Up
- Identified parameters -> [Quick Scan](../01_detection/quick_scan.md)
- WAF detected during crawl -> [WAF Detection](waf_detection.md)
- DBMS errors seen -> [Error-Based Detection](../01_detection/error_based.md)
