# Limpeza de Evidências

> **AVISO**: Esta skill é documentada apenas para fins educacionais e para entender os riscos em ambientes autorizados. Durante um pentest legítimo, NÃO limpar logs é muitas vezes preferível para demonstrar o alcance do comprometimento ao cliente.

## Logs a Considerar

### Linux
```bash
# Logs do sistema
/var/log/auth.log          # Autenticações SSH
/var/log/syslog            # Log geral
/var/log/apache2/access.log   # Acessos web
/var/log/apache2/error.log    # Erros web
/var/log/nginx/access.log
/var/log/mysql/mysql.log   # Queries MySQL (se habilitado)
/var/log/postgresql/       # Logs PostgreSQL

# Histórico de shell
~/.bash_history
~/.zsh_history
/root/.bash_history
```

### MySQL/MariaDB
```sql
-- Verificar se general log está ativo
SHOW VARIABLES LIKE 'general_log%';

-- Verificar slow query log
SHOW VARIABLES LIKE 'slow_query_log%';

-- Verificar binary log
SHOW VARIABLES LIKE 'log_bin%';
```

## Artefatos do SQLMap

```bash
# Localização dos arquivos de sessão e output
~/.sqlmap/output/
~/.sqlmap/logs/

# Limpar sessão específica
rm -rf ~/.sqlmap/output/alvo.com/

# Limpar tudo
rm -rf ~/.sqlmap/
```

## Rastreamento Mínimo durante o Pentest

### Boas Práticas para Não Deixar Rastros Desnecessários
```bash
# Usar delay para não sobrecarregar logs
sqlmap -u "http://alvo.com/?id=1" --delay=2 --batch

# Limitar número de requests
sqlmap -u "http://alvo.com/?id=1" --max-requests=1000 --batch

# Usar proxy para controlar traffic
sqlmap -u "http://alvo.com/?id=1" --proxy=http://127.0.0.1:8080 --batch

# Random agent (menos identificável)
sqlmap -u "http://alvo.com/?id=1" --random-agent --batch
```

## Remover Webshells

```bash
# Após o pentest, remover webshells criadas
rm /var/www/html/shell.php
rm /var/www/html/vlad.php
rm /tmp/*.php

# Verificar que foram removidas
ls -la /var/www/html/ | grep .php
```

## Remover Usuários Criados

```sql
-- MySQL: remover usuário de teste
DROP USER 'vlad'@'%';
FLUSH PRIVILEGES;

-- MSSQL
DROP LOGIN vlad;

-- PostgreSQL
DROP ROLE vlad;
```

## Documentar Ações para o Relatório

Em vez de limpar evidências, documente tudo para o relatório:
- Screenshots de vulnerabilidades
- Timestamps de cada ação
- Dados acessados (não extraídos desnecessariamente)
- Impacto potencial demonstrado

## Nota sobre Ética

Durante um pentest autorizado:
1. **NÃO** acessar dados além do necessário para demonstrar o impacto
2. **NÃO** exfiltrar dados reais de clientes/usuários
3. **SEMPRE** remover artefatos (webshells, usuários criados) ao final
4. **DOCUMENTAR** tudo para o relatório de evidências
5. **NOTIFICAR** o cliente imediatamente sobre vulnerabilidades críticas
