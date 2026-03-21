# SQLMap Master Methodology

> Decision tree for optimal SQLMap usage during authorized penetration testing engagements.

---

## Phase 0: Pre-Engagement Checklist

Before running any SQLMap command:

- [ ] Written authorization obtained from system owner
- [ ] Scope defined (which hosts, parameters, time window)
- [ ] Rules of engagement documented
- [ ] Evidence collection method ready
- [ ] Rollback plan in case of data corruption

---

## Decision Tree

```
STEP 1: RECONNAISSANCE
======================
  a. Identify injectable parameters manually (or via Burp)
  b. Detect WAF presence
  c. Fingerprint DBMS if possible

  -> See: skills/00_reconnaissance/

STEP 2: INITIAL DETECTION
=========================
  Run quick scan first:
    sqlmap -u "TARGET" --batch --level=1 --risk=1

  Result A: Injection found
    -> Record technique and proceed to STEP 4

  Result B: No injection found, WAF suspected
    -> Proceed to STEP 3 (WAF Evasion)

  Result C: No injection found, no WAF
    -> Increase level/risk: --level=3 --risk=2
    -> Try specific parameter: -p "param"
    -> Try POST data: --data="param=val"

STEP 3: WAF EVASION (if needed)
================================
  a. Identify WAF vendor (see waf_detector.py)
  b. Select tampers from tamper/WAF_TAMPER_MATRIX.md
  c. Apply tampers and retry:
     sqlmap -u "TARGET" --tamper=T1,T2 --random-agent --delay=2

  Result A: Bypass successful, injection found
    -> Proceed to STEP 4

  Result B: Still blocked
    -> Try different tamper chains from tamper/chains/
    -> Consider manual testing with Burp Suite

STEP 4: TECHNIQUE SELECTION
============================
  Based on app behavior, choose optimal technique:

  App shows DB errors?
    YES -> Use Error-based (E) -- fastest
    NO  -> Continue

  App outputs query results?
    YES -> Use UNION-based (U) -- very fast
    NO  -> Continue

  Response size/content differs for true/false?
    YES -> Use Boolean-based blind (B) -- medium speed
    NO  -> Continue

  You control DNS server?
    YES -> Use OOB/DNS (Q) -- 30x faster than time-based
    NO  -> Continue

  App supports multiple statements (test with ;SELECT 1--)?
    YES -> Use Stacked queries (S) -- enables more operations
    NO  -> Fall back to Time-based blind (T) -- always works

STEP 5: EXPLOITATION
=====================
  5a. Enumerate target:
      sqlmap -u "TARGET" --technique=X --dbms=DBMS --dbs

  5b. Select target database and enumerate:
      sqlmap -u "TARGET" --technique=X --tables -D TARGET_DB

  5c. Identify high-value tables (users, credentials, sessions):
      sqlmap -u "TARGET" --technique=X --columns -D DB -T users

  5d. Extract data:
      sqlmap -u "TARGET" --technique=X --dump -D DB -T users

  5e. Escalate (if in scope):
      - File read: --file-read=/etc/passwd
      - File write: --file-write=shell.php --file-dest=/var/www/
      - OS shell: --os-shell (MySQL/PostgreSQL/MSSQL with FILE priv)
      - Priv esc: --priv-esc (via Metasploit)

STEP 6: POST-EXPLOITATION
==========================
  a. Harvest and crack credential hashes
  b. Document all findings with evidence
  c. Assess lateral movement paths
  d. Clean up test artifacts
  e. Prepare report

  -> See: skills/04_post_exploitation/
```

---

## Technique Selection Matrix

| Condition | Best Technique | Flags |
|-----------|----------------|-------|
| DB errors visible | Error-based | `--technique=E` |
| Results displayed | UNION-based | `--technique=U` |
| Boolean difference | Boolean blind | `--technique=B` |
| DNS server available | OOB/DNS | `--technique=Q --dns-domain=` |
| Stacked OK | Stacked | `--technique=S` |
| Nothing else works | Time-based | `--technique=T` |
| Unknown | All | (default, no --technique) |

---

## Speed vs Stealth Trade-offs

| Mode | Speed | Detectability | Settings |
|------|-------|---------------|---------|
| Aggressive | Fastest | Very High | `--threads=10 --level=5 --risk=3` |
| Normal | Fast | Medium | `--threads=5 --level=2 --risk=2` |
| Conservative | Medium | Low | `--threads=3 --level=1 --risk=1` |
| Stealth | Slowest | Minimal | `--threads=1 --delay=3 --random-agent` |

---

## DBMS-Specific Strategy

### MySQL
- Preferred techniques: U, E, B
- Key features: FILE privilege, UDF injection, `LOAD_FILE()`, `INTO OUTFILE`
- Version: `--banner` → check for 5.x vs 8.x
- Config: `configs/db_mysql.cfg`

### Microsoft SQL Server (MSSQL)
- Preferred techniques: E, S (stacked enables `xp_cmdshell`)
- Key features: `xp_cmdshell`, linked servers, CLR assemblies
- Must check: `sa` account, `sysadmin` role
- Config: `configs/db_mssql.cfg`

### PostgreSQL
- Preferred techniques: E, S (COPY TO/FROM PROGRAM for RCE)
- Key features: `COPY` command for file I/O, custom functions
- Config: `configs/db_postgresql.cfg`

### Oracle
- Preferred techniques: U, E
- Key features: `UTL_FILE`, `UTL_HTTP`, `DBMS_SCHEDULER`
- No stacked queries by default
- Config: `configs/db_oracle.cfg`

### SQLite
- Preferred techniques: B, U
- Limited post-exploitation (no OS access)
- Often in mobile app / local file scenarios

---

## Common Mistakes to Avoid

1. **Not specifying `--dbms`** — slows everything by 5-10x testing all databases
2. **Starting at `--level=5 --risk=3`** — creates massive traffic, triggers alerts
3. **Ignoring WAF response codes** — 403/406/429 means WAF is active, not invulnerable
4. **Skipping reconnaissance** — testing wrong parameters wastes time
5. **Using `--dump-all` blindly** — can take hours and causes server stress
6. **Not using `--batch`** — interactive prompts break automation
7. **Forgetting cookies/auth** — authenticated endpoints require session tokens
8. **Running without proxy** — lose visibility into what SQLMap is actually sending

---

## Integration with Burp Suite

Always use Burp as a proxy during testing for visibility:

```bash
# Route all sqlmap traffic through Burp
sqlmap -u "TARGET" --proxy=http://127.0.0.1:8080

# Load a captured Burp request directly
sqlmap -r burp_request.txt --batch

# Test specific parameter from captured request
sqlmap -r burp_request.txt -p "username" --batch
```

This allows you to:
- See exact payloads being sent
- Debug WAF blocks in real time
- Capture evidence for reports
- Modify requests on the fly

---

## Evidence Collection

For each finding, record:

1. **Vulnerable parameter**: URL, parameter name, HTTP method
2. **Injection technique**: Which technique worked and why
3. **DBMS version**: Full banner string
4. **Proof of concept**: Screenshot or log of injected data retrieval
5. **Impact**: What data/access was obtained
6. **sqlmap session**: `~/.local/share/sqlmap/output/TARGET/`

Session files are automatically saved and can be resumed with `--resume`.

---

## Reporting Template

```
VULNERABILITY: SQL Injection
SEVERITY: Critical/High/Medium
LOCATION: [URL] parameter [param_name]
TECHNIQUE: [Boolean/Time/Error/UNION/Stacked/OOB]
DBMS: [vendor + version]
OS: [if determined]

DESCRIPTION:
[Brief technical description]

PROOF OF CONCEPT:
sqlmap -u "[URL]" -p "[param]" --technique=[X] --dbms=[Y] --dbs

IMPACT:
- Database enumeration: [yes/no]
- Data extraction: [yes/no, tables affected]
- OS access: [yes/no]
- File system access: [yes/no]

REMEDIATION:
1. Use parameterized queries / prepared statements
2. Implement input validation and sanitization
3. Apply principle of least privilege to DB accounts
4. Enable WAF with SQL injection signatures
5. Monitor for anomalous database queries
```
