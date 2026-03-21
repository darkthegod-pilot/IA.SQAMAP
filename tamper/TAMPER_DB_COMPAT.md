# Tamper Script Database Compatibility

> Which tamper scripts work with which database systems.
> Using incompatible tampers causes injection failures.

---

## Compatibility Matrix

| Tamper Script | MySQL | MSSQL | PostgreSQL | Oracle | SQLite |
|--------------|-------|-------|------------|--------|--------|
| `apostrophemask` | YES | YES | YES | YES | YES |
| `apostrophenullencode` | YES | YES | YES | YES | YES |
| `appendnullbyte` | YES | YES | YES | YES | YES |
| `base64encode` | YES | YES | YES | YES | YES |
| `between` | YES | YES | YES | YES | YES |
| `charencode` | YES | YES | YES | YES | YES |
| `chardoubleencode` | YES | YES | YES | YES | YES |
| `charunicodeencode` | YES | YES | NO | NO | NO |
| `commentbeforeparentheses` | YES | YES | YES | YES | YES |
| `concat2concatws` | YES | NO | NO | NO | NO |
| `equaltolike` | YES | YES | YES | YES | YES |
| `greatest` | YES | NO | YES | YES | NO |
| `halfversionedmorekeywords` | YES | NO | NO | NO | NO |
| `htmlencode` | YES | YES | YES | YES | YES |
| `ifnull2ifisnull` | YES | NO | NO | NO | NO |
| `ifnull2nullif` | YES | NO | NO | YES | NO |
| `least` | YES | NO | YES | YES | NO |
| `modsecurityversioned` | YES | NO | NO | NO | NO |
| `modsecurityzeroversioned` | YES | NO | NO | NO | NO |
| `multiplespaces` | YES | YES | YES | YES | YES |
| `nonrecursivereplacement` | YES | YES | YES | YES | YES |
| `overlongutf8` | YES | YES | YES | YES | YES |
| `percentage` | NO | YES | NO | NO | NO |
| `plus2concat` | YES | NO | NO | NO | NO |
| `plus2fnconcat` | NO | YES | NO | NO | NO |
| `randomcase` | YES | YES | YES | YES | YES |
| `randomcomments` | YES | NO | NO | NO | NO |
| `space2comment` | YES | YES | YES | YES | YES |
| `space2dash` | YES | YES | YES | YES | YES |
| `space2hash` | YES | NO | NO | NO | NO |
| `space2mssqlblank` | NO | YES | NO | NO | NO |
| `space2mssqlhash` | NO | YES | NO | NO | NO |
| `space2mysqlblank` | YES | NO | NO | NO | NO |
| `space2mysqldash` | YES | NO | NO | NO | NO |
| `space2plus` | YES | YES | YES | YES | YES |
| `space2randomblank` | YES | YES | YES | YES | YES |
| `symboliclogical` | YES | NO | NO | NO | NO |
| `unionalltounion` | YES | YES | YES | YES | YES |
| `uppercase` | YES | YES | YES | YES | YES |
| `versionedkeywords` | YES | NO | NO | NO | NO |
| `versionedmorekeywords` | YES | NO | NO | NO | NO |

---

## Recommended Chains by DBMS

### MySQL / MariaDB
```bash
# Conservative
--tamper=space2comment,randomcase

# Moderate
--tamper=space2comment,randomcase,greatest,modsecurityzeroversioned

# Aggressive
--tamper=space2comment,randomcase,between,greatest,modsecurityzeroversioned,versionedkeywords,charencode
```

### Microsoft SQL Server (MSSQL)
```bash
# Conservative
--tamper=space2comment,randomcase

# Moderate
--tamper=space2mssqlblank,randomcase,between,charencode

# Aggressive
--tamper=space2mssqlblank,randomcase,between,charencode,chardoubleencode,percentage
```

### PostgreSQL
```bash
# Conservative
--tamper=space2comment,randomcase

# Moderate
--tamper=space2comment,randomcase,between,charencode

# Aggressive
--tamper=space2comment,randomcase,between,greatest,charencode,chardoubleencode
```

### Oracle
```bash
# Conservative
--tamper=space2comment,randomcase

# Moderate
--tamper=space2comment,randomcase,between,charencode

# Note: Fewer MySQL-specific tampers available
```

---

## Common Mistakes

### Using MySQL-Only Tampers on MSSQL
```bash
# WRONG: modsecurityzeroversioned is MySQL only
sqlmap -u "TARGET" --dbms=mssql --tamper=modsecurityzeroversioned  # Will fail!

# CORRECT for MSSQL:
sqlmap -u "TARGET" --dbms=mssql --tamper=space2mssqlblank,randomcase
```

### Using MSSQL-Only Tampers on MySQL
```bash
# WRONG: percentage is MSSQL only
sqlmap -u "TARGET" --dbms=mysql --tamper=percentage  # May cause syntax errors

# CORRECT for MySQL:
sqlmap -u "TARGET" --dbms=mysql --tamper=space2comment,randomcase
```

### Conflicting Space Tampers
```bash
# WRONG: Multiple space replacement tampers
--tamper=space2comment,space2hash,space2plus  # Conflict!

# CORRECT: Pick one space replacement
--tamper=space2comment,randomcase
```
