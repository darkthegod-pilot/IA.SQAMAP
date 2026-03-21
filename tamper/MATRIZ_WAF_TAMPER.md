# Matriz WAF × Tamper — Vlad Volkov

## Referência Rápida

| WAF | MySQL | MSSQL | PostgreSQL | Oracle |
|-----|-------|-------|-----------|--------|
| Cloudflare | space2comment,randomcase,charencode | space2comment,randomcase,charencode | space2comment,randomcase,charencode | space2comment,randomcase,charencode |
| ModSecurity | modsecurityzeroversioned,space2comment,randomcase | space2mssqlblank,randomcase,between | space2comment,randomcase,between | space2comment,randomcase |
| Imperva | space2comment,randomcase,between,greatest,charencode | space2mssqlblank,randomcase,between,charencode | space2comment,randomcase,between,greatest,charencode | space2comment,randomcase,between,charencode |
| F5 BIG-IP | randomcase,charencode,space2randomblank | randomcase,charencode,space2mssqlblank | randomcase,charencode,space2randomblank | randomcase,charencode,space2randomblank |
| Akamai | between,chardoubleencode,randomcase,space2comment | between,chardoubleencode,randomcase,space2mssqlblank | between,chardoubleencode,randomcase,space2comment | between,chardoubleencode,randomcase |
| Sucuri | space2comment,randomcase | space2mssqlblank,randomcase | space2comment,randomcase | space2comment,randomcase |
| AWS WAF | charencode,randomcase,between,space2comment | charencode,randomcase,between,space2mssqlblank | charencode,randomcase,between,space2comment | charencode,randomcase,between |
| Barracuda | space2comment,randomcase | percentage,randomcase,space2mssqlblank | space2comment,randomcase | space2comment,randomcase |
| Fortinet | space2comment,randomcase,charencode | space2mssqlblank,randomcase,charencode | space2comment,randomcase,charencode | space2comment,randomcase |

## Tampers por Descrição

| Tamper | Transforma | Compatibilidade |
|--------|-----------|----------------|
| `space2comment` | `espaço` → `/**/` | Todos os DBMS |
| `randomcase` | `select` → `sElEcT` | Todos os DBMS |
| `charencode` | `A` → `%41` | Todos os DBMS |
| `chardoubleencode` | `A` → `%2541` | Todos os DBMS |
| `between` | `>` → `NOT BETWEEN 0 AND` | Todos exceto SQLite |
| `greatest` | `>` → `GREATEST()` | MySQL, PostgreSQL |
| `modsecurityzeroversioned` | `UNION` → `/*!00000UNION*/` | MySQL ONLY |
| `space2mssqlblank` | `espaço` → chars alternativos | MSSQL ONLY |
| `space2randomblank` | `espaço` → char aleatório | Todos |
| `percentage` | `SELECT` → `S%E%L%E%C%T` | MSSQL ONLY |
| `apostrophemask` | `'` → `%EF%BC%87` | Todos |
| `equaltolike` | `=` → `LIKE` | MySQL, MSSQL |
| `base64encode` | payload → base64 | Todos (raro) |

## Uso Rápido

```bash
# Selecionar automaticamente
python vlad.py tamper --waf cloudflare --dbms mysql

# Output: --tamper=space2comment,randomcase,charencode
```
