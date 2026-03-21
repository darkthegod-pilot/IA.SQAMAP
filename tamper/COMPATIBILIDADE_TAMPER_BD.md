# Compatibilidade Tamper × Banco de Dados

## Matriz de Compatibilidade

| Tamper | MySQL | MSSQL | PostgreSQL | Oracle | SQLite |
|--------|-------|-------|-----------|--------|--------|
| space2comment | ✓ | ✓ | ✓ | ✓ | ✓ |
| randomcase | ✓ | ✓ | ✓ | ✓ | ✓ |
| charencode | ✓ | ✓ | ✓ | ✓ | ✓ |
| chardoubleencode | ✓ | ✓ | ✓ | ✓ | ✓ |
| between | ✓ | ✓ | ✓ | ✓ | ✗ |
| greatest | ✓ | ✗ | ✓ | ✓ | ✗ |
| modsecurityzeroversioned | ✓ | ✗ | ✗ | ✗ | ✗ |
| modsecurityversioned | ✓ | ✗ | ✗ | ✗ | ✗ |
| versionedkeywords | ✓ | ✗ | ✗ | ✗ | ✗ |
| halfversionedmorekeywords | ✓ | ✗ | ✗ | ✗ | ✗ |
| randomcomments | ✓ | ✗ | ✗ | ✗ | ✗ |
| space2hash | ✓ | ✗ | ✗ | ✗ | ✗ |
| space2mysqlblank | ✓ | ✗ | ✗ | ✗ | ✗ |
| space2mssqlblank | ✗ | ✓ | ✗ | ✗ | ✗ |
| space2mssqlhash | ✗ | ✓ | ✗ | ✗ | ✗ |
| percentage | ✗ | ✓ | ✗ | ✗ | ✗ |
| ifnull2ifisnull | ✓ | ✗ | ✗ | ✗ | ✗ |
| concat2concatws | ✓ | ✗ | ✗ | ✗ | ✗ |
| symboliclogical | ✓ | ✗ | ✗ | ✗ | ✗ |
| space2randomblank | ✓ | ✓ | ✓ | ✓ | ✓ |
| apostrophemask | ✓ | ✓ | ✓ | ✓ | ✓ |
| equaltolike | ✓ | ✓ | ✗ | ✗ | ✗ |
| base64encode | ✓ | ✓ | ✓ | ✓ | ✓ |

## Regra Prática

- **Tampers universais** (use com qualquer DBMS): space2comment, randomcase, charencode, chardoubleencode, space2randomblank, apostrophemask
- **MySQL ONLY**: modsecurityzeroversioned, modsecurityversioned, versionedkeywords, space2hash, space2mysqlblank, halfversionedmorekeywords
- **MSSQL ONLY**: space2mssqlblank, space2mssqlhash, percentage
- **MySQL + PostgreSQL**: greatest, ifnull2ifisnull, concat2concatws

## Verificação Automática

O `SeletorTamper` remove automaticamente tampers incompatíveis:

```python
from utils.seletor_tamper import SeletorTamper
seletor = SeletorTamper()
# Remove tampers incompatíveis com o DBMS especificado
tampers = seletor.selecionar("cloudflare", "mssql", verboso=True)
```
