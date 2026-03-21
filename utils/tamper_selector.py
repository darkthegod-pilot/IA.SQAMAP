"""
Tamper Selector - Auto-select optimal tamper scripts based on WAF and DBMS.

Usage:
    python utils/tamper_selector.py --waf cloudflare --dbms mysql
    python utils/tamper_selector.py --waf modsecurity --dbms postgresql
    python utils/tamper_selector.py --list-wafs
"""

import argparse
import sys


WAF_TAMPER_MAP = {
    "cloudflare": {
        "all": ["space2comment", "randomcase", "charencode"],
        "mysql": ["space2comment", "randomcase", "charencode"],
        "mssql": ["space2comment", "randomcase", "charencode"],
        "postgresql": ["space2comment", "randomcase", "charencode"],
        "oracle": ["space2comment", "randomcase", "charencode"],
    },
    "modsecurity": {
        "all": ["space2comment", "randomcase", "between"],
        "mysql": ["modsecurityzeroversioned", "space2comment", "randomcase"],
        "mssql": ["space2mssqlblank", "randomcase", "between"],
        "postgresql": ["space2comment", "randomcase", "between"],
        "oracle": ["space2comment", "randomcase"],
    },
    "imperva": {
        "all": ["space2comment", "randomcase", "between", "charencode"],
        "mysql": ["space2comment", "randomcase", "between", "greatest", "charencode"],
        "mssql": ["space2mssqlblank", "randomcase", "between", "charencode"],
        "postgresql": ["space2comment", "randomcase", "between", "greatest", "charencode"],
        "oracle": ["space2comment", "randomcase", "between", "charencode"],
    },
    "f5": {
        "all": ["randomcase", "charencode", "space2randomblank"],
        "mysql": ["randomcase", "charencode", "space2randomblank"],
        "mssql": ["randomcase", "charencode", "space2mssqlblank"],
        "postgresql": ["randomcase", "charencode", "space2randomblank"],
        "oracle": ["randomcase", "charencode", "space2randomblank"],
    },
    "akamai": {
        "all": ["between", "chardoubleencode", "randomcase", "space2comment"],
        "mysql": ["between", "chardoubleencode", "randomcase", "space2comment"],
        "mssql": ["between", "chardoubleencode", "randomcase", "space2mssqlblank"],
        "postgresql": ["between", "chardoubleencode", "randomcase", "space2comment"],
        "oracle": ["between", "chardoubleencode", "randomcase"],
    },
    "sucuri": {
        "all": ["space2comment", "randomcase"],
        "mysql": ["space2comment", "randomcase"],
        "mssql": ["space2mssqlblank", "randomcase"],
        "postgresql": ["space2comment", "randomcase"],
        "oracle": ["space2comment", "randomcase"],
    },
    "barracuda": {
        "all": ["percentage", "randomcase", "space2comment"],
        "mysql": ["space2comment", "randomcase"],
        "mssql": ["percentage", "randomcase", "space2mssqlblank"],
        "postgresql": ["space2comment", "randomcase"],
        "oracle": ["space2comment", "randomcase"],
    },
    "aws": {
        "all": ["charencode", "randomcase", "between", "space2comment"],
        "mysql": ["charencode", "randomcase", "between", "space2comment"],
        "mssql": ["charencode", "randomcase", "between", "space2mssqlblank"],
        "postgresql": ["charencode", "randomcase", "between", "space2comment"],
        "oracle": ["charencode", "randomcase", "between"],
    },
    "fortinet": {
        "all": ["space2comment", "randomcase", "charencode"],
        "mysql": ["space2comment", "randomcase", "charencode"],
        "mssql": ["space2mssqlblank", "randomcase", "charencode"],
        "postgresql": ["space2comment", "randomcase", "charencode"],
        "oracle": ["space2comment", "randomcase"],
    },
    "generic": {
        "all": ["space2comment", "randomcase"],
        "mysql": ["space2comment", "randomcase"],
        "mssql": ["space2mssqlblank", "randomcase"],
        "postgresql": ["space2comment", "randomcase"],
        "oracle": ["space2comment", "randomcase"],
        "sqlite": ["space2comment", "randomcase"],
    },
}

# DBMS-incompatible tampers (will cause failures if used on wrong DBMS)
DBMS_INCOMPATIBLE = {
    "modsecurityzeroversioned": ["mssql", "postgresql", "oracle", "sqlite"],
    "modsecurityversioned": ["mssql", "postgresql", "oracle", "sqlite"],
    "versionedkeywords": ["mssql", "postgresql", "oracle", "sqlite"],
    "versionedmorekeywords": ["mssql", "postgresql", "oracle", "sqlite"],
    "halfversionedmorekeywords": ["mssql", "postgresql", "oracle", "sqlite"],
    "randomcomments": ["mssql", "postgresql", "oracle", "sqlite"],
    "space2hash": ["mssql", "postgresql", "oracle", "sqlite"],
    "space2mysqlblank": ["mssql", "postgresql", "oracle", "sqlite"],
    "space2mysqldash": ["mssql", "postgresql", "oracle", "sqlite"],
    "greatest": ["mssql", "sqlite"],
    "ifnull2ifisnull": ["mssql", "postgresql", "oracle", "sqlite"],
    "concat2concatws": ["mssql", "postgresql", "oracle", "sqlite"],
    "plus2concat": ["mssql", "postgresql", "oracle", "sqlite"],
    "space2mssqlblank": ["mysql", "postgresql", "oracle", "sqlite"],
    "space2mssqlhash": ["mysql", "postgresql", "oracle", "sqlite"],
    "plus2fnconcat": ["mysql", "postgresql", "oracle", "sqlite"],
    "percentage": ["mysql", "postgresql", "oracle", "sqlite"],
    "symboliclogical": ["mssql", "postgresql", "oracle", "sqlite"],
}


class TamperSelector:
    def __init__(self):
        self.waf_map = WAF_TAMPER_MAP
        self.incompatible = DBMS_INCOMPATIBLE

    def normalize_waf(self, waf_name):
        """Normalize WAF name to key."""
        waf_name = waf_name.lower()
        mappings = {
            "cloudflare": "cloudflare",
            "modsecurity": "modsecurity",
            "mod_security": "modsecurity",
            "imperva": "imperva",
            "incapsula": "imperva",
            "f5": "f5",
            "bigip": "f5",
            "big-ip": "f5",
            "akamai": "akamai",
            "sucuri": "sucuri",
            "barracuda": "barracuda",
            "aws": "aws",
            "awswaf": "aws",
            "fortinet": "fortinet",
            "fortiweb": "fortinet",
        }
        return mappings.get(waf_name, "generic")

    def normalize_dbms(self, dbms_name):
        """Normalize DBMS name to key."""
        dbms_name = dbms_name.lower()
        mappings = {
            "mysql": "mysql",
            "mariadb": "mysql",
            "mssql": "mssql",
            "sqlserver": "mssql",
            "sql server": "mssql",
            "microsoft sql server": "mssql",
            "postgresql": "postgresql",
            "postgres": "postgresql",
            "oracle": "oracle",
            "sqlite": "sqlite",
        }
        return mappings.get(dbms_name, "all")

    def validate_tampers(self, tampers, dbms):
        """Remove DBMS-incompatible tampers."""
        validated = []
        removed = []

        for tamper in tampers:
            incompatible_dbs = self.incompatible.get(tamper, [])
            if dbms in incompatible_dbs:
                removed.append(tamper)
            else:
                validated.append(tamper)

        return validated, removed

    def select(self, waf, dbms="all", verbose=False):
        """Select optimal tampers for given WAF and DBMS combination."""
        waf_key = self.normalize_waf(waf)
        dbms_key = self.normalize_dbms(dbms)

        if waf_key not in self.waf_map:
            waf_key = "generic"

        waf_profiles = self.waf_map[waf_key]
        tampers = waf_profiles.get(dbms_key, waf_profiles.get("all", []))

        validated, removed = self.validate_tampers(tampers, dbms_key)

        if verbose and removed:
            print(f"[!] Removed incompatible tampers for {dbms}: {', '.join(removed)}")

        return validated

    def build_chain(self, waf, dbms="all", level="standard"):
        """Build a complete tamper chain string."""
        tampers = self.select(waf, dbms, verbose=True)

        if level == "light":
            tampers = tampers[:2]
        elif level == "heavy" and len(tampers) < 4:
            tampers.extend(["charencode", "between"])
            tampers = list(dict.fromkeys(tampers))  # Remove duplicates

        return ",".join(tampers)

    def list_wafs(self):
        """List all supported WAFs."""
        return list(self.waf_map.keys())


def main():
    parser = argparse.ArgumentParser(
        description="Select optimal SQLMap tamper scripts for WAF bypass"
    )
    parser.add_argument("--waf", help="WAF vendor name (e.g., cloudflare, modsecurity)")
    parser.add_argument("--dbms", default="all", help="Database type (mysql, mssql, postgresql, oracle)")
    parser.add_argument("--level", choices=["light", "standard", "heavy"],
                        default="standard", help="Evasion aggressiveness level")
    parser.add_argument("--list-wafs", action="store_true", help="List supported WAFs")
    parser.add_argument("--command", help="Target URL for full command generation")
    args = parser.parse_args()

    selector = TamperSelector()

    if args.list_wafs:
        print("Supported WAFs:")
        for waf in selector.list_wafs():
            print(f"  - {waf}")
        return

    if not args.waf:
        parser.print_help()
        sys.exit(1)

    chain = selector.build_chain(args.waf, args.dbms, args.level)

    print(f"\nWAF: {args.waf}")
    print(f"DBMS: {args.dbms}")
    print(f"Level: {args.level}")
    print(f"\nTamper chain: {chain}")

    if args.command:
        print(f"\nFull SQLMap command:")
        print(f'  sqlmap -u "{args.command}" \\')
        print(f'    --tamper={chain} \\')
        if args.dbms != "all":
            print(f'    --dbms={args.dbms} \\')
        print(f'    --random-agent \\')
        print(f'    --delay=2 \\')
        print(f'    --batch')


if __name__ == "__main__":
    main()
