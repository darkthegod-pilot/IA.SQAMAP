"""
Output Parser - Parse SQLMap output logs into structured findings.

Usage:
    python utils/output_parser.py --input ~/.local/share/sqlmap/output/target.com/log
    python utils/output_parser.py --input log.txt --format json
    python utils/output_parser.py --session ~/.local/share/sqlmap/output/target.com/session.sqlite
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class InjectionPoint:
    parameter: str
    param_type: str  # GET, POST, Cookie, Header
    techniques: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    dbms: Optional[str] = None


@dataclass
class DatabaseFinding:
    databases: List[str] = field(default_factory=list)
    current_db: Optional[str] = None
    current_user: Optional[str] = None
    is_dba: bool = False
    tables: dict = field(default_factory=dict)  # db -> [table, ...]
    columns: dict = field(default_factory=dict)  # db.table -> [col, ...]
    credentials: List[dict] = field(default_factory=list)


@dataclass
class SQLMapFinding:
    target_url: str
    dbms: Optional[str] = None
    os_info: Optional[str] = None
    web_tech: Optional[str] = None
    injection_points: List[InjectionPoint] = field(default_factory=list)
    db_info: DatabaseFinding = field(default_factory=DatabaseFinding)
    file_reads: List[str] = field(default_factory=list)
    os_commands: List[str] = field(default_factory=list)
    severity: str = "unknown"


class OutputParser:
    """Parse SQLMap log files and session databases into structured findings."""

    # Patterns for log parsing
    PATTERNS = {
        "target_url": re.compile(r"\[\*\] testing URL '(.+?)'"),
        "dbms": re.compile(r"back-end DBMS: (.+?)(?:\s+\(|\n|$)"),
        "os_info": re.compile(r"web server operating system: (.+)"),
        "web_tech": re.compile(r"web application technology: (.+)"),
        "is_dba": re.compile(r"the current user is DBA"),
        "current_user": re.compile(r"current user: '(.+?)'"),
        "current_db": re.compile(r"current database: '(.+?)'"),
        "injection_found": re.compile(
            r"Parameter: (.+?) \((.+?)\)\n.+?Type: (.+?)\n.+?Title: (.+?)\n.+?Payload: (.+?)(?:\n\n|$)",
            re.DOTALL
        ),
        "database_list": re.compile(r"\[\*\] (.+?)(?:\n|$)"),
        "file_read": re.compile(r"reading file '(.+?)'"),
        "os_cmd": re.compile(r"os-shell> (.+?)(?:\n|$)"),
        "cracked_password": re.compile(r"password '(.+?)' for user '(.+?)'"),
    }

    def parse_log(self, log_path):
        """Parse a SQLMap log file."""
        if not os.path.exists(log_path):
            print(f"[!] Log file not found: {log_path}")
            return None

        with open(log_path, "r", errors="ignore") as f:
            content = f.read()

        finding = SQLMapFinding(target_url="unknown")

        # Extract target URL
        url_match = re.search(r"testing URL '(.+?)'", content)
        if url_match:
            finding.target_url = url_match.group(1)

        # Extract DBMS
        dbms_match = re.search(r"back-end DBMS: (.+?)(?:\s*\(|\n)", content)
        if dbms_match:
            finding.dbms = dbms_match.group(1).strip()

        # Extract OS info
        os_match = re.search(r"web server operating system: (.+)", content)
        if os_match:
            finding.os_info = os_match.group(1).strip()

        # Extract web technology
        tech_match = re.search(r"web application technology: (.+)", content)
        if tech_match:
            finding.web_tech = tech_match.group(1).strip()

        # Check if DBA
        if "current user is DBA" in content:
            finding.db_info.is_dba = True

        # Extract current user
        user_match = re.search(r"current user: '(.+?)'", content)
        if user_match:
            finding.db_info.current_user = user_match.group(1)

        # Extract current database
        db_match = re.search(r"current database: '(.+?)'", content)
        if db_match:
            finding.db_info.current_db = db_match.group(1)

        # Extract injection points
        inj_pattern = re.compile(
            r"Parameter: (.+?) \((.+?)\)\n\s+Type: (.+?)\n",
            re.MULTILINE
        )
        for match in inj_pattern.finditer(content):
            param = match.group(1).strip()
            param_type = match.group(2).strip()
            technique = match.group(3).strip()

            # Find existing injection point or create new
            existing = next((ip for ip in finding.injection_points
                             if ip.parameter == param), None)
            if existing:
                existing.techniques.append(technique)
            else:
                finding.injection_points.append(InjectionPoint(
                    parameter=param,
                    param_type=param_type,
                    techniques=[technique]
                ))

        # Extract databases
        db_section = re.search(r"available databases \[\d+\]:(.*?)(?:\[\*\]|\Z)",
                                content, re.DOTALL)
        if db_section:
            dbs = re.findall(r"\[\*\] (.+)", db_section.group(1))
            finding.db_info.databases = [d.strip() for d in dbs]

        # Extract cracked passwords
        cred_pattern = re.compile(r"password '(.+?)' (?:for (?:hash|user) '(.+?)')?")
        for match in cred_pattern.finditer(content):
            finding.db_info.credentials.append({
                "password": match.group(1),
                "hash": match.group(2) or "unknown"
            })

        # Determine severity
        finding.severity = self._calculate_severity(finding)

        return finding

    def parse_session(self, session_path):
        """Parse SQLMap session SQLite database."""
        if not os.path.exists(session_path):
            print(f"[!] Session file not found: {session_path}")
            return None

        try:
            conn = sqlite3.connect(session_path)
            cursor = conn.cursor()

            # Get table list
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            data = {}
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 100")
                    cols = [desc[0] for desc in cursor.description]
                    rows = cursor.fetchall()
                    data[table] = [dict(zip(cols, row)) for row in rows]
                except Exception:
                    pass

            conn.close()
            return data

        except sqlite3.Error as e:
            print(f"[!] Session parse error: {e}")
            return None

    def _calculate_severity(self, finding):
        """Calculate finding severity based on capabilities."""
        if finding.db_info.is_dba:
            return "critical"
        if finding.injection_points:
            techniques = []
            for ip in finding.injection_points:
                techniques.extend(ip.techniques)
            if any("UNION" in t or "error" in t.lower() for t in techniques):
                return "high"
            return "medium"
        return "low"

    def to_json(self, finding):
        """Convert finding to JSON string."""
        return json.dumps(asdict(finding), indent=2, default=str)

    def to_report(self, finding):
        """Generate human-readable report."""
        lines = []
        lines.append("=" * 60)
        lines.append("SQLMap Finding Report")
        lines.append("=" * 60)
        lines.append(f"Target: {finding.target_url}")
        lines.append(f"DBMS: {finding.dbms or 'Unknown'}")
        lines.append(f"OS: {finding.os_info or 'Unknown'}")
        lines.append(f"Technology: {finding.web_tech or 'Unknown'}")
        lines.append(f"Severity: {finding.severity.upper()}")
        lines.append("")

        if finding.injection_points:
            lines.append(f"Injection Points ({len(finding.injection_points)}):")
            for ip in finding.injection_points:
                lines.append(f"  - {ip.parameter} ({ip.param_type})")
                lines.append(f"    Techniques: {', '.join(ip.techniques)}")
        else:
            lines.append("No injection points found.")

        lines.append("")
        lines.append("Database Info:")
        lines.append(f"  Current User: {finding.db_info.current_user or 'Unknown'}")
        lines.append(f"  Current DB: {finding.db_info.current_db or 'Unknown'}")
        lines.append(f"  Is DBA: {finding.db_info.is_dba}")

        if finding.db_info.databases:
            lines.append(f"  Databases ({len(finding.db_info.databases)}):")
            for db in finding.db_info.databases:
                lines.append(f"    - {db}")

        if finding.db_info.credentials:
            lines.append(f"\nCracked Credentials ({len(finding.db_info.credentials)}):")
            for cred in finding.db_info.credentials:
                lines.append(f"  Hash: {cred['hash']} -> Password: {cred['password']}")

        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Parse SQLMap output files")
    parser.add_argument("--input", help="SQLMap log file path")
    parser.add_argument("--session", help="SQLMap session SQLite file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--output", help="Output file (default: stdout)")
    args = parser.parse_args()

    if not args.input and not args.session:
        parser.print_help()
        sys.exit(1)

    parser_obj = OutputParser()
    output = ""

    if args.input:
        finding = parser_obj.parse_log(args.input)
        if finding:
            if args.format == "json":
                output = parser_obj.to_json(finding)
            else:
                output = parser_obj.to_report(finding)

    if args.session:
        data = parser_obj.parse_session(args.session)
        if data:
            output += "\n\nSession Data:\n"
            output += json.dumps(data, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"[+] Output written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
