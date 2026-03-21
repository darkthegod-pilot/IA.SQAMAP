"""
Technique Advisor - Recommend optimal SQL injection technique based on observable behavior.

Usage:
    python utils/technique_advisor.py --interactive
    python utils/technique_advisor.py --errors --displays-results
"""

import argparse


class TechniqueAdvisor:
    """
    Advises on the optimal SQLMap injection technique based on application behavior.

    Technique codes:
        B - Boolean-based blind
        T - Time-based blind
        E - Error-based
        U - UNION query-based
        S - Stacked queries
        Q - Out-of-band (DNS)
    """

    def advise(self, shows_errors=False, displays_results=False,
               boolean_difference=False, dns_control=False,
               stacked_supported=False, is_slow_network=False):
        """
        Return recommended techniques with reasoning.

        Args:
            shows_errors: App displays DB error messages
            displays_results: App outputs query results directly
            boolean_difference: Response differs for true/false conditions
            dns_control: Tester has control over a DNS server
            stacked_supported: App supports multi-statement SQL (semicolon)
            is_slow_network: Network has high latency/variable timing

        Returns:
            List of (technique_code, technique_name, reasoning, speed) tuples
        """
        recommendations = []

        if shows_errors:
            recommendations.append((
                "E",
                "Error-Based",
                "DB error messages visible in response - data embedded in errors",
                "fast"
            ))

        if displays_results:
            recommendations.append((
                "U",
                "UNION Query-Based",
                "Application outputs query results - UNION appends rows to output",
                "fastest"
            ))

        if boolean_difference:
            recommendations.append((
                "B",
                "Boolean-Based Blind",
                "Response differs for true/false - extract data character by character",
                "medium"
            ))

        if dns_control:
            recommendations.append((
                "Q",
                "Out-of-Band (DNS)",
                "DNS server control enables 30x faster extraction than time-based",
                "fast"
            ))

        if stacked_supported:
            recommendations.append((
                "S",
                "Stacked Queries",
                "Multi-statement support enables write operations and OS commands",
                "medium"
            ))

        if is_slow_network:
            # Remove time-based from recommendations if network is slow
            recommendations = [(c, n, r, s) for c, n, r, s in recommendations
                                if c != "T"]

        # Time-based is always last resort
        if not recommendations or all(r[0] == "S" for r in recommendations):
            recommendations.append((
                "T",
                "Time-Based Blind",
                "Last resort - works on any injectable parameter by measuring delays",
                "slowest"
            ))

        return recommendations

    def get_technique_flags(self, technique_codes):
        """Return SQLMap flags for selected techniques."""
        code_str = "".join(technique_codes)
        return f"--technique={code_str}"

    def format_recommendation(self, recommendations):
        """Format recommendations as human-readable text."""
        lines = ["\n[+] RECOMMENDED INJECTION TECHNIQUES:"]
        lines.append("=" * 50)

        for i, (code, name, reasoning, speed) in enumerate(recommendations, 1):
            lines.append(f"\n{i}. {name} (code: {code}) [{speed.upper()}]")
            lines.append(f"   Reason: {reasoning}")

        if recommendations:
            best_codes = [r[0] for r in recommendations]
            flags = self.get_technique_flags(best_codes)
            lines.append(f"\n[*] SQLMap flag: {flags}")

        return "\n".join(lines)

    def interactive_wizard(self):
        """Interactive wizard to determine best technique."""
        print("\n=== SQLMap Technique Advisor ===")
        print("Answer these questions about the target application:\n")

        def ask(question):
            while True:
                answer = input(f"  {question} [y/N]: ").strip().lower()
                if answer in ("y", "yes"):
                    return True
                if answer in ("n", "no", ""):
                    return False
                print("  Please answer y or n")

        shows_errors = ask("Does the application display database error messages?")
        displays_results = ask("Does the application display query results (e.g., product list, user data)?")
        boolean_difference = ask("Does the response differ noticeably between true/false conditions?")
        dns_control = ask("Do you control a DNS server/domain for out-of-band exfiltration?")
        stacked_supported = ask("Does the application support multiple SQL statements (stacked queries)?")
        is_slow_network = ask("Is the network connection slow or unreliable (high latency)?")

        recommendations = self.advise(
            shows_errors=shows_errors,
            displays_results=displays_results,
            boolean_difference=boolean_difference,
            dns_control=dns_control,
            stacked_supported=stacked_supported,
            is_slow_network=is_slow_network
        )

        print(self.format_recommendation(recommendations))
        return recommendations


def main():
    parser = argparse.ArgumentParser(
        description="Recommend optimal SQLMap injection technique based on app behavior"
    )
    parser.add_argument("--interactive", action="store_true",
                        help="Interactive wizard mode")
    parser.add_argument("--errors", action="store_true",
                        help="App displays DB errors")
    parser.add_argument("--displays-results", action="store_true",
                        help="App displays query results")
    parser.add_argument("--boolean-diff", action="store_true",
                        help="Response differs for true/false")
    parser.add_argument("--dns-control", action="store_true",
                        help="You control a DNS server")
    parser.add_argument("--stacked", action="store_true",
                        help="Stacked queries supported")
    parser.add_argument("--slow-network", action="store_true",
                        help="Network has high latency")
    args = parser.parse_args()

    advisor = TechniqueAdvisor()

    if args.interactive:
        advisor.interactive_wizard()
        return

    recommendations = advisor.advise(
        shows_errors=args.errors,
        displays_results=args.displays_results,
        boolean_difference=args.boolean_diff,
        dns_control=args.dns_control,
        stacked_supported=args.stacked,
        is_slow_network=args.slow_network
    )

    print(advisor.format_recommendation(recommendations))


if __name__ == "__main__":
    main()
