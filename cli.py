"""
Password Strength Analyzer - Command Line Interface

Run interactively or pass a password as an argument:
    python cli.py
    python cli.py "mypassword"
"""

import getpass
import sys

from password_analyzer import (
    analyze_password,
    suggest_passphrase,
    suggest_strong_password,
)


def _print_result(password: str, result):
    print(f"Password:         {password}")
    print(f"Strength:         {result.label} ({result.score}/100)")
    print(f"Entropy:          {result.entropy} bits")
    print(f"Est. crack time:  {result.crack_time}")
    print("Brute-force scenarios:")
    if result.brute_force:
        for scenario, time in result.brute_force["scenarios"].items():
            print(f"  - {scenario}: {time}")
    print("Checks:")
    for c in result.checks:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  - [{c['name']}] {status} ({c['score']}/{c['max']}) {c['message']}")
    print("Suggestions:")
    for s in result.suggestions:
        print(f"  - {s}")


def interactive():
    password = getpass.getpass("Enter a password to analyse (hidden input): ")
    result = analyze_password(password)

    print("\n" + "=" * 60)
    print("PASSWORD STRENGTH REPORT")
    print("=" * 60)
    _print_result(password, result)
    print("\nStrong alternative: " + suggest_strong_password())
    print("Passphrase idea:    " + suggest_passphrase())


def main():
    if len(sys.argv) > 1:
        password = sys.argv[1]
        _print_result(password, analyze_password(password))
    else:
        interactive()


if __name__ == "__main__":
    main()