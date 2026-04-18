"""Side-by-side demo of every RAG attack, insecure vs hardened.

    python demo.py
"""
from __future__ import annotations

from app.auth import authenticate
from app.rag import SecurityConfig, build_app
from attacks.suite import SUITE

LINE = "=" * 78


def main() -> None:
    insecure, ins_report = build_app(config=SecurityConfig.insecure())
    secure, sec_report = build_app(config=SecurityConfig())

    print(LINE)
    print("Northwind Retail RAG assistant - attack demo".center(78))
    print(LINE)
    print(f"Ingestion, insecure: {ins_report.summary()}")
    print(f"Ingestion, hardened: {sec_report.summary()} "
          f"(sanitized: {sec_report.sanitized})")

    ins_hits = sec_hits = 0
    for attack in SUITE:
        user = authenticate(attack.username)
        before = insecure.ask(user, attack.question)
        after = secure.ask(user, attack.question)
        b, a = attack.succeeded(before), attack.succeeded(after)
        ins_hits += b
        sec_hits += a

        print(f"\n[{attack.id}]  {attack.name}")
        print(f"  OWASP {attack.owasp} | ATLAS {attack.atlas} | as {user.username} ({user.role})")
        print(f"  {attack.description}")
        print(f"  query> {attack.question[:100]}")
        print(f"\n  INSECURE  [{'LEAKED ' if b else 'blocked'}]  retrieved={before.retrieved}")
        print(f"            {before.text[:140].replace(chr(10), ' ')}")
        blocked = f" via {after.blocked_by}" if after.blocked_by else " via retrieval ACL"
        print(f"  HARDENED  [{'LEAKED ' if a else 'blocked'}]{blocked}  retrieved={after.retrieved}")
        print(f"            {after.text[:140].replace(chr(10), ' ')}")
        print("-" * 78)

    print(f"\nRESULT: insecure {ins_hits}/{len(SUITE)} attacks succeeded, "
          f"hardened {sec_hits}/{len(SUITE)}.")

    # Availability check - the controls must not break the product.
    dana = authenticate("dana")
    vpn = secure.ask(dana, "How do I connect to the VPN from home?")
    print(f"\nAvailability check - employee asks a normal question of the "
          f"sanitized document:\n  blocked={vpn.blocked_by} | "
          f"{vpn.text[:110].replace(chr(10), ' ')}")


if __name__ == "__main__":
    main()
