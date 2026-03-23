"""Interactive CLI for the RAG assistant.

    python -m app.cli --user dana                # employee, hardened
    python -m app.cli --user harriet             # HR, hardened
    python -m app.cli --user dana --insecure     # employee, no controls
"""
from __future__ import annotations

import argparse

from app.auth import authenticate
from app.rag import SecurityConfig, build_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Northwind Retail RAG assistant")
    parser.add_argument("--user", default="dana", choices=["dana", "harriet"])
    parser.add_argument("--insecure", action="store_true", help="disable all controls")
    parser.add_argument("--ask", help="ask one question and exit")
    args = parser.parse_args()

    config = SecurityConfig.insecure() if args.insecure else SecurityConfig()
    app, report = build_app(config=config)
    user = authenticate(args.user)

    if args.ask:
        answer = app.ask(user, args.ask)
        print(answer.text)
        return

    posture = "INSECURE (all controls off)" if args.insecure else "HARDENED"
    print(f"Northwind RAG assistant | user={user.username} role={user.role} | {posture}")
    print(f"Corpus: {report.summary()}")
    print("Type 'quit' to exit.\n")

    while True:
        try:
            question = input(f"{user.username}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if question.lower() in {"quit", "exit"}:
            break
        if not question:
            continue
        answer = app.ask(user, question)
        tag = f" [blocked: {answer.blocked_by}]" if answer.blocked_by else ""
        print(f"\nassistant>{tag}\n{answer.text}")
        print(f"\n  retrieved: {answer.retrieved}")
        print(f"  classifications: {sorted(set(answer.classifications))}\n")


if __name__ == "__main__":
    main()
