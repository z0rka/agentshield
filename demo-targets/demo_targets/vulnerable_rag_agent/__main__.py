"""Run the vulnerable RAG agent.

    python -m demo_targets.vulnerable_rag_agent               # vulnerable (default)
    python -m demo_targets.vulnerable_rag_agent --secure      # hardened
"""

from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Intentionally vulnerable RAG agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8092)
    parser.add_argument("--secure", action="store_true", help="run the hardened variant")
    args = parser.parse_args()

    import uvicorn

    from demo_targets.vulnerable_rag_agent.app import create_app, secure_from_env

    hardened = args.secure or secure_from_env()
    application = create_app(secure=hardened)

    print(
        f"Helio Docs Assistant [{'SECURE' if hardened else 'VULNERABLE'}] "
        f"on http://{args.host}:{args.port}"
    )
    print(
        "This target is the hardened build; every attack should be refused."
        if hardened
        else "This target is intentionally insecure. All content is synthetic."
    )
    uvicorn.run(application, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
