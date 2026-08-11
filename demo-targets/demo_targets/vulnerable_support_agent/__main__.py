"""Run the vulnerable support agent.

    python -m demo_targets.vulnerable_support_agent            # vulnerable (default)
    AGENTSHIELD_DEMO_SECURE=1 python -m demo_targets.vulnerable_support_agent   # hardened
"""

from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Intentionally vulnerable support agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument(
        "--secure",
        action="store_true",
        help="run the hardened variant used for the post-fix regression run",
    )
    args = parser.parse_args()

    import uvicorn

    from demo_targets.vulnerable_support_agent.app import create_app, secure_from_env

    # Resolved once, then used for both the banner and the app that is actually served. The
    # flag beats the environment; the environment is how the container image selects a mode.
    hardened = args.secure or secure_from_env()

    # Built here and handed to uvicorn as an object, never as an import string. A string makes
    # uvicorn import the module and take whatever `app` it finds, which is decided by import
    # order, never by anything on this line.
    application = create_app(secure=hardened)

    print(
        f"ACME Support Assistant [{'SECURE' if hardened else 'VULNERABLE'}] "
        f"on http://{args.host}:{args.port}"
    )
    print(
        "This target is the hardened build; every attack should be refused."
        if hardened
        else "This target is intentionally insecure. All side effects are mocked."
    )
    uvicorn.run(application, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
