"""Local loopback entry point for the management-only application."""

import argparse
import os


def valid_port(value):
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        choices=("127.0.0.1", "::1"),
        default="127.0.0.1",
        help="Loopback address to bind (default: 127.0.0.1)",
    )
    parser.add_argument("--port", type=valid_port, default=8080)
    parser.add_argument(
        "--database",
        default=os.getenv("MONOLITH_DATABASE", "monolith_supreme.db"),
        help="SQLite database file (default: monolith_supreme.db)",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    from cyberapp.management_app import create_management_app

    app = create_management_app(config={"DATABASE": args.database})
    print(f"MONOLITH management mode: http://{args.host}:{args.port}")
    print("Operational modules are not loaded in this mode.")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
