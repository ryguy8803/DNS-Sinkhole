"""Command-line interface for the educational sinkhole."""

from __future__ import annotations

import argparse
from pathlib import Path

from .blacklist import Blacklist
from .logger import RequestLogger
from .server import LocalDNSServer

ROOT = Path(__file__).resolve().parents[1]
BLACKLIST = ROOT / "data" / "blacklist.json"
LOG = ROOT / "logs" / "requests.jsonl"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local DNS Black Hole: defensive, localhost-only DNS learning tool")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start", help="start the UDP server")
    start.add_argument("--upstream", default="1.1.1.1", help="upstream DNS IPv4 address")
    start.add_argument("--port", type=int, default=8053)
    add = sub.add_parser("add", help="block a domain and its subdomains")
    add.add_argument("domain")
    remove = sub.add_parser("remove", help="remove a blocked domain")
    remove.add_argument("domain")
    sub.add_parser("list", help="list blocked domains")
    logs = sub.add_parser("logs", help="display recent JSONL request logs")
    logs.add_argument("--limit", type=int, default=20)
    sub.add_parser("stats", help="display request counts")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "start":
        server = LocalDNSServer(BLACKLIST, LOG, port=args.port, upstream=(args.upstream, 53))
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down gracefully.")
            server.stop()
        return 0
    blacklist = Blacklist(BLACKLIST)
    if args.command == "add":
        print(("Added" if blacklist.add(args.domain) else "Already present") + f": {args.domain}")
    elif args.command == "remove":
        print(("Removed" if blacklist.remove(args.domain) else "Not present") + f": {args.domain}")
    elif args.command == "list":
        print("\n".join(sorted(blacklist.domains)) or "(blacklist is empty)")
    elif args.command == "logs":
        for entry in RequestLogger(LOG).entries()[-args.limit :]:
            print(entry)
    elif args.command == "stats":
        print(RequestLogger(LOG).stats())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
