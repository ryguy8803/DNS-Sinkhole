"""Minimal demo client: sends a DNS query directly to localhost:8053."""

import argparse
import socket
import struct


def query_name(domain: str) -> bytes:
    result = bytearray()
    for label in domain.rstrip(".").split("."):
        raw = label.encode("idna")
        result += bytes([len(raw)]) + raw
    return bytes(result) + b"\0"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("domain")
    parser.add_argument("--type", choices=("A", "AAAA"), default="A")
    parser.add_argument("--port", type=int, default=8053)
    args = parser.parse_args()
    qtype = 1 if args.type == "A" else 28
    packet = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + query_name(args.domain) + struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(packet, ("127.0.0.1", args.port))
        response, address = sock.recvfrom(4096)
    flags = struct.unpack("!H", response[2:4])[0]
    print(f"Received {len(response)} bytes from {address[0]}:{address[1]}; rcode={flags & 0xF}, answers={struct.unpack('!H', response[6:8])[0]}")
    print("For a blocked A query, the answer section contains 0.0.0.0.")


if __name__ == "__main__":
    main()
