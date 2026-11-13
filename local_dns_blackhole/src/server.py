"""Local-only UDP DNS sinkhole server."""

from __future__ import annotations

import socket
import time
from pathlib import Path

from .blacklist import Blacklist
from .dns_protocol import DNSFormatError, build_block_response, build_error_response, parse_query
from .logger import RequestLogger

TYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 33: "SRV"}


class LocalDNSServer:
    def __init__(self, blacklist_path: str | Path, log_path: str | Path, host: str = "127.0.0.1", port: int = 8053,
                 upstream: tuple[str, int] = ("1.1.1.1", 53), timeout: float = 2.0):
        if host != "127.0.0.1":
            raise ValueError("Safety requirement: server must bind to 127.0.0.1")
        if not 1024 < port < 65536:
            raise ValueError("Port must be above 1024")
        self.host, self.port, self.upstream, self.timeout = host, port, upstream, timeout
        self.blacklist = Blacklist(blacklist_path)
        self.logger = RequestLogger(log_path)
        self.socket: socket.socket | None = None
        self.running = False

    def handle_datagram(self, packet: bytes, upstream_socket: socket.socket | None = None) -> bytes:
        started = time.perf_counter()
        try:
            query = parse_query(packet)
        except DNSFormatError:
            response = build_error_response(packet, rcode=1)  # FORMERR: the packet could not be parsed.
            self.logger.record("<malformed>", "UNKNOWN", "error", (time.perf_counter() - started) * 1000)
            return response

        qtype_name = TYPE_NAMES.get(query.qtype, f"TYPE{query.qtype}")
        try:
            blocked = self.blacklist.is_blocked(query.domain)
        except ValueError:
            blocked = True
        if blocked:
            response = build_block_response(query)
            self.logger.record(query.domain, qtype_name, "blocked", (time.perf_counter() - started) * 1000)
            return response

        forward_socket = upstream_socket
        owns_socket = forward_socket is None
        try:
            if forward_socket is None:
                forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                forward_socket.settimeout(self.timeout)
            forward_socket.sendto(packet, self.upstream)
            response, _ = forward_socket.recvfrom(4096)
            self.logger.record(query.domain, qtype_name, "forwarded", (time.perf_counter() - started) * 1000)
            return response
        except (OSError, socket.timeout):
            self.logger.record(query.domain, qtype_name, "error", (time.perf_counter() - started) * 1000)
            return build_error_response(packet, rcode=2)  # SERVFAIL: upstream did not answer safely.
        finally:
            if owns_socket and forward_socket is not None:
                forward_socket.close()

    def serve_forever(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(1.0)
        self.socket.bind((self.host, self.port))
        self.running = True
        print(f"Local DNS Black Hole listening on {self.host}:{self.port}; upstream={self.upstream[0]}:{self.upstream[1]}")
        try:
            while self.running:
                try:
                    packet, client = self.socket.recvfrom(4096)
                except socket.timeout:
                    continue
                response = self.handle_datagram(packet)
                self.socket.sendto(response, client)
        finally:
            self.stop()

    def stop(self) -> None:
        self.running = False
        if self.socket is not None:
            self.socket.close()
            self.socket = None
