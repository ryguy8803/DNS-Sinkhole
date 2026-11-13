"""Small, deliberately focused DNS wire-format helpers.

DNS messages begin with a 12-byte header. A question contains a label-encoded
name followed by QTYPE and QCLASS. This module parses exactly one question,
which keeps the educational server understandable while still handling normal
client lookups.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


class DNSFormatError(ValueError):
    """Raised when a packet is too short or uses unsupported DNS encoding."""


@dataclass(frozen=True)
class DNSQuery:
    transaction_id: int
    flags: int
    question_end: int
    domain: str
    qtype: int
    qclass: int


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    original_offset = offset
    jumped = False
    visited: set[int] = set()
    while True:
        if offset >= len(packet):
            raise DNSFormatError("name extends beyond packet")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in visited:
                raise DNSFormatError("compression pointer loop")
            visited.add(pointer)
            if len(visited) > 20:
                raise DNSFormatError("too many compression pointers")
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            continue
        if length & 0xC0:
            raise DNSFormatError("invalid label length bits")
        offset += 1
        if length == 0:
            return ".".join(labels), (original_offset if jumped else offset)
        if length > 63 or offset + length > len(packet):
            raise DNSFormatError("invalid label")
        label = packet[offset : offset + length]
        if any(byte < 32 or byte > 126 for byte in label):
            raise DNSFormatError("non-printable label")
        labels.append(label.decode("ascii"))
        offset += length


def parse_query(packet: bytes) -> DNSQuery:
    if len(packet) < 12:
        raise DNSFormatError("DNS header is incomplete")
    transaction_id, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if qdcount != 1:
        raise DNSFormatError("exactly one question is required")
    domain, end = _read_name(packet, 12)
    if end + 4 > len(packet):
        raise DNSFormatError("question is incomplete")
    qtype, qclass = struct.unpack("!HH", packet[end : end + 4])
    if not domain:
        raise DNSFormatError("root-only queries are not supported")
    return DNSQuery(transaction_id, flags, end + 4, domain, qtype, qclass)


def _name_bytes(domain: str) -> bytes:
    labels = domain.rstrip(".").split(".")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("idna")
        if not 1 <= len(raw) <= 63:
            raise DNSFormatError("domain label is too long")
        encoded.extend((len(raw),))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def _response_header(query: DNSQuery, answer_count: int, rcode: int = 0) -> bytes:
    # QR marks a response; copy RD so clients can correlate recursive intent.
    flags = 0x8000 | (query.flags & 0x0100) | (rcode & 0x000F)
    return struct.pack("!HHHHHH", query.transaction_id, flags, 1, answer_count, 0, 0)


def build_block_response(query: DNSQuery) -> bytes:
    if query.qtype not in (1, 28):
        # Preserve the question section even when this educational server has
        # no synthetic answer for the requested record type.
        return _response_header(query, 0, rcode=0) + _name_bytes(query.domain) + struct.pack("!HH", query.qtype, query.qclass)
    address = b"\x00\x00\x00\x00" if query.qtype == 1 else b"\x00" * 16
    rr = b"\xc0\x0c" + struct.pack("!HHIH", query.qtype, query.qclass, 60, len(address)) + address
    return _response_header(query, 1) + _name_bytes(query.domain) + struct.pack("!HH", query.qtype, query.qclass) + rr


def build_error_response(packet: bytes, rcode: int = 1) -> bytes:
    transaction_id = struct.unpack("!H", packet[:2])[0] if len(packet) >= 2 else 0
    return struct.pack("!HHHHHH", transaction_id, 0x8000 | (rcode & 0xF), 0, 0, 0, 0)
