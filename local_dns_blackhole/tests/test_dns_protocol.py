import struct

import pytest

from src.dns_protocol import DNSFormatError, build_block_response, parse_query


def make_query(domain="example.test", qtype=1):
    encoded = b"".join(bytes([len(part)]) + part.encode() for part in domain.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0xCAFE, 0x0100, 1, 0, 0, 0) + encoded + struct.pack("!HH", qtype, 1)


def test_parse_domain_and_type():
    query = parse_query(make_query("www.example.test", 28))
    assert query.domain == "www.example.test"
    assert query.qtype == 28
    assert query.transaction_id == 0xCAFE


def test_malformed_packet_is_rejected():
    with pytest.raises(DNSFormatError):
        parse_query(b"\x00\x01")


def test_block_response_contains_zero_address():
    query = parse_query(make_query())
    response = build_block_response(query)
    assert b"\x00\x00\x00\x00" in response
