import socket
import struct
import threading

from src.server import LocalDNSServer
from test_dns_protocol import make_query


def test_blocked_domain(tmp_path):
    (tmp_path / "blacklist.json").write_text('{"blocked_domains": ["blocked.test"]}', encoding="utf-8")
    server = LocalDNSServer(tmp_path / "blacklist.json", tmp_path / "log.jsonl")
    response = server.handle_datagram(make_query("blocked.test"))
    assert b"\x00\x00\x00\x00" in response
    assert server.logger.stats()["blocked"] == 1


def test_allowed_domain_is_forwarded_to_fake_upstream(tmp_path):
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    address = upstream.getsockname()

    def fake_resolver():
        packet, client = upstream.recvfrom(4096)
        upstream.sendto(packet[:2] + b"\x81\x80" + packet[4:6] + b"\x00\x00\x00\x00\x00\x00" + packet[12:], client)

    thread = threading.Thread(target=fake_resolver, daemon=True)
    thread.start()
    server = LocalDNSServer(tmp_path / "missing.json", tmp_path / "log.jsonl", upstream=address)
    response = server.handle_datagram(make_query("allowed.test"), upstream_socket=upstream)
    upstream.close()
    thread.join(timeout=1)
    assert response[:2] == b"\xca\xfe"
    assert server.logger.stats()["forwarded"] == 1


def test_malformed_packet_gets_formerr(tmp_path):
    server = LocalDNSServer(tmp_path / "missing.json", tmp_path / "log.jsonl")
    response = server.handle_datagram(b"\x12\x34")
    assert response[:2] == b"\x12\x34"
    assert response[3] & 0x0F == 1
