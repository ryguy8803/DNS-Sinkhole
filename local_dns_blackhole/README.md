# Local DNS Black Hole

A small Python DNS sinkhole for learning defensive networking. It listens only on `127.0.0.1:8053`, blocks domains from a JSON blacklist, and forwards allowed DNS requests to an upstream resolver. It does not change router settings, system DNS settings, or network devices.

## Build and run

Steps to install and run the software:

1. Install Python 3.10 or newer.
2. From this project folder, run `python -m src.cli start`.
3. Leave the server running and open a second terminal.
4. Test a blocked domain with `python demo_client.py coolmathgames.com`.
5. Test an allowed domain with `python demo_client.py example.com`.

The default port is `8053` because Windows commonly uses port `5353` for mDNS. No administrator privileges are required.

## Commands

Manage blocked domains with the CLI:

```text
python -m src.cli add example-blocked.test
python -m src.cli remove example-blocked.test
python -m src.cli list
python -m src.cli logs
python -m src.cli stats
```

The blacklist is stored in `data/blacklist.json`. Exact domains, subdomains, and configured hostname keywords can be blocked. The sample keyword `proxy` blocks hostnames containing that word.

To query the server with other tools:

```text
dig @127.0.0.1 -p 8053 coolmathgames.com A
nslookup -port=8053 coolmathgames.com 127.0.0.1
```

The included `demo_client.py` is the most reliable Windows demonstration because some versions of `nslookup` handle custom ports inconsistently.

## Tests

Install the test dependency and run the automated tests:

```text
python -m pip install -r requirements.txt
python -m pytest -q
```

The tests cover blacklist loading, keyword matching, DNS parsing, blocked responses, allowed-domain forwarding through a fake local resolver, and malformed packets.

## Implementation notes

The server uses Python UDP sockets. It parses the DNS transaction ID, flags, domain name, record type, and record class from each request.

Blocked `A` queries receive `0.0.0.0`. Blocked `AAAA` queries receive `::`. Allowed requests are sent unchanged to the upstream resolver, normally `1.1.1.1:53`, and the response is returned to the local client.

Each request is written to `logs/requests.jsonl` with a UTC timestamp, domain, query type, action, and response time.

This is intentionally a compact educational server rather than a complete recursive DNS resolver. It supports one question per packet, does not cache responses, and does not perform DNSSEC validation. It is designed for direct demonstrations using `127.0.0.1:8053`; Chrome and other applications will not use it unless their DNS traffic is separately configured to do so.

## Safety notes

This is an educational defensive networking tool. It binds only to loopback, never scans networks, does not collect personal data, and does not modify router or operating-system DNS settings. Do not change the bind address to expose it to a network.

## Learning sources

* [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)
* [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034)
* [Python socket documentation](https://docs.python.org/3/library/socket.html)
* [Python struct documentation](https://docs.python.org/3/library/struct.html)

## Future Work

The following items could improve the project in the future:

* [ ] Add response caching and TTL handling.
* [ ] Support more DNS record types and multiple questions.
* [ ] Add a simple local dashboard for logs and statistics.
* [ ] Add a configurable upstream timeout and resolver list.
* [ ] Improve Windows-friendly demo output and error messages.
