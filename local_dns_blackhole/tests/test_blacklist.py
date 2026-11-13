import json

from src.blacklist import Blacklist


def test_configuration_loading_and_subdomain_matching(tmp_path):
    path = tmp_path / "blacklist.json"
    path.write_text(json.dumps({"blocked_domains": ["Bad.Example"]}), encoding="utf-8")
    blacklist = Blacklist(path)
    assert blacklist.is_blocked("bad.example.")
    assert blacklist.is_blocked("www.bad.example")
    assert not blacklist.is_blocked("bad-example")


def test_add_and_remove_persist(tmp_path):
    path = tmp_path / "blacklist.json"
    blacklist = Blacklist(path)
    assert blacklist.add("ads.test")
    assert Blacklist(path).is_blocked("ads.test")
    assert Blacklist(path).remove("ads.test")
    assert not Blacklist(path).is_blocked("ads.test")


def test_hostname_keyword_rule(tmp_path):
    path = tmp_path / "blacklist.json"
    path.write_text(json.dumps({"blocked_domains": [], "blocked_keywords": ["proxy"]}), encoding="utf-8")
    blacklist = Blacklist(path)
    assert blacklist.is_blocked("free-proxy.example")
    assert not blacklist.is_blocked("games.example")
