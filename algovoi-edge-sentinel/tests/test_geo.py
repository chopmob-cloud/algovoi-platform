"""IP / geo / ASN blocking."""
from algovoi_edge_sentinel import EdgePolicy, RequestContext
from algovoi_edge_sentinel.geo import InMemoryGeoProvider
from conftest import make_sentinel

GEO = InMemoryGeoProvider([
    {"cidr": "203.0.113.0/24", "country": "KP", "asn": 64500},
    {"cidr": "198.51.100.0/24", "country": "US", "asn": 64501},
    {"cidr": "192.0.2.0/24", "country": "GB", "asn": 64502},
])


def test_deny_country_blocks():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    r = s.evaluate(RequestContext(ip="203.0.113.5"))
    assert not r.allowed and r.reason_code == "BLOCK_GEO_COUNTRY" and r.check == "geo"


def test_allowed_country_passes():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    assert s.evaluate(RequestContext(ip="198.51.100.10")).allowed


def test_deny_asn_blocks():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_asns=(64501,)), geo=GEO)
    assert s.evaluate(RequestContext(ip="198.51.100.10")).reason_code == "BLOCK_GEO_ASN"


def test_deny_cidr_blocks():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_cidrs=("192.0.2.0/24",)), geo=GEO)
    assert s.evaluate(RequestContext(ip="192.0.2.7")).reason_code == "BLOCK_IP_CIDR"


def test_allow_cidr_bypasses_country_deny():
    s, _pk, _ = make_sentinel(
        policy=EdgePolicy(deny_countries=("KP",), allow_cidrs=("203.0.113.0/24",)), geo=GEO)
    assert s.evaluate(RequestContext(ip="203.0.113.5")).allowed  # trusted IP bypasses geo


def test_allowlist_mode_blocks_other_countries():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(allow_countries=("GB", "US")), geo=GEO)
    assert s.evaluate(RequestContext(ip="203.0.113.5")).reason_code == "BLOCK_GEO_NOT_ALLOWLISTED"
    assert s.evaluate(RequestContext(ip="192.0.2.7")).allowed


def test_no_ip_no_block():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    assert s.evaluate(RequestContext()).allowed  # no signal -> cannot block


def test_client_asserted_country_cannot_override_provider():
    """A configured geo provider is authoritative: an attacker on a KP IP claiming country=US is still
    blocked (security fix 2026-08-19)."""
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_countries=("KP",)), geo=GEO)
    r = s.evaluate(RequestContext(ip="203.0.113.5", country="US"))
    assert not r.allowed and r.reason_code == "BLOCK_GEO_COUNTRY"


def test_client_asserted_country_cannot_disable_asn_denylist():
    """Supplying only a country used to null the asn and skip the ASN deny-list; the provider still
    resolves the real ASN (security fix 2026-08-19)."""
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_asns=(64500,)), geo=GEO)
    r = s.evaluate(RequestContext(ip="203.0.113.5", country="US"))
    assert not r.allowed and r.reason_code == "BLOCK_GEO_ASN"
