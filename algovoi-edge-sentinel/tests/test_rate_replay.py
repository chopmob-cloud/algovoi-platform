"""Rate/velocity limiting and replay/nonce/freshness — the stateful, clock-driven checks."""
from algovoi_edge_sentinel import EdgePolicy, RequestContext
from conftest import FakeClock, make_sentinel


def test_rate_limit_blocks_after_max_in_window():
    clk = FakeClock()
    s, _pk, _ = make_sentinel(policy=EdgePolicy(rate_max=2, rate_window_s=60, checks=("rate",)), clock=clk)
    assert s.evaluate(RequestContext(ip="10.0.0.1")).allowed   # 1
    assert s.evaluate(RequestContext(ip="10.0.0.1")).allowed   # 2
    r = s.evaluate(RequestContext(ip="10.0.0.1"))              # 3 > max
    assert not r.allowed and r.reason_code == "BLOCK_RATE_EXCEEDED"


def test_rate_window_slides():
    clk = FakeClock()
    s, _pk, _ = make_sentinel(policy=EdgePolicy(rate_max=1, rate_window_s=60, checks=("rate",)), clock=clk)
    assert s.evaluate(RequestContext(ip="10.0.0.1")).allowed
    assert not s.evaluate(RequestContext(ip="10.0.0.1")).allowed
    clk.advance(61)  # old hit ages out of the window
    assert s.evaluate(RequestContext(ip="10.0.0.1")).allowed


def test_rate_is_per_scope():
    clk = FakeClock()
    s, _pk, _ = make_sentinel(policy=EdgePolicy(rate_max=1, rate_window_s=60, checks=("rate",)), clock=clk)
    assert s.evaluate(RequestContext(ip="10.0.0.1")).allowed
    assert s.evaluate(RequestContext(ip="10.0.0.2")).allowed   # different IP, own counter


def test_replay_nonce_blocks_second_use():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(require_nonce=True, checks=("replay",)))
    assert s.evaluate(RequestContext(nonce="n1")).allowed
    assert s.evaluate(RequestContext(nonce="n1")).reason_code == "BLOCK_REPLAY"


def test_missing_nonce_blocked_when_required():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(require_nonce=True, checks=("replay",)))
    assert s.evaluate(RequestContext()).reason_code == "BLOCK_MISSING_NONCE"


def test_stale_timestamp_blocked():
    clk = FakeClock()
    s, _pk, _ = make_sentinel(policy=EdgePolicy(freshness_window_s=30, checks=("replay",)), clock=clk)
    fresh = clk().strftime("%Y-%m-%dT%H:%M:%SZ")
    assert s.evaluate(RequestContext(timestamp=fresh)).allowed
    stale = (clk().replace(hour=10)).strftime("%Y-%m-%dT%H:%M:%SZ")  # ~2h old
    assert s.evaluate(RequestContext(timestamp=stale)).reason_code == "BLOCK_STALE"


def test_missing_timestamp_blocked_when_freshness_required():
    """Freshness is mandatory when a window is set: omitting the timestamp must fail closed, not skip
    the check (security fix 2026-08-19)."""
    s, _pk, _ = make_sentinel(policy=EdgePolicy(freshness_window_s=30, checks=("replay",)), clock=FakeClock())
    r = s.evaluate(RequestContext())  # no timestamp supplied
    assert not r.allowed and r.reason_code == "BLOCK_MISSING_TIMESTAMP"
