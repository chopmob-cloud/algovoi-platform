"""Identity allow/deny lists."""
from algovoi_edge_sentinel import EdgePolicy, RequestContext
from conftest import make_sentinel


def test_deny_did_blocks():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(deny_dids=("did:web:evil",), checks=("identity",)))
    assert s.evaluate(RequestContext(agent_did="did:web:evil")).reason_code == "BLOCK_DID_DENIED"
    assert s.evaluate(RequestContext(agent_did="did:web:good")).allowed


def test_deny_wallet_and_key():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(
        deny_wallets=("0xbad",), deny_keys=("k-bad",), checks=("identity",)))
    assert s.evaluate(RequestContext(wallet="0xbad")).reason_code == "BLOCK_WALLET_DENIED"
    assert s.evaluate(RequestContext(key_id="k-bad")).reason_code == "BLOCK_KEY_DENIED"


def test_did_allowlist_mode():
    s, _pk, _ = make_sentinel(policy=EdgePolicy(allow_dids=("did:web:ok",), checks=("identity",)))
    assert s.evaluate(RequestContext(agent_did="did:web:ok")).allowed
    assert s.evaluate(RequestContext(agent_did="did:web:other")).reason_code == "BLOCK_DID_NOT_ALLOWLISTED"
    assert s.evaluate(RequestContext()).reason_code == "BLOCK_DID_NOT_ALLOWLISTED"  # no DID, allowlist on
