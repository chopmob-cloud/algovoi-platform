# Test fixtures

## `tsa_freetsa_response.der` / `.json`

A **real** RFC 3161 `TimeStampResp` obtained from `https://freetsa.org/tsr` on 2026-07-21,
covering the retention-chain head recorded in the `.json` metadata.

It is deliberately a real token rather than a synthetic one. A hand-built fixture would only
prove the parser agrees with itself; this proves it agrees with a TSA that has no idea we
exist.

**Do not regenerate casually.** The token is immutable evidence and the tests pin its serial,
policy OID, `genTime` and signature algorithm. If it ever must be replaced:

```
cd substrate2
python - <<'PY'
import json, pathlib
from substrate2 import timestamp as ts
from substrate2.retention_chain import retention_chain_ref

chain_ref = retention_chain_ref(prev_receipt_hash="sha256:"+"a"*64,
                                receipt_hash="sha256:"+"b"*64,
                                chain_seq=7, issuer_id="did:web:algovoi.co.uk")
req, nonce = ts.timestamp_request(chain_ref)
der = ts.fetch_timestamp("https://freetsa.org/tsr", req, timeout=25)
res = ts.verify_timestamp_token(der, expected_digest=chain_ref, nonce=nonce)
assert res.valid, res.failure_reason
t = res.token
pathlib.Path("tests/fixtures/tsa_freetsa_response.der").write_bytes(der)
pathlib.Path("tests/fixtures/tsa_freetsa_response.json").write_text(json.dumps({
    "tsa_url": "https://freetsa.org/tsr", "obtained_utc": "<today>",
    "covers_chain_ref": chain_ref, "chain_seq": 7, "issuer_id": "did:web:algovoi.co.uk",
    "request_nonce": nonce, "serial": t.serial, "policy_oid": t.policy_oid,
    "gen_time_ms": t.gen_time_ms, "signature_alg": t.signature_alg,
    "tsa_name": t.tsa_name, "bytes": len(der)}, indent=2) + "\n",
    encoding="utf-8", newline="")
PY
```

The `chain_ref` inputs must not change: `tests/test_timestamp.py` recomputes the head from
them and asserts it still matches the token, so that a change to `retention_chain_ref` fails
loudly instead of silently invalidating every timestamp ever issued.
