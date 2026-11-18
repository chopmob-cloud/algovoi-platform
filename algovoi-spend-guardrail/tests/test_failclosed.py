"""Cap B: fail-closed revocation. A commercial gate denies when it cannot confirm not-revoked."""
from __future__ import annotations

import pytest

from algovoi_agent_passport import InMemoryStore as PStore, PassportIssuer, signing
from algovoi_payment_mandate import InMemoryStore as MStore, MandateIssuer

from algovoi_spend_guardrail import Policy, SpendGuardrail

USDC = 1_000_000


class ErroringPStore(PStore):
    """Inserts work (so a passport can be issued); the revocation lookup is unreachable."""
    async def get(self, **kwargs):
        raise RuntimeError("revocation store down")


class ErroringMStore(MStore):
    async def get(self, **kwargs):
        raise RuntimeError("revocation store down")


def _gate(*, pstore, mstore, strict):
    ppk, psk = signing.generate_keypair()
    mpk, msk = signing.generate_keypair()
    gpk, gsk = signing.generate_keypair()
    pi = PassportIssuer(secret_key=psk, public_key=ppk, store=pstore, issuer_did="did:web:pi")
    mi = MandateIssuer(secret_key=msk, public_key=mpk, store=mstore, issuer_did="did:web:mi")
    g = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mi, decision_secret_key=gsk,
                       decision_public_key=gpk, policy=Policy(), passport_store=pstore,
                       guardrail_did="did:web:guard", strict_revocation=strict)
    return g, pi, mi


async def _issue(pi, mi, *, payee="merchant:acme"):
    cred = (await pi.issue(agent_did="did:web:agent", scopes=["payments.send"]))["credential"]
    mandate = (await mi.issue(payer="acct:alice", payee=payee, max_amount=50 * USDC, period="month"))["mandate"]
    return cred, mandate


@pytest.mark.asyncio
async def test_passport_store_unreachable_denies_when_strict():
    g, pi, mi = _gate(pstore=ErroringPStore(), mstore=MStore(), strict=True)
    cred, mandate = await _issue(pi, mi)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    assert not d.allowed
    assert d.reasons == ["passport:REVOCATION_UNAVAILABLE"]


@pytest.mark.asyncio
async def test_passport_store_unreachable_allows_when_not_strict():
    g, pi, mi = _gate(pstore=ErroringPStore(), mstore=MStore(), strict=False)
    cred, mandate = await _issue(pi, mi)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    assert d.allowed  # signature + expiry hold; lite/open behaviour fails open


@pytest.mark.asyncio
async def test_mandate_store_unreachable_denies_when_strict():
    g, pi, mi = _gate(pstore=PStore(), mstore=ErroringMStore(), strict=True)
    cred, mandate = await _issue(pi, mi)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    assert not d.allowed
    assert d.reasons == ["mandate:REVOCATION_UNAVAILABLE"]


@pytest.mark.asyncio
async def test_default_gate_is_strict():
    # No strict kwarg -> commercial default is fail-closed.
    ppk, psk = signing.generate_keypair()
    mpk, msk = signing.generate_keypair()
    gpk, gsk = signing.generate_keypair()
    mi = MandateIssuer(secret_key=msk, public_key=mpk, store=MStore(), issuer_did="did:web:mi")
    g = SpendGuardrail(passport_public_key=ppk, mandate_issuer=mi, decision_secret_key=gsk,
                       decision_public_key=gpk, passport_store=ErroringPStore())
    assert g.strict_revocation is True
    pi = PassportIssuer(secret_key=psk, public_key=ppk, store=g.passport_store, issuer_did="did:web:pi")
    cred, mandate = await _issue(pi, mi)
    d = await g.authorize(passport_credential=cred, mandate=mandate, charge_id="c1",
                          amount=1 * USDC, payee="merchant:acme")
    assert not d.allowed and d.reasons == ["passport:REVOCATION_UNAVAILABLE"]
