"""x402 payment verification Pydantic models."""
import re
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

# Algorand / Voi formats
_ALGO_TX_RE   = re.compile(r"^[A-Z2-7]{52,64}$")
_ALGO_ADDR_RE = re.compile(r"^[A-Z2-7]{58}$")

# Hedera formats
# TX ID submitted by payer wallet: 0.0.ACCT@SECONDS.NANOSECONDS
# Mirror Node also accepts hyphens:  0.0.ACCT-SECONDS-NANOSECONDS
_HEDERA_TX_RE   = re.compile(r"^0\.\d+\.\d+[@-]\d+[\.\-]\d+$")
_HEDERA_ADDR_RE = re.compile(r"^0\.\d+\.\d+$")   # shard.realm.account

# Stellar formats
# Transaction hashes are 64 lowercase hex chars; addresses are 56-char base32 starting with G.
_STELLAR_TX_RE   = re.compile(r"^[a-f0-9]{64}$")
_STELLAR_ADDR_RE = re.compile(r"^G[A-Z2-7]{55}$")

# Base / EVM formats
# TX hash: 0x + 64 hex chars. Address: 0x + 40 hex chars (checksum or lowercase).
_EVM_TX_RE   = re.compile(r"^0x[0-9a-fA-F]{64}$")
_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Solana formats (base58: 1-9, A-Z excl I/O, a-z excl l)
# TX signature: 87-88 chars. Address (pubkey): 32-44 chars.
_SOLANA_TX_RE   = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{87,88}$")
_SOLANA_ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


class NetworkEnum(str, Enum):
    algorand_mainnet = "algorand_mainnet"
    algorand_testnet = "algorand_testnet"
    voi_mainnet      = "voi_mainnet"
    voi_testnet      = "voi_testnet"
    hedera_mainnet   = "hedera_mainnet"
    hedera_testnet   = "hedera_testnet"
    stellar_mainnet  = "stellar_mainnet"
    stellar_testnet  = "stellar_testnet"
    base_mainnet     = "base_mainnet"
    base_sepolia     = "base_sepolia"
    solana_mainnet   = "solana_mainnet"
    solana_devnet    = "solana_devnet"
    tempo_mainnet    = "tempo_mainnet"
    tempo_testnet    = "tempo_testnet"
    arc_mainnet      = "arc_mainnet"
    arc_testnet      = "arc_testnet"


class ExpectedFeeLeg(BaseModel):
    """
    Platform take-rate fee leg expected alongside the merchant payment leg
    in an atomic group (Billing V1 Phase B3+).

    When present on a PaymentPayload, the settlement verifier MUST confirm
    that the on-chain transaction identified by tx_id belongs to a group
    that also contains a sibling transfer to `wallet` of at least
    `amount_microunits` in the same asset as the main payment. If any part
    of that check fails the whole verification fails — the merchant cannot
    settle without paying the platform fee.

    The fee is always in the same asset/denomination as the merchant leg.
    Cross-asset fees are out of scope for V1.
    """

    model_config = {"extra": "forbid"}

    wallet: str = Field(
        ...,
        min_length=5,
        max_length=60,
        description="Chain-specific operator wallet address (base32 for Algo/VOI/Stellar, account id for Hedera).",
    )
    amount_microunits: int = Field(..., ge=0)


class PaymentPayload(BaseModel):
    model_config = {"extra": "forbid"}

    # When True, only confirms the tx is mined/confirmed on-chain — skips
    # amount/receiver validation. Used by the MPP subscription activation
    # reaper to verify standing authority txs (approve/allowance).
    verify_authority: bool = False

    network: NetworkEnum
    tx_id: str = Field(..., min_length=10, max_length=100, description="Transaction ID")
    # Defaults relaxed to allow authority mode (0 / "") — model_validator
    # enforces >0 / non-empty for standard payment verification.
    expected_amount_microalgos: int = Field(0, ge=0)
    expected_receiver: str = Field(
        "", min_length=0, max_length=60, description="Algorand/Voi address or Hedera account ID"
    )
    # Optional caller-supplied correlation IDs (echoed for the caller's own
    # bookkeeping; not used by on-chain verification). Required by the AlgoVoi
    # platform; optional in the standalone SDK.
    resource_id: str = ""  # caller correlation id (e.g. order/resource ref)
    tenant_id: str = ""    # caller correlation id (e.g. account ref)
    # Note binding: if set, the on-chain tx note (base64-decoded) must match
    # this value EXACTLY (after strip()).  The name "prefix" is a historical
    # artefact — all verifiers enforce strict equality, not a prefix check, to
    # prevent crafted memos like "algovoi:tokenA_extra" from colliding.
    # Populated by the gateway when note_binding_required=True on the
    # ResourceDefinition.  None means no note check.
    expected_note_prefix: str | None = None  # semantics: exact-match (see verifiers)
    expected_asset_id: int | str | None = Field(
        None,
        description=(
            "Token identifier for non-native asset payments. "
            "Algorand/VOI: integer ASA ID. Hedera: integer token num. "
            "Stellar: string in 'CODE:ISSUER' format (e.g. 'USDC:GA5ZS...'). "
            "None/omit for native ALGO/VOI/HBAR/XLM."
        ),
    )
    # Billing V1 Phase B3+: platform fee leg expected in the same atomic
    # group/multi-output transaction. None = no fee (trial, grandfathered,
    # or enforcement flag off on the gateway). When set, the verifier
    # enforces atomic multi-output semantics per chain.
    expected_fee: ExpectedFeeLeg | None = None

    # Solana Pay `reference` pubkey (Migration 079).
    # When set (Solana checkouts only), the verifier MUST confirm the tx
    # includes this pubkey as a non-signer account. This is the Solana-native
    # equivalent of the memo/note binding used on other chains — it
    # cryptographically binds the settling tx to a specific checkout.
    # Base58, 32–44 chars. Ignored on non-Solana networks.
    expected_reference_pubkey: str | None = Field(
        None,
        min_length=32,
        max_length=44,
        description=(
            "Solana Pay reference pubkey (base58). When set, the verifier "
            "requires this pubkey to appear in the tx's account keys. "
            "Used only on solana_mainnet / solana_devnet."
        ),
    )

    @model_validator(mode="after")
    def validate_network_formats(self) -> "PaymentPayload":
        """Validate tx_id and expected_receiver format based on the selected network."""
        # Authority mode: only the tx_id format matters; skip amount/receiver checks.
        if self.verify_authority:
            return self

        if self.expected_amount_microalgos <= 0:
            raise ValueError("expected_amount_microalgos must be > 0 for payment verification")
        if len(self.expected_receiver) < 5:
            raise ValueError("expected_receiver is required for payment verification")

        is_hedera  = self.network in (NetworkEnum.hedera_mainnet, NetworkEnum.hedera_testnet)
        is_stellar = self.network in (NetworkEnum.stellar_mainnet, NetworkEnum.stellar_testnet)
        is_evm     = self.network in (NetworkEnum.base_mainnet, NetworkEnum.base_sepolia,
                                      NetworkEnum.tempo_mainnet, NetworkEnum.tempo_testnet,
                                      NetworkEnum.arc_mainnet, NetworkEnum.arc_testnet)
        is_solana  = self.network in (NetworkEnum.solana_mainnet, NetworkEnum.solana_devnet)

        if is_solana:
            if not _SOLANA_TX_RE.match(self.tx_id):
                raise ValueError(
                    "For Solana networks, tx_id must be a base58 signature (87-88 chars) "
                    f"(got: {self.tx_id!r})"
                )
            if not _SOLANA_ADDR_RE.match(self.expected_receiver):
                raise ValueError(
                    "For Solana networks, expected_receiver must be a base58 public key (32-44 chars) "
                    f"(got: {self.expected_receiver!r})"
                )
        elif is_hedera:
            if not _HEDERA_TX_RE.match(self.tx_id):
                raise ValueError(
                    "For hedera_mainnet, tx_id must be in format 0.0.ACCOUNT@SECONDS.NANOSECONDS "
                    f"(got: {self.tx_id!r})"
                )
            if not _HEDERA_ADDR_RE.match(self.expected_receiver):
                raise ValueError(
                    "For hedera_mainnet, expected_receiver must be a Hedera account ID "
                    f"(e.g. 0.0.12345, got: {self.expected_receiver!r})"
                )
        elif is_stellar:
            if not _STELLAR_TX_RE.match(self.tx_id):
                raise ValueError(
                    "For stellar networks, tx_id must be 64 lowercase hex chars "
                    f"(got: {self.tx_id!r})"
                )
            if not _STELLAR_ADDR_RE.match(self.expected_receiver):
                raise ValueError(
                    "For stellar networks, expected_receiver must be a Stellar public key "
                    f"(G... 56 chars, got: {self.expected_receiver!r})"
                )
        elif is_evm:
            if not _EVM_TX_RE.match(self.tx_id):
                raise ValueError(
                    "For EVM networks (Base, Tempo), tx_id must be 0x + 64 hex chars "
                    f"(got: {self.tx_id!r})"
                )
            if not _EVM_ADDR_RE.match(self.expected_receiver):
                raise ValueError(
                    "For EVM networks (Base, Tempo), expected_receiver must be 0x + 40 hex chars "
                    f"(got: {self.expected_receiver!r})"
                )
        else:
            # Algorand / Voi validation
            if not _ALGO_TX_RE.match(self.tx_id):
                raise ValueError(
                    "tx_id must be a valid Algorand/Voi transaction ID (uppercase base32: A-Z, 2-7)"
                )
            if not _ALGO_ADDR_RE.match(self.expected_receiver):
                raise ValueError(
                    "expected_receiver must be a valid Algorand/Voi address (uppercase base32: A-Z, 2-7)"
                )

        return self


class VerifyResult(BaseModel):
    model_config = {"extra": "forbid"}

    verified: bool
    tx_id: str
    network: NetworkEnum
    confirmed_amount: int | None = None  # microunits, None if not verified
    # Round/block in which the transaction was confirmed. Populated by verifiers
    # that already fetch it (Algorand/Voi confirmed-round); None elsewhere.
    # Downstream consumers use it to anchor state-proof evidence capture.
    confirmed_round: int | None = None
    error: str | None = None  # Generic error only -- never expose node internals
