"""Abstract base class for network payment verifiers."""
from abc import ABC, abstractmethod
from algovoi_settlement_verify.schemas import NetworkEnum, PaymentPayload, VerifyResult


class BaseVerifier(ABC):
    @abstractmethod
    async def verify(self, payload: PaymentPayload) -> VerifyResult:
        """Verify that a payment transaction is valid and confirms the correct amount."""
        ...

    @abstractmethod
    async def verify_authority_tx(self, tx_id: str, network: NetworkEnum) -> VerifyResult:
        """Confirm a tx is mined/confirmed on-chain without checking amount or receiver.

        Used by the MPP subscription activation reaper to validate standing
        authority txs (ERC-20 approve, SPL Approve, Soroban approve, etc.).
        """
        ...

    @abstractmethod
    async def health(self) -> bool:
        """Return True if the upstream node is reachable."""
        ...
