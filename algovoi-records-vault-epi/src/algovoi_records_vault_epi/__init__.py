"""algovoi-records-vault-epi — the AlgoVoi Records Vault `.epi` portable-evidence export add-on.

Commercial add-on to Records Vault. Exports a Records Vault evidence set as a portable `.epi` artifact
(the AlgoVoi PQC / Falcon-1024 profile of the `.epi` compliance-evidence format), and bundles a
redistributable offline verifier (``algovoi_records_vault_epi/verifier/``) that a buyer may pass to
their auditors / counterparties to verify a `.epi` artifact independently.

Licensed product — see LICENSE.md. Runtime licence enforced, fail-closed.
"""
from algovoi_records_vault_epi.profile import (
    SCHEMA,
    SUITE,
    build_steps,
    control_mapping_for,
    export_epi,
)

__all__ = ["export_epi", "build_steps", "control_mapping_for", "SCHEMA", "SUITE"]
__version__ = "0.1.1"
