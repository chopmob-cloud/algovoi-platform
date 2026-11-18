# Changelog

## 0.1.2
- Service launches via a uvicorn factory (`create_app`). Importing the module no longer has a side
  effect, so it stays importable for tests and tooling without a licence; the boot-time licence gate is
  unchanged and still fail-closed.

## 0.1.1
- Runtime licence gate: fail-closed OEM enforcement, included free for any valid AlgoVoi suite licence
  (no separate Recovery Vault purchase). With no licence at all, the appliance refuses to boot.

## 0.1.0
- Sealed, client-deployed key-recovery appliance for the AlgoVoi Verifiable Archive. Keys encrypted at
  rest (scrypt over the unlock secret + AES-256-GCM); Shamir k-of-n threshold recovery; optional
  sub-threshold assisted-AlgoVoi share (inert alone, `disable` / `resplit` any time). The crypto and
  custody modules are Nuitka-compiled to native `.so` in the image, so no readable source ships.
