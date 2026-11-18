# algovoi-command-center-totp

TOTP (RFC 6238) authenticator-app second factor for the AlgoVoi Compliance Command Center.

Install it and the console offers TOTP, with no configuration:

```bash
pip install algovoi-command-center-totp
```

The console discovers the add-on through the `algovoi_command_center.auth_factors` entry point. A user
enrolls from the console's Security page by scanning the `otpauth://` URI into an authenticator app
(Google Authenticator, Authy, 1Password, and so on) and confirming a code. From then on, that user's
sign-in requires the code (opt-in, then required).

The TOTP maths is standard-library; enrollment QR rendering uses `segno` (pure-Python, no network). No
external services, fully offline and air-gap friendly. This package stores no secrets; the console
persists the shared secret in its own account store.

Commercial add-on to the AlgoVoi Compliance Command Center. **Licence-gated, fail-closed**: it enforces
a valid AlgoVoi suite licence at load time exactly as the rest of the suite does (offline, Falcon-1024
verified). Inside a licensed Command Center it works with no configuration; without a valid licence the
console simply does not offer TOTP. Not for redistribution.
