# algovoi-command-center-scim

SCIM 2.0 (RFC 7643 / 7644) auto-provisioning for the **AlgoVoi Compliance Command Center**.

A commercial, licence-gated add-on. Install it and the console mounts a `/scim/v2` endpoint that an
identity provider (Okta, Azure AD, OneLogin) uses to provision and deprovision console accounts, and to
map its groups onto the console's fixed RBAC roles. Every change is written to the console's signed,
tamper-evident audit chain, so provisioning is itself compliance evidence.

## How it works

- **Discovery, no config.** The console finds this package through the
  `algovoi_command_center.provisioning` entry point. `pip install algovoi-command-center-scim` and the
  SCIM endpoint appears; nothing else to wire up.
- **No parallel identity model.** A SCIM User *is* a console account in the existing store; a SCIM Group
  *is* one of the four fixed roles (`admin`, `compliance_officer`, `auditor`, `viewer`). This package
  adds no new role or group concept.
- **Separate bearer auth.** The SCIM endpoint authenticates with a dedicated bearer token
  (`Authorization: Bearer ...`), independent of human sign-in. The console supplies and rotates it via
  `COMMAND_CENTER_SCIM_TOKEN` (or a `0600` file in the data dir), the same pattern as its
  service-registration token.
- **Soft deprovision.** `DELETE /Users/{id}` deactivates the account (`active=false`); it is never a hard
  delete. A deactivated account can no longer sign in, and the account plus its audit history are retained
  as evidence.
- **Licence-gated, fail-closed.** Without a valid AlgoVoi suite licence the endpoint is not mounted at
  all. A suite `bundle_license` unlocks it, exactly like the TOTP add-on.

## Endpoints

`/scim/v2/Users` — GET (list + `eq` filter on `userName` / `emails.value` / `active` / `externalId`),
GET/{id}, POST, PUT, PATCH, DELETE (soft-deactivate).

`/scim/v2/Groups` — GET, GET/{id}, POST (idempotent for the four fixed roles), PATCH (add/remove/replace
members), DELETE (rejected: role groups are fixed).

`/scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes` — discovery.

See <https://docs.algovoi.co.uk/scim-provisioning> for Okta, Azure AD and OneLogin setup.
