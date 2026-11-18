# AlgoVoi Evidence Auditor (`av-audit`)

**An [AlgoVoi](https://algovoi.co.uk) product.** Point it at an archive of signed
documents; it verifies **every** signature (classical RSA/ECDSA *and* post-quantum
reseal attestations) and hands you a **signed, tamper-evident audit report** you
can give an auditor — and re-run each cycle to prove nothing changed.

The middle rung of the ladder:

- **Free** — [`algovoi-reseal-verify`](https://pypi.org/project/algovoi-reseal-verify/): check *one* document.
- **This** — batch-verify a *whole archive* + produce the signed report.
- **Enterprise** — [AlgoVoi Compliance Suite](https://docs.algovoi.co.uk/verifiable-compliance-suite): store, govern, retain, seal at scale.

## Use

```bash
pip install --index-url https://<token>@api.algovoi.co.uk/pkgs/simple/ \
            --extra-index-url https://pypi.org/simple/ algovoi-evidence-audit
export ALGOVOI_LICENSE_KEY="<your-licence-key>"

av-audit keygen                                   # your auditor identity
av-audit run ./signed-records --out ./audit       # verify the archive -> report
av-audit run ./signed-records --baseline ./audit/audit-report.json   # diff a re-run
```

`run` produces `audit-report.json` (findings), `audit-report.json.reseal.json`
(the signed attestation), `audit-report.html`, and `audit-report.csv`.

## The report verifies itself — with the free tool

The report is signed with a post-quantum reseal envelope, so anyone can confirm
it is authentic and unaltered using the **free** verifier, no licence needed:

```bash
pip install algovoi-reseal-verify
av-reseal-verify verify audit-report.json.reseal.json --file audit-report.json --expect-kid sha256:...
```

## What it flags per document

verified / invalid, unsigned, weak digest (SHA-1), expired certificate, broken
trust chain, partial-coverage (shadow) PDF, and post-quantum exposure — with
optional offline trust-path (`--trust-roots`) and CRL (`--crl`) checks.

## Scope

Read-only: it verifies and reports, it never stores, mutates, or governs your
documents. Storage/retention/legal-holds/console/SIEM/HSM and at-scale
re-anchoring live in the Compliance Suite. **Auditing an archive is the licensed
action** (gated at the engine, fail-closed); *verifying* an existing report is
free — that's the open `algovoi-reseal-verify`, and single-document verification
is free too.

## Licensing

Proprietary (see LICENSE / NOTICE). Depends only on permissive open-source
libraries plus the open `algovoi-reseal-verify`; third parties attributed in
THIRD_PARTY_NOTICES.md.
