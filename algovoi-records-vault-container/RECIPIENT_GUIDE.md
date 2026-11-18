# Opening an AlgoVoi sealed container (`.acv`)

You have been sent a sealed, encrypted records container. This one page is everything you need to open
it. No AlgoVoi account, no network, no vendor software.

## What you need

- `container.acv` — the sealed container (from the sender)
- `acv_unseal.py` — the extractor (sent alongside it)
- **Python 3.10+** and three public libraries:
  ```bash
  pip install pqcrypto rfc8785 cryptography
  # add shamir-mnemonic only if you were given recovery shares instead of a key
  ```

## Step 1 (once, before the sender seals to you): make your key

The container is sealed to **you** specifically, so the sender needs your public key first:

```bash
python acv_unseal.py --genkey recipient
```
This writes two files:
- `recipient_pk.b64` — **send this to the sender.** It is public; it is safe to email.
- `recipient_sk.b64` — **keep this private and safe.** It is the only thing that opens your containers
  (unless you also arranged recovery shares). If you lose it and there is no recovery, the container
  cannot be opened.

## Step 2: open the container

```bash
python acv_unseal.py --key @recipient_sk.b64 --revocation-list @crl.txt --out ./unsealed container.acv
```

- It prints `issuer_kid=...`. Check that against the fingerprint the sender gave you (or add
  `--expect-issuer <kid>` to make the check mandatory) so you know it really came from them.
- It verifies the signature, checks the container has not expired or been **revoked**, decrypts with your
  key, and checks each document is intact before writing it to `./unsealed`.
- `crl.txt` is the sender's current **revocation list**. If the container requires one and you were not
  given it, ask the sender for the latest copy. (Some containers are sealed without this requirement and
  open with no `--revocation-list`.)

If anything is wrong (wrong key, tampered file, expired, or revoked) it refuses and tells you why. A
successful run ends with `VERIFIED + unsealed N document(s)`.

## If you lost your key

If the sender set up **custodian recovery**, any *k* of the named custodians can open it together, with
no recipient key:

```bash
python acv_unseal.py --recover-share "word list one ..." --recover-share "word list two ..." --out ./unsealed container.acv
```

Otherwise, contact the sender: if they marked the container **console-recoverable**, they can recover it
for you from their Compliance Command Center.
