#!/usr/bin/env bash
# AlgoVoi — Verify It Yourself
# Don't trust AlgoVoi. In five minutes, prove our evidence is genuine, post-quantum
# signed, and tamper-evident — offline, with NO AlgoVoi code in your trust base.
#
#   Trust base:  pqcrypto + rfc8785   (two public, audited-primitive libraries)
#   Network:     one HTTPS GET of our public, signed registry. Nothing else phones home.
#
# Run:  bash verify_it_yourself.sh
set -euo pipefail

REGISTRY_URL="https://api.algovoi.co.uk/.well-known/algovoi-product-keys.json"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$HERE/algovoi_verify.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "No Python found. Install Python 3.8+ from https://python.org and re-run."; exit 1; }

bar()  { printf '%s\n' "------------------------------------------------------------"; }
step() { bar; printf '  %s\n' "$1"; bar; }

step "1/4  Trust base — two public libraries, no AlgoVoi code"
if "$PY" -c "import pqcrypto, rfc8785" 2>/dev/null; then
  echo "  present: pqcrypto + rfc8785"
else
  echo "  installing into an isolated venv (never touches your system packages)..."
  if "$PY" -m venv "$HERE/.venv" 2>/dev/null; then
    # shellcheck disable=SC1091
    if [ -f "$HERE/.venv/bin/activate" ]; then . "$HERE/.venv/bin/activate"
    else . "$HERE/.venv/Scripts/activate"; fi
    PY="$(command -v python || command -v python3)"
    pip install --quiet --upgrade pip
    pip install --quiet pqcrypto rfc8785
    echo "  installed: pqcrypto + rfc8785 (in ./.venv)"
  else
    echo "  could not create a venv. Install the venv module, then re-run:"
    echo "      Debian/Ubuntu:  sudo apt install python3-venv"
    echo "      then:           python3 -m venv .venv && . .venv/bin/activate && pip install pqcrypto rfc8785"
    exit 1
  fi
fi

step "2/4  Fetch AlgoVoi's live, public, Falcon-1024-signed key registry"
curl -fsS "$REGISTRY_URL" -o "$WORK/registry.json"
echo "  fetched $(wc -c < "$WORK/registry.json") bytes from $REGISTRY_URL"

step "3/4  Verify it — offline, from the published public key alone"
"$PY" "$VERIFY" product-keys "$WORK/registry.json"
echo "  ^ exit 0 = every Falcon-1024 signature re-derived correctly, on YOUR machine."

step "4/4  Now break it — change ONE character of a signed key, re-verify"
"$PY" - "$WORK/registry.json" "$WORK/tampered.json" <<'PY_EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
d = json.load(open(src, encoding="utf-8"))
k = d["payload"]["algovoi_operated_keys"][0]
old = k["public_key"]; k["public_key"] = ("A" if old[0] != "A" else "B") + old[1:]
json.dump(d, open(dst, "w", encoding="utf-8"))
print(f"  tampered operated_keys[0].public_key: {old[:12]}... -> {k['public_key'][:12]}...")
PY_EOF
if "$PY" "$VERIFY" product-keys "$WORK/tampered.json"; then
  echo "  UNEXPECTED: tampered registry verified — please report this."; exit 2
else
  echo "  ^ exit 1 = the post-quantum signature caught a single-character change."
fi

bar
cat <<'DONE'
  You just proved, on your own machine, with no AlgoVoi code in your trust base:
    - the registry was signed by the holder of the key published at api.algovoi.co.uk,
      whose kid is a SHA-256 fingerprint of that key (anchor it via TLS or a pinned
      fingerprint — the signature then proves everything from that anchor forward)
    - the evidence is genuine, unaltered, and offline-verifiable into the post-quantum
      era (Falcon-1024 / FN-DSA-1024)
    - a single altered byte is caught at exactly that entry
    - key-rotation lineage is cross-signed, so a long-lived anchor's succession is provable

  That is the whole promise: evidence you can defend to an auditor, a court, or
  your own security team — years from now, without trusting the vendor.

  Next: point this same verifier at a receipt from your own pilot deployment.
  -> pilot@algovoi.co.uk   |   https://docs.algovoi.co.uk/verifiable-archive
DONE
bar
