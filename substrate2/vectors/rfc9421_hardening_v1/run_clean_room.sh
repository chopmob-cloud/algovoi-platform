#!/bin/sh
# Clean-room cross-implementation validation of rfc9421_hardening_v1.
# Runs inside a fresh python:3.11-slim container with /work mounted.
set -e
cd /work
echo "python: $(python -V 2>&1)   pip: $(pip -V 2>&1 | cut -d' ' -f1-2)"
echo "installing verifiers from source (wheels only, no local caches)..."
pip install --quiet --no-cache-dir --disable-pip-version-check ./substrate2
pip install --quiet --no-cache-dir --disable-pip-version-check ./standalone
echo "installed:"
pip show substrate2 2>/dev/null | grep -E '^(Name|Version)' | tr '\n' ' '; echo
pip show algovoi-rfc9421-verifier 2>/dev/null | grep -E '^(Name|Version)' | tr '\n' ' '; echo

rc=0
echo
echo "########## IMPL 1: substrate2.rfc9421_verifier (hardened) ##########"
python validate_vectors.py rfc9421_hardening_v1.json substrate2.rfc9421_verifier:verify_request || rc=$?
echo
echo "########## IMPL 2: algovoi_rfc9421_verifier (standalone package) ##########"
python validate_vectors.py rfc9421_hardening_v1.json algovoi_rfc9421_verifier:verify_request || rc=$?
echo
echo "clean-room aggregate exit: $rc"
exit $rc
