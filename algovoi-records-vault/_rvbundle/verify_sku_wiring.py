"""Re-runnable proof of the Records Vault SKU wiring (AST-only; no heavy imports, cmd.exe-safe).

Asserts:
  * gateway suite_store _SKUS carries AV-ReVLT -> algovoi-records-vault @ $18000, no dup SKU/package
  * AV-ReVLT does NOT collide with the free Recovery Vault AV-RVLT (_FREE_APPS)
  * fulfiller _SUITE_DEPS maps algovoi-records-vault -> (doc-archive, -s3, -archive-auditor)

Exit 0 + 'SKU_WIRING_OK' on success; non-zero AssertionError otherwise.
Run: python C:/algo/platform/algovoi-records-vault/_rvbundle/verify_sku_wiring.py
"""
import ast

PLATFORM = "C:/algo/platform"
SUITE = f"{PLATFORM}/gateway/app/routers/suite_store.py"
FULF = f"{PLATFORM}/algovoi-license-fulfillment/src/algovoi_license_fulfillment/fulfiller.py"


def grab(path, name):
    mod = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(mod):
        val = None
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    val = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            val = node.value
        if val is not None:
            return ast.literal_eval(val)
    raise AssertionError(f"{name} not found in {path}")


skus = grab(SUITE, "_SKUS")
free = grab(SUITE, "_FREE_APPS")
deps = grab(FULF, "_SUITE_DEPS")

codes = [s["sku"] for s in skus]
pkgs = [s["package"] for s in skus]
assert len(codes) == len(set(codes)), f"duplicate SKU codes: {codes}"
assert len(pkgs) == len(set(pkgs)), f"duplicate packages: {pkgs}"

rv = [s for s in skus if s["sku"] == "AV-ReVLT"]
assert len(rv) == 1, "AV-ReVLT must appear exactly once in _SKUS"
assert rv[0]["package"] == "algovoi-records-vault", rv[0]["package"]
assert rv[0]["price"] == 18000, rv[0]["price"]
assert not rv[0].get("is_bundle"), "must be a normal metered SKU, not is_bundle (single-bundle machinery)"
# merchandised at the top, directly under the substrate-2 bundle, styled as a (display-only) bundle
assert codes[0] == "AV-S2-ONPREM", f"substrate-2 bundle must be first, got {codes[0]}"
assert codes[1] == "AV-ReVLT", f"Records Vault must be second (just under the bundle), got {codes[1]}"
assert rv[0].get("display_bundle") is True, "Records Vault must carry display_bundle (bundle card, correct fulfilment)"

free_codes = {f["sku"] for f in free}
assert "AV-RVLT" in free_codes, "Recovery Vault AV-RVLT expected in _FREE_APPS"
assert "AV-ReVLT" not in free_codes, "Records Vault must not be in _FREE_APPS"

assert deps.get("algovoi-records-vault") == (
    "algovoi-doc-archive", "algovoi-doc-archive-s3", "algovoi-archive-auditor"
), deps.get("algovoi-records-vault")

print(f"SKU rows={len(skus)} AV-ReVLT->{rv[0]['package']} ${rv[0]['price']} "
      f"| free RecoveryVault=AV-RVLT distinct | deps={deps['algovoi-records-vault']}")
print("SKU_WIRING_OK")
