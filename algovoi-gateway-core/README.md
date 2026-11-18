# algovoi-gateway-core

Self-hostable, chain-agnostic payment gateway engine. Create payment intents, watch settlement through per-chain add-ons (`algovoi-gateway-<chain>`), and emit signed, no-PII, CCC-ingestable settlement receipts. Crypto core is substrate2. Commercial.

Install the core plus one chain add-on per blockchain you accept:

    pip install algovoi-gateway-core algovoi-gateway-base

Run the service (port 8090): `python -m algovoi_gateway_core.app` or the `create_app` factory.
