# Benchmarking Rampart against external vulnerable apps

Rampart ships a built-in, offline benchmark (`python benchmarks/run_benchmark.py`) against its own
on/off demo target — the clean way to measure precision/recall (100% on the shipped corpus, both
vulnerable and fixed). To validate against the community's standard intentionally-vulnerable apps,
point Rampart at them locally. These are **not bundled** (they require Docker/Node and carry their
own licenses); run them yourself on an isolated host you own.

> Only ever test these on localhost / an isolated lab you control, with a matching `SECURITY.md`
> whose `resolved_ip_allowlist` and `in_scope` cover the app. Never point Rampart at a shared host.

## OWASP crAPI (API security — BOLA/BFLA/mass assignment/JWT)
```bash
git clone https://github.com/OWASP/crAPI && cd crAPI/deploy/docker
docker compose up -d                      # app on http://localhost:8888
# scope: host 127.0.0.1, port 8888, paths /** ; seed two accounts in secrets.json
python -m rampart pipeline --scope-file crapi-SECURITY.md --target http://127.0.0.1:8888 \
  --openapi crapi-openapi.json --active --report html,sarif,soc2
```
Expected high-value hits: BOLA on vehicle/mechanic endpoints, mass assignment, JWT, BFLA.

## VAmPI (API — toggleable vulnerable/secure, like Rampart's own demo)
```bash
git clone https://github.com/erev0s/VAmPI && cd VAmPI
docker build -t vampi . && docker run -d -p 5000:5000 -e vulnerable=1 vampi   # vulnerable
# re-run with -e vulnerable=0 for the secure build to measure false positives
python -m rampart pipeline --scope-file vampi-SECURITY.md --target http://127.0.0.1:5000 \
  --crawl --active --report html,sarif
```
VAmPI's `vulnerable=1/0` switch mirrors Rampart's demo on/off design — ideal for FP/FN scoring.

## OWASP Juice Shop (web — XSS/SQLi/auth, heavy client-side)
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop   # http://localhost:3000
python -m rampart pipeline --scope-file juice-SECURITY.md --target http://127.0.0.1:3000 \
  --crawl --browser --report html,sarif
```
Juice Shop is an Angular SPA — use `--browser` for DOM/stored XSS; much of its content needs the
headless-browser engine (`pip install rampart-appsec[browser] && python -m playwright install chromium`).

## Scoring
Run each app in its vulnerable and (where available) secure mode; compare `report.json` findings to
the app's documented issues. The design of `benchmarks/run_benchmark.py` (ground-truth set + on/off
target) extends directly — add a fixtures adapter per app to automate scoring in a lab with Docker.
