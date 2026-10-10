# Benchmarking Rampart against external vulnerable apps

Rampart ships a built-in, offline benchmark (`python benchmarks/run_benchmark.py`) against its own
on/off demo target — the clean way to measure precision/recall (100% on the shipped corpus, both
vulnerable and fixed). To validate against the community's standard intentionally-vulnerable apps,
point Rampart at them locally. These are **not bundled** (they require Docker/Node and carry their
own licenses); run them yourself on an isolated host you own.

> Only ever test these on localhost / an isolated lab you control, with a matching `rampart.scope.yaml`
> whose `resolved_ip_allowlist` and `in_scope` cover the app. Never point Rampart at a shared host.

## OWASP crAPI (API security — BOLA/BFLA/mass assignment/JWT)
```bash
git clone https://github.com/OWASP/crAPI && cd crAPI/deploy/docker
docker compose up -d                      # app on http://localhost:8888
# scope: host 127.0.0.1, port 8888, paths /** ; seed two accounts in secrets.json
python -m rampart pipeline --scope-file crapi-rampart.scope.yaml --target http://127.0.0.1:8888 \
  --openapi crapi-openapi.json --active --report html,sarif,soc2
```
Expected high-value hits: BOLA on vehicle/mechanic endpoints, mass assignment, JWT, BFLA.

## VAmPI (API — toggleable vulnerable/secure, like Rampart's own demo)
```bash
git clone https://github.com/erev0s/VAmPI && cd VAmPI
docker build -t vampi . && docker run -d -p 5000:5000 -e vulnerable=1 vampi   # vulnerable
# re-run with -e vulnerable=0 for the secure build to measure false positives
python -m rampart pipeline --scope-file benchmarks/fixtures/vampi-rampart.scope.yaml --target http://127.0.0.1:5000 \
  --crawl --active --report html,sarif
```
VAmPI's `vulnerable=1/0` switch mirrors Rampart's demo on/off design — ideal for FP/FN scoring.

## OWASP Juice Shop (web — XSS/SQLi/auth, heavy client-side)
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop   # http://localhost:3000
python -m rampart pipeline --scope-file juice-rampart.scope.yaml --target http://127.0.0.1:3000 \
  --crawl --browser --report html,sarif
```
Juice Shop is an Angular SPA — use `--browser` for DOM/stored XSS; much of its content needs the
headless-browser engine (install the `browser` extra, then `python -m playwright install chromium`).

## Scoring — the multi-app benchmark program

`benchmarks/corpus_runner.py` scores Rampart against any running fixture with a committed
ground-truth file, and reports more than a single number so a run can be read honestly:

```bash
python benchmarks/corpus_runner.py \
  --target http://127.0.0.1:5000 \
  --scope-file benchmarks/fixtures/vampi-rampart.scope.yaml \
  --ground-truth benchmarks/fixtures/vampi-ground-truth.json \
  --crawl --runs 5 --min-recall 0.5 --out vampi-report.json
```

It emits, as JSON:

- **per-class and overall** precision / recall / F1 (`per_run[].per_class`), so a strong overall
  number can't hide a weak class;
- a **coverage manifest** (`coverage_manifest`) — for every expected class, `tested+confirmed`,
  `tested+missed` (a real false negative: the engine exercised it and did not prove it), or
  **`not-tested`** (a coverage gap: the engine never tried it). *"No findings" is never reported as
  "fully tested"* — an un-exercised class is surfaced loudly (and on stderr);
- **variance across `--runs`** and whether the confirmed set was **deterministic** (`aggregate`);
- **inconclusive / error** signals (`signals`): whether any run was incomplete (target unreachable
  or every request blocked), plus the dropped-by-FP-gate and agent-assessed counts.

Ground-truth file: `{"path_keys": ["/users/v1", ...], "expected": [["IDOR/BOLA","/users/v1"], ...]}`.
Starter fixtures live in `benchmarks/fixtures/` for **VAmPI** (wired into the weekly
[`corpus.yml`](../.github/workflows/corpus.yml)) and **Juice Shop**; crAPI uses the scope/commands
above. They are **best-effort templates** — tune `path_keys`/`expected` to your version using the
`missed`/`unexpected` lists and the coverage manifest the runner prints. The pure scorers
(`score`, `coverage_manifest`, `aggregate`) are unit-tested in `tests/test_corpus.py`.

Run each app in its vulnerable and (where available) secure mode; a credible comparison freezes
target versions, accounts/roles, specs, runtime, and compute budget, runs ≥ 5 times, and records
per-class precision/recall/F1, variance, inconclusive/error states, and the coverage manifest for
both products. This is due-diligence scaffolding, not a substitute for an independent, blinded
bake-off.
