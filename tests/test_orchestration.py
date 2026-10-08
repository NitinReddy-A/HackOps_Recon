"""The graph orchestrator: DAG ordering, true parallelism, dynamic spawning, error isolation —
and a parity proof that running the supervisor in parallel yields the SAME confirmed findings as
a single worker (concurrency changes throughput, never the evidence or safety guarantees)."""
import threading
import time

import pytest

from conftest import write_engagement
from rampart.engagement import Engagement, EngagementConfig
from rampart.orchestration import Task, TaskGraph, TaskOutcome, run_graph


# --------------------------------------------------------------- unit: graph engine
def test_dag_dependency_ordering_and_ctx():
    g = TaskGraph()
    a = Task(name="a", run=lambda ctx: 2, kind="t")
    b = Task(name="b", run=lambda ctx: 3, kind="t")
    ga, gb = g.add(a), g.add(b)
    c = Task(name="c", run=lambda ctx: ctx[ga] * ctx[gb], deps=[ga, gb], kind="t")
    gc = g.add(c)
    res = run_graph(g, max_workers=4)
    assert res.values[gc] == 6                 # c saw both deps' values in its ctx
    assert res.order.index(ga) < res.order.index(gc)
    assert res.order.index(gb) < res.order.index(gc)


def test_runs_in_parallel():
    # 8 tasks that each sleep 0.2s finish in ~0.2s on an 8-wide pool, not ~1.6s serially.
    g = TaskGraph()
    idents = []
    lock = threading.Lock()

    def slow(ctx):
        time.sleep(0.2)
        with lock:
            idents.append(threading.get_ident())
        return 1

    for i in range(8):
        g.add(Task(name=f"s{i}", run=slow, kind="slow"))
    res = run_graph(g, max_workers=8)
    assert res.duration_s < 1.0                # proves concurrency (serial would be ~1.6s)
    assert res.max_concurrency >= 4
    assert len(set(idents)) >= 2               # genuinely ran on multiple threads


def test_dynamic_subagent_spawning():
    # A "planner" task decomposes its goal into child tasks at runtime (spawn), and those run too.
    g = TaskGraph()

    def planner(ctx):
        kids = [Task(name=f"k{i}", run=lambda c, i=i: i * 10, kind="kid") for i in range(5)]
        return TaskOutcome(value="decomposed", spawn=kids)

    pid = g.add(Task(name="planner", run=planner, kind="plan"))
    res = run_graph(g, max_workers=4)
    assert res.values[pid] == "decomposed"
    assert sorted(res.results_of_kind("kid")) == [0, 10, 20, 30, 40]


def test_spawned_children_can_depend_on_more_spawns():
    # Two-level decomposition: a planner spawns a sub-planner that spawns leaves.
    g = TaskGraph()

    def leaf(ctx):
        return "leaf"

    def subplanner(ctx):
        return TaskOutcome(value="sub", spawn=[Task(name="leaf", run=leaf, kind="leaf")])

    def planner(ctx):
        return TaskOutcome(value="top", spawn=[Task(name="sub", run=subplanner, kind="mid")])

    g.add(Task(name="planner", run=planner, kind="top"))
    res = run_graph(g, max_workers=4)
    assert res.results_of_kind("leaf") == ["leaf"]


def test_error_isolation_one_failure_does_not_sink_the_graph():
    g = TaskGraph()

    def boom(ctx):
        raise RuntimeError("kaboom")

    ok1 = g.add(Task(name="ok1", run=lambda ctx: "ok", kind="x"))
    bad = g.add(Task(name="bad", run=boom, kind="x"))
    ok2 = g.add(Task(name="ok2", run=lambda ctx: "ok", kind="x"))
    res = run_graph(g, max_workers=4)
    assert bad in res.errors and "kaboom" in res.errors[bad]
    assert res.values[ok1] == "ok" and res.values[ok2] == "ok"
    assert g.tasks[bad].status == "error"


def test_many_tasks_scale():
    # Sanity at scale: hundreds of tiny tasks all complete and are accounted for.
    g = TaskGraph()
    ids = [g.add(Task(name=f"t{i}", run=lambda ctx, i=i: i, kind="n")) for i in range(300)]
    res = run_graph(g, max_workers=64)
    assert len(res.values) == 300
    assert sum(res.values[i] for i in ids) == sum(range(300))


# --------------------------------------------- integration: parallel == sequential findings
def _run_with_parallel(tmp_path, port, parallel):
    scope_file = write_engagement(tmp_path, port)
    cfg = EngagementConfig(
        scope_file=scope_file, target=f"http://127.0.0.1:{port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
        application="demo-shop-api", parallel=parallel)
    eng = Engagement(cfg)
    result = eng.run_scan()
    confirmed = sorted(f"{f.vuln_class}@{f.endpoint.get('url','')}"
                       for f in result.findings if f.verification.validated)
    ok, msg = eng.audit.verify_chain()
    return confirmed, ok, msg


def test_parallel_findings_match_sequential(tmp_path, vuln_server):
    seq_dir = tmp_path / "seq"
    par_dir = tmp_path / "par"
    seq_dir.mkdir(); par_dir.mkdir()
    seq, ok1, m1 = _run_with_parallel(seq_dir, vuln_server.port, parallel=1)
    par, ok2, m2 = _run_with_parallel(par_dir, vuln_server.port, parallel=16)
    assert ok1, m1
    assert ok2, m2                                   # audit hash-chain intact under concurrency
    assert seq == par, f"parallel findings diverged:\n seq={seq}\n par={par}"
    assert seq, "expected confirmed findings on the vulnerable target"


# --------------------------------------------- integration: IaC / gRPC / SCA wiring
def test_engagement_wires_iac_and_grpc(tmp_path, vuln_server):
    import os
    repo = os.path.join(os.path.dirname(__file__), "..", "examples", "demo_target")
    scope_file = write_engagement(tmp_path, vuln_server.port)
    cfg = EngagementConfig(
        scope_file=scope_file, target=f"http://127.0.0.1:{vuln_server.port}",
        work_dir=str(tmp_path / ".rampart"),
        openapi=str(tmp_path / "openapi.json"),
        appmodel_seed=str(tmp_path / "seed.json"),
        application="demo-shop-api", repo=repo)
    eng = Engagement(cfg)
    iac = eng.run_iac()
    assert iac, "expected IaC findings from the demo iac/ fixtures"
    assert all("iac" in f.tags for f in iac)
    # gRPC is a no-op without the [grpc] extra / a gRPC target — must never raise.
    assert eng.run_grpc() == [] or isinstance(eng.run_grpc(), list)
