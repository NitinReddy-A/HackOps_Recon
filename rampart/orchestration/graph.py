"""The DAG task graph + a bounded, concurrent scheduler with dynamic task spawning."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any

from ..util import gen_id


@dataclass
class TaskOutcome:
    """A task may return a plain value, or a TaskOutcome carrying newly-spawned child tasks."""

    value: Any = None
    spawn: list = field(default_factory=list)  # list[Task] added to the graph dynamically


@dataclass
class Task:
    name: str
    run: Callable[[dict], Any]  # ctx = {dep_id: dep_value}; returns value or TaskOutcome
    deps: list = field(default_factory=list)
    kind: str = "agent"
    id: str = ""
    status: str = "pending"  # pending | running | done | error
    value: Any = None
    error: str = ""
    started: float = 0.0
    ended: float = 0.0

    def __post_init__(self):
        if not self.id:
            self.id = gen_id("task")


@dataclass
class GraphResult:
    tasks: dict = field(default_factory=dict)  # id -> Task
    order: list = field(default_factory=list)  # completion order (ids)
    values: dict = field(default_factory=dict)  # id -> value
    errors: dict = field(default_factory=dict)  # id -> error
    max_concurrency: int = 0
    duration_s: float = 0.0

    def results_of_kind(self, kind: str) -> list:
        return [t.value for t in self.tasks.values() if t.kind == kind and t.status == "done"]


class TaskGraph:
    def __init__(self):
        self.tasks: dict[str, Task] = {}
        self._lock = threading.Lock()

    def add(self, task: Task) -> str:
        with self._lock:
            self.tasks[task.id] = task
        return task.id

    def add_all(self, tasks) -> list:
        return [self.add(t) for t in tasks]

    def _ready(self) -> list:
        with self._lock:
            ready = []
            for t in self.tasks.values():
                if t.status != "pending":
                    continue
                if all(self.tasks.get(d) and self.tasks[d].status in ("done", "error") for d in t.deps):
                    ready.append(t)
            return ready

    def _ctx(self, task: Task) -> dict:
        with self._lock:
            return {d: self.tasks[d].value for d in task.deps if d in self.tasks}

    def _pending_or_running(self) -> bool:
        with self._lock:
            return any(t.status in ("pending", "running") for t in self.tasks.values())


def run_graph(graph: TaskGraph, max_workers: int = 16, on_event=None) -> GraphResult:
    """Execute the graph concurrently. Tasks run when their deps complete; a task may spawn more.

    `max_workers` caps concurrency (the per-host rate limit/budget still throttles real traffic).
    """
    result = GraphResult(tasks=graph.tasks)
    t0 = time.monotonic()
    inflight = {}  # future -> task
    peak = 0

    def _submit(executor, task):
        task.status = "running"
        task.started = time.monotonic()
        ctx = graph._ctx(task)
        if on_event:
            on_event("start", task)
        return executor.submit(task.run, ctx)

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        for t in graph._ready():
            inflight[_submit(executor, t)] = t
        peak = max(peak, len(inflight))

        while inflight:
            done, _ = wait(list(inflight), return_when=FIRST_COMPLETED)
            for fut in done:
                task = inflight.pop(fut)
                task.ended = time.monotonic()
                try:
                    out = fut.result()
                    if isinstance(out, TaskOutcome):
                        task.value = out.value
                        for child in out.spawn:
                            graph.add(child)
                    else:
                        task.value = out
                    task.status = "done"
                    result.values[task.id] = task.value
                except Exception as exc:  # noqa: BLE001 - one task's failure must not sink the graph
                    task.status = "error"
                    task.error = str(exc)
                    result.errors[task.id] = str(exc)
                result.order.append(task.id)
                if on_event:
                    on_event("done", task)
            # schedule any newly-ready tasks (including freshly-spawned children)
            for t in graph._ready():
                if t.status == "pending":
                    inflight[_submit(executor, t)] = t
            peak = max(peak, len(inflight))

    result.max_concurrency = peak
    result.duration_s = round(time.monotonic() - t0, 3)
    return result
