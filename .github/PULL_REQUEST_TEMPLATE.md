<!-- Thanks for contributing to Rampart! Keep PRs focused on one thing. -->

## What does this change?

<!-- A short description of the change and why it's needed. Link any related issue. -->

## How did you verify it?

<!-- Commands you ran, what you saw. e.g. pytest output, benchmark numbers. -->

## Checklist

- [ ] `pytest` passes
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] I added or updated tests for the behavior I changed
- [ ] If I added a confirmed check, it uses an independent oracle (probe + negative control +
      2+ reproductions) and the benchmark still reports 100%
- [ ] Any active/write probe is gated behind `--active`, and nothing I added is destructive
- [ ] Findings and docs are honest about limitations (no overclaiming)
