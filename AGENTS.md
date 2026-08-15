# AGENTS.md

Guide for coding agents (Claude Code, Codex CLI, etc.) working **on** this
repository's source. If you were handed this repo to run **as** a hemisphere
inside a live CALLOSUM session, read `PROTOCOL.md` instead — that's the
runtime contract, this is the contributor guide.

## What this is

CALLOSUM is a governed dual-hemisphere AI brain harness: two peer AI agents
run in separate terminals, coupled through an inhibitory, evidence-gated
bridge. See `README.md` for the full mechanism table and `docs/CLAIM_SEEDS.md`
for the patent claim language this implementation embodies.

**`docs/CLAIM_SEEDS.md` is provisional patent claim language.** Don't edit its
substance (claim scope, wording) without the repo owner's sign-off — cosmetic
fixes (typos, formatting) are fine.

## Setup

```powershell
pip install -e .[dev]
```

## Test

```powershell
pytest -q                      # full suite, currently 70 tests, all adversarial-first
python scripts\run_eval.py     # five-config eval on demo tasks (A-E)
python scripts\kill_drill.py   # failover drill: detect -> elect -> absorb -> degrade -> fence
```

Run the full suite before opening a PR. The test suites are adversarial by
design (tamper, forgery, race, torn-write) — a change that only satisfies the
happy path is not done.

## Module map

| Module | Owns |
|---|---|
| `envelope.py` | `BrainEnvelope` — identity + memory above the models, hot-swap |
| `instrumentation.py` | Independence phase (sealed commits), sycophancy classification |
| `bridge.py` | The inhibitory evidence-gated bridge — the 7 ordered gating rules |
| `evidence.py` | sha256-bound evidence root, laundering/traversal defenses |
| `capability.py` | Per-subtask authority record, ledger-rebuildable |
| `failover.py` | Capability-weighted election, absorb, unbacked flags, degraded mode, watchdog |
| `transport.py` | Epoch fencing, file-drop bus |
| `ledger.py` | Hash-chained, Ed25519-signed, HEAD-anchored append-only log |
| `corrections.py` | Three-status correction gate |
| `adapter.py` | `MockHemisphere` + `TerminalHemisphere` (real CLI agents over file-drop) |
| `cli.py` | `callosum post/beat/status/verify` |
| `eval/runner.py` | Five-configuration eval harness |

## Conventions

- **Windows-first.** `FileLock` uses `msvcrt` `LK_NBLCK` in an owned retry
  loop — never `LK_LOCK`. Atomic writes are tmp + fsync + `os.replace`. All
  JSON is written as bytes (no newline translation — CRLF-safe by
  construction). See README "Windows-first notes" for the POSIX deltas.
- No mocks standing in for the adversarial guarantees under test — the test
  suites simulate real tamper/crash/race conditions, not idealized ones.
- New gating rules or claim-adjacent mechanisms belong in `bridge.py` /
  `failover.py` with a corresponding entry in `docs/CLAIM_SEEDS.md` if they
  change claim scope — flag this explicitly in the PR description rather than
  silently expanding it.
