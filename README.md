# CALLOSUM

Governed dual-hemisphere AI brain harness. Two capability-matched models
(e.g., Claude Code + Codex CLI) run as **peers in separate terminals**; a
cryptographically sealed, **inhibitory, evidence-gated bridge** — the corpus
callosum — governs everything that crosses between them. The bridge is the
invention; the models are replaceable organs.

**Private personal IP (Ron Blake).** See `LICENSE` and `docs/CLAIM_SEEDS.md`. Do
not publish, demo publicly, or reference in outreach before the covering
provisional is filed.

> **Repository visibility is part of that standing order.** `docs/CLAIM_SEEDS.md`
> is unfiled provisional claim language. Hosting it in a repository that anyone
> can view is itself a public disclosure, regardless of what the file's header
> says. Confirm this repo is **Private** before pushing anything further.

## What it enforces

| Mechanism | Module | Why |
|---|---|---|
| Independence phase: positions sha-sealed before contact | `instrumentation.py` | anti-sycophancy (models converge on the loudest voice otherwise) |
| Inhibitory bridge: influence needs authority or validated evidence | `bridge.py` | counterexample-with-citation is the only guaranteed crossing |
| Evidence jail: sha256-bound artifacts inside `evidence/` only | `evidence.py` | no forged, stale, traversal, or laundered evidence |
| Sycophancy ratio + fast-agreement tripwire | `instrumentation.py` | changed-by-assertion is flagged; cheap agreement demands validation |
| Capability matrix: authority from adjudicated wins | `capability.py` | ledger-rebuildable; file poisoning is defeated by replay |
| Failover as plasticity: capability-weighted election, absorb, **unbacked flags**, degraded mode | `failover.py` | survivor knows exactly which guarantees it can no longer back |
| Epoch fencing + quarantined rejoin | `transport.py`, `failover.py` | split-brain guard for false deaths |
| Watchdog: verified progress or HALT | `failover.py` | two models free-running unverified get stopped |
| Hash-chained Ed25519 ledger + HEAD anchor | `ledger.py` | tamper-evident incl. tail truncation and rollback |
| Correction packages, three-status gate | `corrections.py` | only execution-verified corrections publish; agreement ≠ truth |
| BrainEnvelope: identity + memory above the models; hot-swap | `envelope.py` | the brain survives the organ transplant |

## Quickstart

```powershell
pip install -e .[dev]
pytest -q                      # 89 tests
python scripts\run_eval.py     # five-config eval on demo tasks
python scripts\kill_drill.py   # detect -> elect -> absorb -> degrade -> fence
```

Wire real terminals:

```powershell
callosum init --root C:\envelopes\demo     # identity key + evidence jail + terminal dirs
```

Then open Claude Code in `<ROOT>\terminals\left` and Codex CLI in
`<ROOT>\terminals\right`, paste each agent `PROTOCOL.md`, and start their
heartbeats. Agents speak via `callosum post/beat/status/verify`. For a scripted
envelope instead, construct `BrainEnvelope` with two `TerminalHemisphere`
adapters directly.

`SECURITY.md` states the trust boundaries, the adversary model, and — more
usefully — the five things this system explicitly does **not** guarantee.

## Five-configuration eval

A left solo · B right solo · C frozen council · D live collaboration · E kill
drill. Headline: `pair_vs_best_single_pp` (D vs best single **model**);
`pair_vs_oracle_single_pp` compares against a per-task perfect router (strictly
harder — expect smaller or zero on synthetic mocks). Demo output: D=1.0 vs best
single 0.5 (+50pp), sycophancy 0.0, detection latency ≈0.23s at a 0.15s budget.
Mocks expose perfect `evidence_for`, which flatters config C; real models won't.

## Test map (89 tests, all adversarial-first)

| Suite | n | Proves |
|---|---|---|
| `test_atomic_locks.py` | 7 | crash-safe atomic writes, CRLF byte fidelity, cross-process mutual exclusion (4 procs × 50, zero lost updates), deterministic lock timeout |
| `test_ledger_adversarial.py` | 10 | payload tamper, reorder, mid-chain delete, tail truncation (HEAD anchor), sig forgery, attacker full-rewrite vs trusted set, HEAD corruption, torn line, 4-process concurrent appends verify |
| `test_bridge_adversarial.py` | 13 | sha forgery, traversal, absolute path, mixed-evidence laundering, suppression + ledgered dissent, authority pass, quarantine dampening w/ credits, stale-epoch fencing, degraded-mode universal evidence |
| `test_instrumentation_capability.py` | 14 | reveal blocked pre-commit, commit tamper, sycophancy classification/ratio, tripwire, authority flips, tie ⇒ nobody inhibits, matrix poisoning defeated by ledger rebuild, rebuild refuses tampered chain |
| `test_failover_watchdog.py` | 11 | detection within budget, capability-weighted election, degraded + unbacked, idempotent election, both-dead ⇒ watchdog, quarantined rejoin, watchdog halt/stand-down, exactly-once bus, torn in-flight tolerance |
| `test_envelope_corrections_eval.py` | 15 | correction gate (5), full session evidence-correction e2e, sycophant flagged, session tripwire, hot-swap identity+memory, kill drill e2e, checkpoint, HALT blocks sessions, eval report semantics (3) |
| `test_hardening_regressions.py` | 19 | forged-forward epoch fenced, attacker-resigned chain refused by rebuild, faithful absorb replay (incl. legacy entries), capability read-modify-write under lock (4 procs x 25, zero lost), ledger crash windows vs truncation (4), key 0600 at rest (3), delivered evidence sha sealed, corrections lock + line integrity |

## Windows-first notes

- `FileLock` uses `msvcrt` `LK_NBLCK` in an **owned retry loop** — never `LK_LOCK`
  (the CRT retries it 10×/1s internally, making timeouts non-deterministic).
- Atomic writes: tmp + fsync + `os.replace` (atomic on NTFS). All JSON is written
  as bytes — no newline translation, CRLF-safe by construction.
- Identity key: `Signer.save()` defaults to protect-if-possible — DPAPI
  (`CryptProtectData`, CURRENT_USER) on Windows, `O_EXCL` 0600 on POSIX. Pass
  `use_dpapi=False` to opt out. (Through v0.1.0 this defaulted to *off*, so the
  runtime never took the DPAPI path the docs advertised.)
- Linux deltas: `flock` instead of `msvcrt`; directory fsync after replace
  (skipped on Windows where it is unsupported/unneeded).

## Troubleshooting

- **Everything suppressed after a drill/crash** → degraded mode is on
  (`status` shows it). That is by design; carry evidence or clear `degraded.json`
  after review.
- **`stale_epoch` rejections** → an election happened while the sender was
  presumed dead. `FailoverController.rejoin(side)` re-admits it quarantined.
- **`future_epoch` rejections** → the sender stamped an epoch ahead of
  `epoch.json`. The fence is strict equality; epochs are envelope-assigned, so
  this means a stale process, a hand-edited message, or a forgery attempt.
- **`verify` fails with HEAD mismatch** → tail truncation or rollback. Restore
  from backup; the chain will not self-heal by design.
- **`verify` says "uncommitted tail recovered"** → not tamper. The anchor update
  was lost to a crash while the entries themselves landed intact and signed.
  This path requires a pinned signer set, which `callosum verify` always passes.
- **Watchdog HALT** → no verified progress within `t_safe`. Inspect the ledger
  tail, then `Watchdog.clear()`.
- **TerminalHemisphere timeout** → the CLI agent didn't write
  `round_N_out.json`; check its heartbeat loop and PROTOCOL.md compliance.
