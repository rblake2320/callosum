# Changelog

All notable changes to CALLOSUM. This project is proprietary; see `LICENSE`.

## [0.1.1] - 2026-08-15 — hardening pass

Two independent adversarial passes against v0.1.0, reconciled via rebase
(no code lost or silently overwritten). Combined test count: 70 -> 104.

### Second pass — modules the first pass didn't touch

Four parallel reviewers each auditing a distinct module, plus hands-on
adversarial testing (real exploits run, not just code reading). Two findings
(`rebuild_from_ledger` signer pinning, corrections lock) were superseded by
the more complete fixes below and dropped rather than duplicated.

- **`reveal()` never verified the ledger, not even unpinned.** Unlike
  `rebuild_from_ledger`, `PositionTracker.reveal()` trusted `ledger.entries()`
  raw — an attacker with filesystem access to the ledger dir could inject an
  unsigned `position_commit` entry and have it treated as a legitimately
  sealed independent commitment.
- **`check_and_elect()` had no lock around its read-modify-write**, unlike
  every other stateful primitive in `failover.py`. Concurrent controller
  instances could each "win" the same death event and mint their own epoch
  (confirmed 6/6 in a real 6-process race). Now one lock spans the full
  detect -> epoch -> absorb -> degrade sequence.
- **Quarantine credit accepted evidence replay.** Resubmitting the same
  artifact repeatedly earned repeated release credit. Now requires each
  credit to include at least one sha256 not already credited *in the current
  quarantine term* — a follow-up code review caught that the first version of
  this fix let novelty tracking outlive its term, starving a hemisphere that
  legitimately re-cited an old artifact in a later, unrelated incident.
- **`E_kill_drill` scored a hardcoded `"left"`** regardless of which side
  actually survived. Half of `demo_tasks()` kill `"left"`; the eval was
  silently scoring the dead side's stale position (reporting 0.5 instead of
  the true 1.0).
- **`hot_swap()` bypassed quarantined rejoin entirely**, setting
  `alive[side]=True` directly. An operator recovering from a kill drill via
  hot_swap instead of `rejoin()` silently skipped the documented quarantine
  gate. Now routes through `rejoin()` when the side was dead/absorbed, without
  blocking or delaying the swap itself.
- **A malformed `round_N_out.json` crashed the whole session.**
  `TerminalHemisphere.react()` trusted a real CLI peer's draft output
  verbatim; a typo'd or invalid key raised a raw `KeyError`/`ValueError`
  instead of being dropped as a protocol violation.
- **Unrecognized message kind fell through to "always passes."** Not reachable
  via the shipped call sites today, but the bridge is documented as the sole
  inhibitory checkpoint and shouldn't depend on callers pre-validating. Now
  fails closed, ledgered.
- **`verified_correction` checked evidence integrity, never substance.** A
  correction citing its own proof of a *failed* run (`exit_code != 0`) was
  still accepted as verified. Fix positive-matches the documented
  `{cmd, exit_code, ...}` test-run-record shape rather than triggering on a
  bare `exit_code` key — there's no `etype` taxonomy in `evidence.py` to scope
  by, and an unrelated artifact carrying a coincidental `exit_code`-named
  field must not misfire.
- **`CapabilityMatrix.__init__` read `capability.json` with no lock** — the
  only constructor of the three stateful primitives (`Ledger`, `Quarantine`,
  `CapabilityMatrix`) that eagerly caches file state on construction, and the
  only one that did so unprotected. A concurrent `atomic_write_json` replace
  from another process's `record_outcome`/`absorb` could make a fresh
  construction raise `PermissionError` on Windows (~7.5% of runs under real
  concurrent construction + writes — present since v0.1.0, surfaced only by
  a genuinely concurrent multi-process regression test for the
  `check_and_elect()` fix above). Present since day one, in both hardening
  passes, until this one.

### First pass — the eight defects below

### Security

- **Epoch fence bypassed by a forged-forward epoch.** `bridge.transmit` fenced
  on `msg.epoch < current`, so a hemisphere declared dead could stamp an
  arbitrarily high epoch and cross freely — defeating the split-brain guard in
  claim seed 2(f). Now strict equality, with `stale_epoch` and `future_epoch`
  distinguished in the ledger.
- **`rebuild_from_ledger` accepted a foreign-signed chain.** It called
  `ledger.verify()` with no `trusted_pubs`, so a chain an attacker re-signed
  end-to-end verified cleanly. The anti-poisoning defense was itself the
  poisoning vector. Rebuild now pins the envelope key by default.
- **Envelope key written unprotected.** `Signer.save` defaulted to
  `use_dpapi=False` and every `BrainEnvelope` took that path, so the README's
  DPAPI hardening was never on the runtime path. Default is now
  protect-if-possible (DPAPI on Windows, `O_EXCL` 0600 on POSIX — no
  write-then-chmod race).
- **Delivered messages did not seal their evidence.** Suppressions logged
  evidence detail; deliveries logged only a boolean, so a crossing could not be
  re-adjudicated from the chain. `bridge_delivered` now seals each ref's path
  and sha256.

### Correctness

- **Capability matrix lost adjudicated outcomes.** `record_outcome` and
  `absorb` locked the write but mutated a cache loaded at construction, so two
  live handles silently dropped an outcome. Read-modify-write now happens
  inside the lock. Verified: 4 processes x 25 outcomes, zero lost.
- **Ledger replay diverged from live state.** Replaying `capability_absorb`
  blanket-assigned *every* subtask to the survivor, while live `absorb` moved
  only the dead side's (and unheld) subtasks. The reassignment map is now
  sealed to the ledger and replayed verbatim; legacy entries are recomputed.
- **Clean crash reported as tamper.** A crash between the JSONL append and the
  HEAD update produced "tail truncation or rollback" — a false alarm on an
  ordinary power cut, contradicting the module docstring. HEAD is now two-phase
  (signed pending -> committed), so verify resolves crash and truncation
  separately. Committed-tail truncation is still detected.
- **Corrections log appended without a lock**, unlike every other append path.
  Now takes the same cross-process `FileLock`.

### Added

- `callosum init --root R` — creates an envelope root, identity key, terminal
  and evidence directories. Previously no CLI path existed to create the root
  every other subcommand requires.
- `callosum status` now reports quarantine state. PROTOCOL.md tells occupants
  to run `status` when confused; quarantine is exactly the state that silently
  changes what the bridge demands of them.
- CI: Windows + Linux x Python 3.10-3.13, plus eval, kill drill, CLI smoke,
  lint, and a secret-scan job that fails the build if key material or envelope
  state is ever committed.
- `LICENSE` (proprietary, all rights reserved, no implied patent license or
  publication), `SECURITY.md` (trust boundaries, adversary model, known
  limits), `CODEOWNERS`, PR template.
- `.gitignore` now excludes `identity.key`, `*.key`, and all envelope runtime
  state. v0.1.0 would have committed the envelope private key if a session had
  ever been rooted inside the checkout.

## [0.1.0] - 2026-08-15

Initial implementation: inhibitory evidence-gated bridge, sealed independence
phase, capability matrix, failover-as-plasticity, hash-chained Ed25519 ledger,
correction gate, brain envelope, five-configuration eval. 70 tests.
