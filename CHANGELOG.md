# Changelog

All notable changes to CALLOSUM. This project is proprietary; see `LICENSE`.

## [0.1.1] - 2026-08-15 — hardening pass

Eight defects found by adversarially probing the guarantees the v0.1.0 docs
claimed. Each fix ships with a regression test that fails on v0.1.0.
Test count: 70 -> 89.

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
