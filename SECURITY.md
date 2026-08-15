# Security model and reporting

CALLOSUM is trust infrastructure: its value is entirely in what it refuses to
let across the bridge and in what it can still prove after the fact. This file
states what is actually guaranteed, and — more usefully — what is not.

## Reporting

Private disclosure only. Do not open a public issue. Use GitHub's **Report a
vulnerability** (Security → Advisories) or contact the repository owner
directly. This repository is proprietary and unpublished; see `LICENSE`.

## Trust boundaries

| Asset | Protection | Fails if |
|---|---|---|
| `identity.key` (Ed25519, envelope-owned) | DPAPI `CryptProtectData` CURRENT_USER on Windows; `O_EXCL` 0600 on POSIX | the operator account is compromised — DPAPI user scope does not defend against code running as that user |
| `ledger/ledger.jsonl` | sha256 hash chain + per-entry Ed25519 signature | the signing key leaks; then history can be rewritten wholesale |
| `ledger/HEAD.json` | signed anchor, two-phase (pending → committed) | see "Known limits" below |
| `evidence/` | realpath jail + sha256 content binding, mixed-evidence poisoning rule | an attacker with write access to the evidence root can author artifacts; the jail bounds *where*, not *what* |
| `capability.json` | ledger-rebuildable with a **pinned** signer set | rebuilt without `trusted_pubs` — that path is now closed by default |
| epoch fence | strict equality against `epoch.json` | an attacker can write `epoch.json` |

## Adversary model

Defended:

- An occupant (either hemisphere) that lies, forges evidence hashes, path-traverses
  out of the evidence root, launders one forged ref among valid ones, replays a
  stale epoch, forges a *forward* epoch, or edits `capability.json` directly.
- An operator or occupant that edits, reorders, deletes mid-chain, or truncates
  the tail of the ledger without the envelope key.
- Concurrent processes racing on the ledger, capability matrix, or corrections log.
- Crash at any point in an append (torn line, lost anchor update).

Not defended:

- Anyone holding `identity.key`. There is no split custody, threshold signing,
  or external timestamping. Key compromise is total compromise.
- An adversary who can modify the CALLOSUM code itself before it runs.
- Content-level truth of an evidence artifact. The system proves an artifact
  with a given hash existed inside the jail and was cited; it does not prove
  the test it records was honest. `verified_correction` means
  verified-in-the-specified-environment, nothing stronger.
- Side channels: message bodies, positions, and memory are stored in cleartext.

## Known limits

1. **One-entry crash ambiguity.** With two-phase HEAD, an attacker who cuts a
   tail entry that was *pending* at crash time is indistinguishable from the
   crash itself. Committed entries remain protected. The window is one entry.
2. **Uncommitted-tail recovery requires pinning.** `verify()` will accept a HEAD
   anchor that trails a longer, validly-signed chain (the legacy single-phase
   crash window) **only** when `trusted_pubs` is supplied. Always pass it:
   `callosum verify` does.
3. **Evidence TOCTOU.** A ref is validated by hashing the file at transmit time.
   Nothing prevents the artifact from being replaced afterwards. The ledger now
   seals the path *and* sha256 of every delivered ref, so a later swap is
   detectable by re-hashing against the chain — but it is detected, not prevented.
4. **No external anchoring.** The chain proves internal consistency and
   authorship. It does not prove *when* an entry was made to a third party.
   Anything needed as dated evidence should be independently timestamped.
5. **`Monitor.is_dead` returns False for a hemisphere that never beat at all**
   (absence ≠ death). A hemisphere that fails to start is caught by the
   watchdog's no-verified-progress HALT, not by election.

## Operational rules

- Never root a `BrainEnvelope` inside this git checkout. `.gitignore` and the
  `secret-scan` CI job are backstops, not the control.
- Run `callosum verify --root <ROOT>` before trusting any session's output. It
  pins the envelope's own public key.
- Back up `ledger/` and `HEAD.json` together, atomically. The chain does not
  self-heal by design; a partial restore is indistinguishable from an attack.
