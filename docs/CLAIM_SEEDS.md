# CALLOSUM — Provisional Claim Seeds

**PRIVATE — Ron Blake personal IP. Not a public disclosure.** This repo is an
unpublished implementation record. Per standing order: no outreach, publication,
or benchmark release referencing these mechanisms before the provisional
covering them (MELD family or standalone) is filed.

## Independent Claim Seed 1 — Inhibitory evidence-gated interhemispheric coupling

A method for governed collaboration between at least two independently operating
AI agents, comprising: (a) maintaining a per-subtask **authority record** derived
from adjudicated task outcomes between the agents; (b) receiving, at a coupling
component logically interposed between the agents, an influence message from a
first agent directed at a second agent; (c) classifying the message as
influence-bearing or non-influence-bearing by message kind; (d) for an
influence-bearing message from an agent lacking authority on the message's
subtask, **suppressing transmission unless the message carries at least one
evidence reference that cryptographically binds (content hash) to a verifiable
execution artifact resolving within a controlled evidence root**; (e) recording
every suppression, delivery, and rejection as an entry in a hash-chained,
digitally signed, append-only ledger anchored by a separately persisted head
record; and (f) classifying any subsequent position change of the receiving
agent as evidence-driven or assertion-driven according to whether its causal
message carried validated evidence, and computing therefrom a conformity
(sycophancy) metric.

Distinguishing emphasis: the coupling is **inhibitory by default** (suppression
absent evidence or authority), not aggregative; dissent is damped in-flight but
persisted immutably.

## Independent Claim Seed 2 — Competence-profile-driven functional reassignment on agent loss

A method for fault handling in a multi-agent system, comprising: (a) maintaining
per-agent, per-subtask competence profiles from adjudicated outcomes; (b)
detecting loss of an agent via missed liveness signals within a bounded
detection budget; (c) electing a surviving agent **by aggregate competence score
rather than static identifier**; (d) reassigning the lost agent's per-subtask
authorities to the survivor while **flagging as unbacked each subtask on which
the lost agent's measured competence exceeded the survivor's by a margin**; (e)
entering a degraded operating mode that (i) requires validated evidence for all
influence messages, (ii) reduces autonomous action scope, and (iii) shortens
checkpoint intervals, the mode record enumerating the unbacked subtasks; and (f)
incrementing a fencing epoch such that messages bearing a prior epoch are
rejected, whereby a falsely-declared-lost agent cannot re-enter except through a
quarantined rejoin requiring validated evidence for its next K influence messages.

## Dependent seeds

1. Sealed independence commits: agent positions hash-committed to the ledger
   prior to first contact; reveal verifies stored text against commits (tamper
   halts the session).
2. Fast-agreement tripwire: convergence within a time window with zero
   evidence-bearing exchanges triggers a mandatory independent-validation action.
3. Three-status correction gate: {model_disagreement, collaborative_agreement,
   verified_correction}; only execution-verified corrections are publishable;
   agreement between models is structurally non-publishable.
4. Quarantine-not-delete trust dampening with evidence-earned release credits.
5. Mixed-evidence poisoning rule: one invalid reference invalidates the entire
   message's evidence set (no laundering).
6. HEAD-anchored tail-truncation detection over the hash chain.
7. Cross-vendor heterogeneous instantiation: hemispheres are adapters over
   distinct foundation-model vendors coupled solely through the file-drop bus.
8. Envelope-persistent identity: an Ed25519 identity and memory store owned by
   the envelope, surviving occupant (model) hot-swap, with swaps sealed to the
   ledger.

## Design-around note (prior art)

Hippocratic AI, US 12,142,371 ("polyadic/constellation architecture"): primary
model with **support models bounded to specialist verification duties**,
hub-and-spoke. CALLOSUM is distinguishable on: (1) peer symmetry — both agents
are general, full-surface actors, not bounded specialists; (2) the inventive
locus is the **inhibitory gate + authority record + sealed dissent ledger**, not
the presence of multiple models; (3) competence-profile reassignment with
unbacked-capability flagging and degraded-mode posture change has no analog in
the constellation scheme. FTO search still required before filing/marketing.
