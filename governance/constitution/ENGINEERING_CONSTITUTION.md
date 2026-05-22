******************************************************************************
 * FILE:        /governance/constitution/ENGINEERING_CONSTITUTION.md
 * LAYER:       Governance Layer
 * MODULE:      Engineering Constitution
 * PURPOSE:     Supreme law governing all DCAVP engineering decisions
 * DOMAIN:      Governance Foundation
 * AUTHOR:      DCAVP Engineering System
 * CREATED:     2026-05-11
 * UPDATED:     2026-05-11
 * VERSION:     v0.1.0
 *
 * DESCRIPTION:
 * The Engineering Constitution is the highest-authority governance document.
 * It is immutable upon ratification. Amendments require a formal ADR and
 * unanimous review board approval.
 *
 * This document governs: all code, all policies, all catalogs, all releases.
 * It cannot be overridden by any operational requirement, deadline, or
 * customer request.
 *
 * DEPENDENCIES: None. This document has no dependencies.
 * CONSTRAINTS:  Immutable upon ratification. Amendment requires ADR.
 * LICENSE:      Apache-2.0
 ******************************************************************************

# DCAVP Engineering Constitution
## Version 0.1.0 — Phase 0 Ratification

---

## Article I — Supreme Principle: Determinism

**Section 1.1 — The Determinism Contract**

Every execution of the DCAVP kernel on identical inputs MUST produce
byte-identical outputs. This is not a goal. It is a non-negotiable contract.

Any code path that violates this contract is a CRITICAL architectural defect,
not a bug. It must halt the release pipeline immediately.

**Section 1.2 — Determinism Definition**

An execution is deterministic if and only if:

1. All data structures iterate in a defined, canonical order
2. All timestamps are UTC, ISO 8601, microsecond precision, no timezone offset
3. All file paths are absolute, normalized, symlink-resolved, case-preserved
4. All hashes use SHA-256 over canonically serialized inputs
5. All sorting operations use stable sort algorithms
6. No floating-point arithmetic appears in any decision path
7. No operating system entropy source is consulted without explicit seeding
8. No thread scheduling affects output ordering
9. All Unicode text is NFC-normalized before processing or storage

**Section 1.3 — Determinism Verification Mandate**

Every release MUST include a Determinism Self-Test that:

- Executes 100 runs of the same analysis
- Across at least 3 different host environments
- Asserts SHA-256 equality of all 100 output artifacts
- Halts the release pipeline on any failure

---

## Article II — Kernel Purity Law

**Section 2.1 — Forbidden Inside the Kernel**

The DCAVP kernel is the decision-making core. The following are ABSOLUTELY
FORBIDDEN inside any kernel module, with no exceptions and no overrides:

| Category | Examples |
|---|---|
| Artificial Intelligence | Neural networks, transformers, embeddings |
| Machine Learning | Classifiers, regressors, unsupervised models |
| Natural Language Processing | Tokenizers, semantic parsers, intent detectors |
| Probabilistic Logic | Bayesian inference, fuzzy logic, stochastic processes |
| Self-Modifying Code | Runtime code generation, eval, exec, reflection mutation |
| Dynamic Policy Mutation | Runtime rule changes, adaptive thresholds |
| Hidden Heuristics | Undocumented approximations, magic constants without citation |
| Non-deterministic Concurrency | Unsynchronized shared state, race conditions |
| Unbounded Recursion | Any recursive call without explicit depth ceiling |
| Uncontrolled FP Arithmetic | Float scoring, float thresholds in decisions |
| Unverified Third-Party Plugins | Dynamic plugin loading without hash verification |

**Section 2.2 — Permitted AI Usage (Outside Kernel Only)**

LLMs and AI tools are permitted exclusively in:

| Zone | Use | Kernel Impact |
|---|---|---|
| UI Explanation Sidecar | JSON-to-human translation | Zero |
| Documentation Generation | README, changelog drafts | Zero |
| Developer Onboarding | Chatbot assistance | Zero |
| Policy Drafting Assistance | Human-reviewed only | Zero |

Any LLM output that enters the decision path invalidates the artifact
signature. This invalidation is permanent and cannot be reversed.

---

## Article III — Knowledge Integrity Law

**Section 3.1 — Every Catalog Entry Must Have**

No entry in the Knowledge Catalog, Policy Library, Standards Map, or
Hazard Model may exist without ALL of the following fields:

- `source_reference`: Full citation (standard number, DOI, CVE-ID, RFC number)
- `publication_date`: ISO 8601 date of the referenced source
- `validation_status`: One of `[verified, pending_review, disputed]`
- `reviewer_id`: ID of the engineer who verified this entry
- `verification_date`: ISO 8601 date of verification

**Section 3.2 — Prohibited Catalog Content**

The following are grounds for automatic rejection of any catalog entry:

- General "best practices" without named source
- Assumptions presented as rules
- Rules copied from other tools without independent verification
- References to sources the reviewer has not personally verified
- Undated references
- References to anonymized or unavailable sources

**Section 3.3 — Catalog Immutability**

Once a catalog version is signed and released:

- No entry may be modified in place
- A new catalog version must be issued
- The old version remains available for replay forever
- The change log must document the exact modification and rationale

---

## Article IV — Clean Architecture Law

**Section 4.1 — Mandatory Layer Structure**

All DCAVP code must exist in one of these layers:

```
domain          ← Pure business logic. No I/O. No external dependencies.
application     ← Use cases. Orchestrates domain. No infrastructure.
infrastructure  ← I/O, storage, network, signing. Implements domain interfaces.
interfaces      ← CLI, API. Thin. No business logic.
adapters        ← Format conversion. No business logic.
governance      ← Audit, policy control. Read-only access to domain.
verification    ← Self-tests, replay engine. Reads all layers.
orchestration   ← Phase coordination. Reads application layer only.
```

**Section 4.2 — Dependency Direction Law**

```
PERMITTED:   outer_layer → inner_layer (via abstractions only)
FORBIDDEN:   inner_layer → outer_layer (in any form)
PERMITTED:   domain → domain (within same module)
FORBIDDEN:   domain → infrastructure (direct import)
```

Violation of dependency direction is a CRITICAL architectural defect.

**Section 4.3 — File Header Mandate**

Every source file MUST begin with the standard file header as defined in
`governance/coding_rules/FILE_HEADER_STANDARD.md`.

A file without a valid header will be rejected by the CI gate.

---

## Article V — Evidence and Replayability Law

**Section 5.1 — Every Decision Produces an Artifact**

No analysis result may exist without a corresponding Canonical Evidence Format
(CEF) artifact. Informal findings, "quick checks," or undocumented outputs are
architectural violations.

**Section 5.2 — Replay Guarantee**

Every CEF artifact must be accompanied by a Replay Bundle that enables exact
reproduction of the analysis using only:

- The Replay Bundle contents
- A DCAVP kernel binary of the matching version
- No external dependencies

**Section 5.3 — Cryptographic Integrity**

Every artifact in Phase 1+ must carry:

- SHA-256 hash of canonical serialized form
- Ed25519 signature from the authorized signing key
- Catalog version reference
- Execution seed

In Phase 0, artifacts carry `signature: "PHASE0-UNSIGNED"` with a mandatory
warning in the artifact header.

---

## Article VI — Release Law

**Section 6.1 — Release Gate Checklist**

No release may proceed unless ALL of the following pass:

- [ ] Determinism Self-Test: 100 runs, identical SHA-256
- [ ] Replay Test: All golden corpus artifacts replay to identical hash
- [ ] Type Check: `mypy --strict` zero errors
- [ ] Lint: Zero violations
- [ ] Forbidden Import Check: No forbidden module in kernel
- [ ] Forbidden Call Check: No forbidden function in kernel
- [ ] Knowledge Integrity: All catalog entries have valid citations
- [ ] Policy Signature: All policies signed (Phase 1+)
- [ ] Catalog Signature: All catalog versions signed (Phase 1+)
- [ ] Architecture Review: Dependency direction verified
- [ ] Documentation: All public functions documented to Google standard

**Section 6.2 — The Nuclear Option**

If the self-verification system (Phase 8) detects a determinism failure
in the release candidate, the following actions are MANDATORY:

1. Halt all release processes immediately
2. Invalidate all artifacts produced by the failing build
3. Issue a public Determinism Incident Report
4. Root-cause analysis before any new release attempt

---

## Article VII — Governance of This Constitution

**Section 7.1 — Amendment Process**

This Constitution may only be amended by:

1. Filing a formal ADR documenting the proposed change and rationale
2. Unanimous approval of the Engineering Review Board
3. External advisory approval for changes to Articles I, II, or III
4. Versioned re-release of this document

**Section 7.2 — Conflict Resolution**

In any conflict between:

- A customer requirement and this Constitution → Constitution prevails
- A deadline and this Constitution → Constitution prevails
- A market opportunity and this Constitution → Constitution prevails
- An engineer's judgment and this Constitution → Constitution prevails, with
  the engineer empowered to file an ADR for amendment

---

## Ratification

| Role | Status |
|---|---|
| Principal Architect | PHASE0-RATIFIED |
| Compliance Advisor | PENDING-PHASE1 |
| External Reviewer | PENDING-PHASE2 |

*This document is version-controlled, hash-verified, and immutable upon
Phase 0 milestone sign-off.*
