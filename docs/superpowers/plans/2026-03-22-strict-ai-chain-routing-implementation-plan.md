# Strict AI Chain Routing Implementation Plan

- Date: 2026-03-22
- Repository: `clash-override-chain-proxy`
- Depends on: `docs/superpowers/specs/2026-03-22-strict-ai-chain-routing-design.md`
- Branch: `spec/strict-ai-chain-routing`

## Objective

Implement strict AI chain routing without changing the user's core workflow:

- the user still chooses `chainRegion` manually
- when `strictAiRouting=true`, AI and related support traffic must be forced
  through the selected region's chain path
- if that strict path cannot be honored, the script must fail closed
- when `strictAiRouting=false`, compatibility mode keeps existing chain-region
  behavior with weaker guarantees and without the extra strict-mode validation layer

The work should preserve current non-AI routing behavior unless a small change
is required to avoid regressions while introducing the strict AI path.

## Constraints

- Keep the implementation in `src/家宽IP-链式代理.js`
- Preserve ES5 compatibility for Clash Party JavaScriptCore
- Avoid broad behavior changes to browser/media/social routing in this work
- Keep current user entry points stable where possible
- Prefer refactoring by extracting canonical data and control-flow stages rather
  than rewriting the whole script at once

## Deliverables

- Updated `src/家宽IP-链式代理.js`
- Expanded `tests/validate.js`
- Updated `README.md`
- No merge to `main` in this phase; all work stays on the version branch until review

## High-Level Phases

### Phase 1: Introduce canonical routing data

Goal:
Create a single source of truth for strict and direct object sets so DNS,
Sniffer, rules, and tests consume the same classification data.

Planned changes:

- Add a user-visible `strictAiRouting` option to `USER_OPTIONS`, default `true`
- Consolidate existing grouped constants into canonical buckets:
  - strict AI domains
  - strict support-platform domains
  - strict processes
  - direct-only domains
  - direct-only processes
  - direct-only network/CIDR rules
  - validation domains
- Encode conflict precedence explicitly:
  - direct-only overrides strict
- Keep current provider/domain coverage as the initial source set, then derive
  downstream outputs from the canonical buckets

Acceptance criteria:

- A reader can identify one canonical section in the script that defines strict
  and direct routing inputs
- No downstream stage keeps a conflicting hand-maintained copy of the same
  object list

### Phase 2: Rebuild DNS and Sniffer around the canonical sets

Goal:
Make DNS and Sniffer the first strict-routing layer.

Planned changes:

- Rework `buildNameserverPolicy` to read from canonical strict/direct sets
- Rework `buildDnsFallbackFilterDomains` to include strict AI/support/validation domains
- Rework `buildSnifferConfig` so strict key domains are driven by canonical
  strict data and direct exclusions by canonical direct data
- Keep fake-ip exclusions for local-network, router-management, and time-sync
  entries separate from direct-rule-only logic

Acceptance criteria:

- Key strict AI/support domains appear in:
  - `dns.nameserver-policy`
  - `dns.fallback-filter.domain`
  - `sniffer.force-domain` where applicable
- Direct exclusions such as Tailscale and local-network entries appear in the
  expected direct/sniffer exclusion paths
- `strictAiRouting=false` does not weaken canonical DNS and Sniffer generation

### Phase 3: Resolve the strict target directly

Goal:
Lock strict AI/support traffic directly to the selected chain exit without an
extra proxy-group hop.

Planned changes:

- Build or validate:
  - current region relay group
  - current region chain exit group
- In strict mode:
  - managed AI/support rules must target the selected region chain exit group directly
  - any legacy explicit AI proxy group must be removed from the generated config
- In compatibility mode:
  - managed AI/support rules still target the selected region chain exit group directly
  - no extra strict-mode validation layer is required

Acceptance criteria:

- Strict mode targets the selected chain exit directly
- Compatibility mode has the same emitted target but weaker validation guarantees
- Neither mode silently routes strict AI/support traffic to `DIRECT`, `节点选择`,
  or a different region

### Phase 4: Rebuild managed rule emission around mode-aware targets

Goal:
Capture AI/support traffic with explicit managed rules and deterministic targets.

Planned changes:

- Split managed rule construction into:
  - direct-only process/network rules
  - strict AI/support process rules
  - strict AI/support domain rules
  - non-AI managed categories that remain behaviorally unchanged
- Add a clear target resolver:
  - strict mode target = selected region chain exit group
  - compatibility mode target = selected region chain exit group
- Keep rule ordering deterministic:
  - direct-only protections first
  - managed AI/support process rules next
  - managed AI/support domain rules after that
  - existing non-AI behavior preserved afterward
- Keep conflict filtering explicit:
  - managed rule identities win over existing subscription rules

Acceptance criteria:

- Every strict AI/support rule uses exactly one resolved target for the current mode
- Existing subscription rules that conflict with managed AI/support rules are removed
- No strict AI/support rule falls through to `MATCH` or old subscription targets

### Phase 5: Add fail-closed strict validation

Goal:
Make strict mode refuse misconfigured or incomplete routes.

Planned changes:

- Add explicit validation helpers for:
  - selected region relay resolution
  - valid `manualNode`
  - direct strict-target correctness for key managed rules
  - removal of any legacy explicit AI proxy group
  - absence of target leakage for key managed rules
- Keep compatibility mode on baseline checks only:
  - selected region relay resolution
  - valid `manualNode`

Acceptance criteria:

- `strictAiRouting=true` throws on any broken strict-path construction
- `strictAiRouting=false` does not pretend to provide the same guarantees
- Error messages identify the broken guarantee clearly

### Phase 6: Expand regression coverage

Goal:
Turn `tests/validate.js` into a strict-routing safety net.

Planned tests:

- strict mode default path
  - no legacy explicit AI proxy group remains
  - key AI/support domains map directly to the selected chain exit
- compatibility mode path
  - key AI/support rules target the selected chain exit group directly
  - DNS and Sniffer outputs remain canonical
- direct-only protection
  - Tailscale processes, domains, and CIDRs stay direct
  - domestic AI remains direct
- conflict precedence
  - direct-only objects override strict objects
- hard failure cases
  - missing region relay
  - invalid `manualNode`
  - strict target mismatch
- leakage checks
  - key AI/support domains do not remain mapped to `DIRECT`, old subscription
    rules, or unrelated groups
- toggle isolation
  - process toggles only affect process rules and do not weaken strict DNS/Sniffer behavior

Acceptance criteria:

- `node tests/validate.js` covers both strict and compatibility modes
- A regression in target selection or leakage fails locally without manual inspection

### Phase 7: Rewrite README contract

Goal:
Align user-facing docs with the new routing contract.

Planned changes:

- Document `strictAiRouting` as a user-visible option
- Explain strict mode:
  - selected `chainRegion`
  - direct lock to the selected chain exit
  - fail-closed behavior
- Explain compatibility mode:
  - same selected region
  - weaker guarantees
- Clarify what this repository does and does not promise
- Add a validation checklist for:
  - proxy-group bindings
  - exit IP verification
  - AI service / App / CLI consistency

Acceptance criteria:

- README reflects the exact spec contract
- User can tell the difference between strict mode and compatibility mode
- User can verify the selected chain path after changing `chainRegion`

## File-Level Plan

### [`src/家宽IP-链式代理.js`](/Users/az/Projects/claude/repositories/clash-override-chain-proxy/src/家宽IP-链式代理.js)

- Add `strictAiRouting` to `USER_OPTIONS`
- Introduce canonical strict/direct data buckets
- Add target-resolution helpers for strict vs compatibility mode
- Remove any legacy explicit AI proxy group from generated output
- Refactor DNS, Sniffer, and rule generation to read from canonical data
- Add strict validation helpers and mode-aware failure behavior

### [`tests/validate.js`](/Users/az/Projects/claude/repositories/clash-override-chain-proxy/tests/validate.js)

- Extend test fixtures for strict mode and compatibility mode
- Add explicit assertions for:
  - strict mode direct-to-chain-exit targeting
  - compatibility mode direct-to-chain-exit targeting
  - legacy explicit AI proxy group removal
  - direct-only precedence
  - no leakage
  - hard failure behavior

### [`README.md`](/Users/az/Projects/claude/repositories/clash-override-chain-proxy/README.md)

- Document `strictAiRouting`
- Reframe the contract around forced current-region routing
- Explain strict vs compatibility mode
- Add verification and failure-behavior guidance

## Execution Order

1. Add canonical routing data and `strictAiRouting`
2. Refactor DNS and Sniffer to consume canonical data
3. Add direct strict-target resolution and legacy group cleanup
4. Refactor managed rule emission around mode-aware targets
5. Add strict validation helpers
6. Expand tests until both modes are covered
7. Rewrite README to match shipped behavior

This order keeps the highest-risk plumbing changes ahead of documentation and
ensures tests land before user-facing wording is finalized.

## Key Risks

- Refactoring shared domain lists may accidentally change existing non-AI routing
- Strict mode may over-capture provider-owned domains that are unrelated to AI continuity
- Compatibility mode may drift into an under-specified halfway state if not tested explicitly
- DNS/Sniffer changes may alter behavior even when rule outputs look unchanged

## Risk Mitigations

- Keep non-AI routing categories behaviorally unchanged unless regression prevention requires a minimal edit
- Reuse existing grouped constants as the initial extraction source
- Add explicit tests for both `strictAiRouting=true` and `strictAiRouting=false`
- Validate key outputs at multiple layers:
  - DNS
  - Sniffer
  - proxy-group cleanup
  - rules

## Plan Exit Criteria

The implementation can be considered ready for coding only when:

- the plan is approved by the user
- strict and compatibility mode contracts are both testable
- file-level change scope is understood
- non-AI behavior preservation is treated as an explicit regression constraint
