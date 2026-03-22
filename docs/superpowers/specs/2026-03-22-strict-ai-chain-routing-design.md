# Strict AI Chain Routing Design

- Date: 2026-03-22
- Repository: `clash-override-chain-proxy`
- Status: Approved for planning draft

## Summary

This repository should continue to let the user manually choose `chainRegion`.
The design goal is not to lock the user into a long-term region. The goal is:

When the user selects a `chainRegion`, AI services and related support services
must be forced through that region's chain proxy path. If that path is not
valid, the script must fail closed and throw an error instead of falling back
to `DIRECT`, another region, or a broad default proxy group.

The design combines two enforcement strategies:

1. Rule enforcement: AI and related traffic must be explicitly captured by
   managed DNS, Sniffer, process, and domain rules.
2. Fail-closed direct-target enforcement: in strict mode, all managed
   AI-related traffic must target the chain proxy exit for the currently
   selected `chainRegion` directly, and the script must refuse silent fallback.

## Goals

- Preserve manual region selection through `chainRegion`.
- Force AI and related traffic through the currently selected chain region.
- Fail closed when the selected chain path is unavailable or misconfigured.
- Prevent silent leakage to `DIRECT`, `节点选择`, `MATCH`, or another region.
- Keep Tailscale, domestic AI, and local-network traffic out of the strict path.
- Make these guarantees testable and visible in documentation.

## Non-Goals

- Guarantee that platforms will never suspend or restrict an account.
- Automatically choose the safest long-term region for the user.
- Route all normal web browsing through the chain path by default.
- Expand the repository into a generic multi-profile proxy manager.
- Redesign existing browser, media/social, or other non-AI chain-routing behavior
  beyond the minimum changes required to prevent regression while introducing
  strict AI routing.

## Current Context

The current repository already has strong building blocks:

- A single ES5 Clash Party override script injects proxies, proxy groups, DNS,
  Sniffer, and managed rules.
- `chainRegion` and `manualNode` already support explicit user control.
- Missing region matches and invalid manual nodes already throw errors.
- Tests already verify some critical ordering and duplication constraints.

The current gap is not "missing features" in the broad sense. The gap is that
strict routing intent is spread across multiple concerns in one file and is not
modeled as a first-class guarantee. The design needs to make "forced current
region routing with fail-closed behavior" explicit in data, control flow, tests,
and documentation.

## Design Decisions

### 1. Keep `chainRegion` as the manual selector

`chainRegion` remains the active region chosen by the user. This repository must
not reinterpret it as a long-term locked profile or replace it with a mandatory
`primaryRegion` model.

The user may switch regions manually. The repository's responsibility is narrower:
after a region is selected, managed traffic must consistently and only use that
region's chain path.

### 2. Introduce a strict AI routing concept

The script should treat AI-related traffic as a dedicated managed class with
stronger guarantees than general foreign traffic.

This class includes:

- Core AI services
- AI static assets and APIs
- Authentication, verification, download, and IDE support platforms
- AI desktop app processes and CLI executables
- Validation endpoints used to confirm the active exit path

This class should be named explicitly in the implementation to make the routing
intent obvious during maintenance.

### 3. DNS and Sniffer come first

Strict routing must start with correct identification, not only with late-stage
rules. DNS and Sniffer should be the first enforcement layer because they reduce
misclassification caused by fake-ip behavior, CDN indirection, pure-IP requests,
and app behavior that does not map cleanly to a short domain allowlist.

Managed strict objects must be reflected in:

- `dns.nameserver-policy`
- `dns.fallback-filter.domain`
- `sniffer.force-domain` for key domains

Direct-only exclusions must be reflected in:

- direct DNS-related behavior
- `sniffer.skip-domain`

### 4. Use direct strict targeting

Managed AI-related traffic should target the selected region chain exit group
directly in the final emitted rules.

That target must resolve to exactly one valid path:

- the chain exit for the currently selected `chainRegion`

The script must not quietly degrade that target to:

- `节点选择`
- unrelated regional groups
- a general-purpose fallback proxy
- `DIRECT`

If an old explicit AI proxy group exists from a previous version, the script
should remove it during generation so the final config does not carry redundant
or misleading routing layers.

### 5. Fail closed

If the strict path cannot be constructed correctly, the script must throw an
error and stop.

This includes at least:

- selected region has no usable relay node or reusable region group
- `manualNode` does not resolve to an existing node or proxy group
- strict AI rules do not target the selected chain exit directly
- a legacy explicit AI proxy group remains present in the generated config
- managed AI rules would otherwise fall through to existing subscription rules

The repository must prefer a visible failure over an invisible routing mistake.

## Managed Traffic Boundary

### Must be forced through the selected chain region

#### Core AI services

- Anthropic and Claude properties
- OpenAI and ChatGPT properties
- Gemini, AI Studio, NotebookLM, and related Google AI properties
- Perplexity
- OpenRouter
- xAI / Grok

#### AI static assets and APIs

- Claude-related static or content domains
- OpenAI static and user-content domains
- Gemini and Google AI API domains
- Perplexity CDN domains
- Other explicitly tracked support domains required for session continuity

#### Authentication, verification, download, and IDE support platforms

Support-platform scope should not be inferred from broad vendor names alone.
Implementation planning should start from the existing grouped constants in
`src/家宽IP-链式代理.js` and keep capture limited to domains that materially
affect AI login continuity, verification, downloads, updates, or IDE workflows.

Concrete initial host groups:

- Google: `google.com`, `googleapis.com`, `googleusercontent.com`,
  `gstatic.com`, `ggpht.com`, `gvt1.com`, `gvt2.com`, `withgoogle.com`,
  `cloud.google.com`
- Microsoft: `microsoft.com`, `live.com`, `windows.net`, `office.com`,
  `office.net`, `office365.com`, `m365.cloud.microsoft`, `sharepoint.com`,
  `onenote.com`, `onedrive.com`, `microsoftonline.com`, `msftauth.net`,
  `msauth.net`, `msecnd.net`
- Developer platforms: `github.com`, `visualstudio.com`, `vsassets.io`,
  `vsmarketplacebadges.dev`

Selection rule for additions:

- include only domains that are required for authentication, static assets,
  redirect completion, downloads, extension delivery, or IDE service continuity
- do not include ordinary browsing domains that are merely owned by the same
  vendor but are unrelated to the AI workflow continuity problem

#### Processes

- AI desktop apps
- AI CLI executables
- IDE and developer platform apps that materially affect AI workflows

#### Validation endpoints

- endpoints such as `ping0.cc` and `ipinfo.io` that the README uses to verify
  the effective chain exit

### Must stay outside the strict chain path

- Tailscale control plane domains, MagicDNS domains, Tailnet CIDRs, and related processes
- Domestic AI domains already treated as direct-only
- Local-network and router-management domains
- Time sync and local-network support domains already excluded from fake-ip

Local-network, router-management, and time-sync entries are primarily fake-ip
and Sniffer exclusion inputs. They should not be mistaken for a requirement to
emit matching direct domain rules unless the current script already does so for a
specific subset.

### Conflict precedence

If an object is ever classified into both a strict set and a direct-only set,
direct-only classification wins.

This rule applies consistently to:

- canonical object assembly
- DNS generation
- Sniffer generation
- process and domain rule generation
- regression tests

The implementation plan must treat this as an invariant rather than an
accidental byproduct of rule ordering.

## Proposed Internal Structure

The implementation should remain a single Clash Party script for now, but its
internal flow should be reorganized into four explicit stages.

### Stage 1: Managed object assembly

Build a single canonical data source for:

- strict AI domains
- strict support-platform domains
- strict processes
- direct-only domains
- direct-only processes
- direct-only network/CIDR rules
- validation domains

DNS, Sniffer, rule generation, and tests should derive from the same data source
instead of maintaining partially overlapping lists.

For planning purposes, the extraction starts from the existing domain/process
constants in `src/家宽IP-链式代理.js`, then consolidates them into one canonical
source used by all downstream stages.

### Stage 2: DNS and Sniffer enforcement

Generate DNS and Sniffer configuration from the canonical strict/direct sets.

Strict sets feed:

- `nameserver-policy`
- `fallback-filter.domain`
- `force-domain`

Direct sets feed:

- direct-leaning DNS behavior
- `skip-domain`

This stage exists to identify strict traffic early and consistently.

### Stage 3: Strict target resolution

Create or validate:

- current region relay group
- current region chain exit group
- strict AI managed target

In strict mode, the strict AI managed target is the selected region chain exit
group itself. The script should also remove any legacy explicit AI proxy group
to prevent redundant routing layers from surviving in the output.

### Stage 4: Managed rule emission and fail-closed validation

After DNS, Sniffer, and proxy groups are valid:

- emit `PROCESS-NAME` rules for strict processes
- emit `DOMAIN-SUFFIX` rules for strict domains
- emit direct-only process and network rules
- remove conflicting existing subscription rules
- verify the final managed targets and throw if the strict contract is broken

## Configuration Model

The design keeps the existing user-facing model with limited adjustments.

### Keep

- `chainRegion`
- `manualNode`
- `enableAiCliProcessProxy`
- `strictAiRouting`

### Change

- `strictAiRouting` should be a user-visible config switch and should default to `true`
- `enableBrowserProcessProxy` should default to `false`

Reason:
The design goal is not broad browser unification. The goal is strict routing for
AI and related support services. Full-browser process capture should remain
optional because it widens the trust boundary and adds traffic unrelated to the
account continuity problem.

`strictAiRouting` should not remain an internal-only concept. It should be
explicit in the user-facing configuration so the repository's routing contract is
visible, inspectable, and intentionally controlled by the user.

When `strictAiRouting` is `true`, the script must enforce the full strict path:

- DNS and Sniffer strict object enforcement
- direct targeting of the selected `chainRegion` chain exit
- fail-closed validation

When `strictAiRouting` is `false`, the script enters an explicit compatibility
mode with a weaker contract:

- canonical strict/direct object assembly remains the same
- DNS and Sniffer generation remain the same
- AI-related traffic is still routed by managed process and domain rules, and
  those rules continue to target the current `chainRegion` chain exit group directly
- fail-closed validation is limited to existing baseline checks such as selected
  region relay resolution and valid `manualNode` lookup
- the repository no longer guarantees that all managed AI/support traffic uses
  only the selected chain exit, or that strict-path leakage checks pass

This mode exists for user-controlled fallback behavior and backward
compatibility, not as an implicit degradation path. The implementation must make
the mode distinction obvious in code, tests, and documentation.

Non-AI chain-routing categories in the current script, including browser and
media/social routing, remain behaviorally unchanged in this work unless a change
is required to keep the new strict AI path from regressing them.

## Error Handling

Errors should be specific and action-oriented. They should tell the user what is
missing and which guarantee cannot be honored.

Examples of failure classes:

- selected region cannot build a relay target
- strict AI target does not point to the selected chain exit directly
- a legacy explicit AI proxy group remains in the generated config
- managed rules would leak into non-strict targets

When `strictAiRouting` is `true`, the script should not degrade to a weaker
routing mode.

## Testing Strategy

The existing `tests/validate.js` should evolve into a strict-routing regression
suite focused on invariant protection.

Required assertions:

1. Strict domain coverage
   All strict objects appear where expected in DNS and Sniffer outputs.
2. Direct-only protection
   Tailscale, domestic AI, and local-network exclusions remain direct.
3. Strict direct-target invariant
   Strict AI/support rules point directly to the selected chain exit, and no
   legacy explicit AI proxy group remains in the generated config.
4. Hard failure behavior
   Missing region targets, invalid manual nodes, or malformed strict groups throw.
5. No leakage
   Key AI/support domains do not remain mapped to `DIRECT`, old subscription
   rules, general-purpose groups, or another region.
6. Toggle isolation
   Process toggles only affect process rules and do not weaken DNS/Sniffer/domain
   enforcement for strict objects.
7. Conflict precedence
   Objects present in both strict and direct-only sets resolve to direct-only
   behavior everywhere the canonical data source is consumed.

## Documentation Changes

The README should state the contract precisely:

- The user manually chooses `chainRegion`.
- Managed AI and related traffic is forced through that selected chain region.
- If the chain path cannot be honored, the script fails with an error.
- The repository reduces routing mistakes and leakage risk; it does not promise
  immunity from provider-side account restrictions.

The README should also add a validation flow that checks:

1. selected proxy group bindings
2. effective residential exit IP
3. AI service, support platform, App, and CLI consistency with the selected region

## Risks and Tradeoffs

- Maintaining a broader strict object set increases curation cost.
- Some support domains will remain partly evidence-based and require periodic review.
- A stronger fail-closed model improves safety but raises the chance of visible
  breakage when upstream subscriptions or app behaviors change.

These are acceptable tradeoffs because the repository's value proposition is
controlled routing, not maximum automatic availability.

## Planning Focus

Implementation planning should focus on:

1. extracting canonical strict/direct object sets
2. enforcing direct strict targeting to the selected chain exit and removing
   any legacy explicit AI proxy group
3. reordering the control flow so DNS and Sniffer are enforced before late rules
4. expanding tests around leakage and hard-failure behavior
5. rewriting README language around the new contract
