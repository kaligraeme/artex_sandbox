# ARTEX tool state — 16 November 2026

This records the local tool after integration commit `fe110c1` and the subsequent full-estate recording and canary-visibility changes. It describes implemented behavior and verification limits; it does not certify product effectiveness or remote publication.

## Running the tool

Use `start.bat` on Windows or `start.sh` on macOS/Linux. Both serve the static application locally; the browser runs the deterministic model in `js/wire-engine.js`. The model also runs headlessly under Node for validation. There is no separate production simulation service. The current local demo was started at `http://127.0.0.1:8080/wire.html`.

The Range Operations presentation remains the approved v2 design: four defense cards, ARTEX / Pre-LLM toggle, topology, moving attackers, stopwatch, SOC tickets, search, Replay, Results and New Infra. The later user-requested visibility correction adds an existing-style `Canary deployed` badge to a decoy when the selected mode enables canaries. A real canary signal changes that badge to `Canary alert`. Deployment alone earns no containment credit. Search for `Canary` to locate the decoy in a dense estate.

## Random infrastructure and repeatable comparisons

New Infra draws a reference context and conventional attacker group, generates a fresh seeded estate, and rejects a repeat of the previous appliance roster. The generator selects assets, variant mappings, findings, credentials, relationships, sensor placement and response assumptions. The reference catalog is context, not proof that every referenced CVE is executable or applicable to the estate.

Attacker and defense changes reuse the estate. Replay repeats the same modeled inputs; Results advances the same event history. Resizing redraws the estate rather than generating another one. Fixed seeds in tests and recordings make scenarios reproducible; they do not disable random creation in the application.

All retained infrastructure objects are rendered at the start. Attack effects change their state; objects are not progressively created by discovery. Large estates scroll vertically and narrow views can scroll horizontally. An object outside the current viewport still exists in the estate.

## Logical connections and backend checks

Connections are generated from `ALLOWED_CONNECTIONS`, a curated mapping of service families. Examples include gateway → application, application → PostgreSQL, and reporting service → SQL Server. Normal generated links join adjacent modeled layers and point from the permitted source family to the target family. Special authored routes, diagnostic access and deployed decoys have explicit purposes and prerequisites.

Each relationship records source, target, direction, protocol, trust boundary, required source capability and purpose. The generator selects a protocol from the target interfaces. Structural validation checks identifiers, references, direction, nonempty interfaces/protocols, action ordering and control declarations before simulation. A syntactically valid but incompatible route is allowed as an inaccessible scenario; action evaluation rejects it.

Traversal requires a directed relationship, actual source access, the required source capability and a matching target interface. CVE actions additionally require the declared product, affected version, configuration, interface and authentication assumptions. Credential actions check acquisition, target scope, permissions and expiry/revocation. A diagram edge alone grants no access.

`scripts/test-wire-model.cjs` checks connection mappings and adjacency, negative product/version/protocol/direction cases, source capabilities, credential scope and revocation, replay and authored walkthroughs. `scripts/test-remediation.cjs` checks malformed declarations and inaccessible routes. `scripts/review-remediation.cjs` checks successful events against established source access and causal timestamps over 7,200 generated runs. These checks are headless and add no verification panel to the UI.

This proves consistency against the authored simulation rules. It does not independently prove that each enterprise is a realistic deployable architecture. Source-side egress capabilities, detailed firewall/ACL rules, full service dependencies, real product version ranges and every generated archetype still need richer modeling and audit. The connection allowlist and target-derived protocol selection remain simplifying assumptions.

## Attack and defense contracts

ARTEX currently has three scheduled workers; conventional profiles have one. Successful source access unlocks downstream work. All modes share the default 1,000 evaluated-transition ceiling. Rendering density does not determine exploration allowance. Impact and incomplete exploration remain independent facts.

Virtual patching needs a modeled matching rule and inspected surface. Coverage declarations carry reasoned `modeled`, `unsupported`, `unknown` or `not_applicable` states; only modeled controls can mitigate. Executable catalog and variant mappings are enumerated in tests. The four imported HTTP examples have matching/uncovered-route fixtures; non-HTTP traffic remains outside HTTP inspection. These are simulation declarations, not evidence that arbitrary production deployments are protected.

SOC containment requires observation, collection, decision, authority and successful enforcement in the relevant session scope. Canary contact contributes evidence. An untouched canary supplies no signal. Reads before enforcement remain impact; enforcement at completion cancels the effect. Queued and in-flight suppression record their phase and causal timestamps and are counted separately from new prevented attempts. `classifyRun()` supplies result facts and styling.

The integration guide remains the detailed acceptance checklist. The commits do not establish an exhaustive advisory/KEV evidence audit, all requested browser outcome fixtures, or a complete independent sensitivity study. Current direct browser outcome coverage includes a neutral no-access case in addition to the general mode/replay matrix. Paired sensitivity probes vary response latency, scope and telemetry placement; they do not yet independently vary every coverage and canary-placement assumption.

## Recordings and evidence

| Artifact | Scope |
| --- | --- |
| `assets/ARTEX_vs_PreLLM_v2.gif` | Earlier focused nine-asset estate, eight comparisons. |
| `assets/ARTEX_vs_PreLLM_full_estate.gif` | Full 54-asset seed 1853, fixed overview, eight comparisons; 1440 × 2058, 306 frames, 117.7 seconds, approximately 5.76 MiB. |
| `docs/artex-comparison-realism-review.md` and `docs/comparison-review-evidence.json` | Historical Claude review of `286cf02`; historical counts must not be presented as current results. |

The full-estate GIF was recorded before the subsequent `Canary deployed` badge fix. Its topology is complete, but that later badge appears only in the live tool or a fresh recording. The two untracked `wire_*` GIFs dated 13 November are legacy recordings and are excluded from this handoff. Capture instructions and interpretation are in [v2-animation.md](v2-animation.md).

## Verification and handoff

The latest model and remediation suites passed after the canary correction. The browser suite passed 72 attacker/defense/seed/viewport combinations, plus neutral-result, canary-deployment visibility, New Infra, replay, search, keyboard and animation checks. The integration sweep previously passed 7,200 runs at `fe110c1`, with independent paired sensitivity probes; the subsequent changes affect recording and canary presentation rather than model behavior. The full-estate capture validated eight runs, unchanged estate inputs, marker counts and browser console errors. The encoder checked dimensions, duration and looping metadata; the initial full-estate frame was visually inspected.

Changes in this handoff preserve the frozen layout and controls. Documentation and source are committed locally; pushing or publishing is a separate action.
