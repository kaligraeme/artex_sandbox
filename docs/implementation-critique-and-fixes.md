# Implementation Critique & Recommended Fixes: Is the Wire Simulation Realistic?

**Date:** 2026-11-15  
**Scope:** Critique of the Wire diagram simulation ([wire.html](../wire.html), [js/wire-engine.js](../js/wire-engine.js), [assets/wire-defense-catalog.json](../assets/wire-defense-catalog.json), [scripts/test-wire-model.cjs](../scripts/test-wire-model.cjs)) against its objectives:
1. **Realistic comparison of pre-2023 human-led attacks vs. ARTEX-era agentic attacks** across plausible enterprise infrastructure.
2. **Meaningful comparison of defensive mechanisms**—**Virtual Patching**, **Canaries**, and **Agentic SOC/SOAR** (plus combined defenses).

---

## Executive Verdict

**Not yet—the timeline assumptions are grounded in real-world reporting, but the simulation mechanics and UI undermine realism.**

Specifically:
- **What *is* well-grounded:** Using an **80–270 minute** foothold-to-read window for Pre-2023 attacks (based on CrowdStrike 84–98 min breakout observations), a **45–75 minute** window with a **50-second API-to-data execution burst** for ARTEX-like attacks (reflecting GTIG/Mandiant observations of short execution bursts between longer pauses), and a **60-second SOAR containment window** (15 s decision + 60 s enforcement) is a reasonable, historically anchored modeling choice for an enterprise simulation.
- **Why the simulation still fails to be realistic:** In the active UI (`wire.html`), `simulateWireRun` + `seedExercise` bypasses the engine's actual CVE, protocol, and defensive rule evaluation; binds *defender visibility* to random pre-2023 gang names; offers identical attack paths and capabilities for old and new attackers; fakes early canaries on Layer 0 perimeter firewalls; omits standalone Canaries; and hides the sub-minute SOAR timing race behind minute-rounded clock labels. Meanwhile, `js/wire-engine.js` already contains ~1,100 lines of a much cleaner comparison engine (`evaluateComparisonMatrix` / `COMPARISON_FIXTURES`) that `wire.html` no longer calls.

---

## Detailed Critique: Where Realism Breaks Down

### 1. The Main Attack Path Bypasses Real Exploits, Protocols, and Defense Rules (`seedExercise`)

`wire.html:1064` generates every estate with `seedExercise: true`. While `js/wire-engine.js` defines 51 asset groups, explicit protocol/interface checks, credential scopes, and per-CVE `KEV_MITIGATION_RULES` (`lines 222-277`), `seedExercise` (`lines 1264-1314`) overrides the primary path with generic `kind: 'exercise'` placeholders (`"Edge access weakness"`, `"Overbroad session access"`, `"Internal service access weakness"`, `"Overbroad sample record access"`).

- **Action prerequisite bypass:** `evaluateDistinctActions` (`js/wire-engine.js:593-607`) returns immediately on `exercise` findings before checking product, version, configuration prerequisites, protocol compatibility, or credentials.
- **Virtual Patching reduced to a coin flip:** In `evaluateDefense` (`lines 843-848`), `patch` mode on the exercise path checks only `patchCovered = !fromLogs && rng() < 0.65` (`line 1294`) at Layer 0. A non-HTTP IPsec VPN appliance (`zyxel-atp`, `interfaces: ['vpn']`) can be "blocked by edge WAF" on the exercise path, contradicting `evaluateDefense`'s own `WAF BLIND` rule (`line 907`) used on non-exercise branches in the same graph.
- **Agentic SOC rules disabled:** In `simulateWireRun`, `timing.respond` is `true` for `soc` and `soc-canary`, causing `simulateEstate` (`line 1088`) to pass `'baseline'` into `evaluateDefense`. Every per-CVE behavioral/ML rule in `KEV_MITIGATION_RULES[cveId].ml` and `SOAR_DETECTION_RATE` is ignored.

---

### 2. Old vs. New Attacks Differ Only in the Clock and Cosmetic Lanes

Switching `Attacker` between `Pre-2023` and `ARTEX-like` in `wire.html` does not model how pre-2023 human-operated intrusions and post-2023 agentic frameworks actually behave differently on the same infrastructure:

1. **Random Pre-2023 gang choice mutates *defender* visibility (`WIRE_ATTACKERS`, `js/wire-engine.js:2522-2529`):**
   - `wire.html:1062` picks one of `lockbit`, `conti`, `blackcat`, `hive`, or `revil` per generated estate.
   - `WIRE_ATTACKERS` hardcodes `boundarySignal` (`'all'`, `'first'`, `'none'`) and `canary` (`'early'`, `'late'`, `'untouched'`) per gang—putting `none`/`untouched` on `revil` and `none`/`late` on `blackcat`, while giving `artex` `all`/`early`.
   - In reality, telemetry coverage and canary deployment belong to the **target infrastructure**, not the attacker group. When an estate draws `revil`, `Pre-2023` bypasses both `Agentic SOAR` and `Agentic SOAR + Canary` (`"No matching signal"`), whereas `ARTEX-like` on the *exact same estate* triggers both signals and gets contained—inverting the intended security comparison.
2. **Identical attack paths and TTPs:** Both profiles traverse the exact same `seedExercise` route and succeed against the exact same weaknesses.
   - Real-world **Pre-2023** operations relied on noisy host tooling (Cobalt Strike, Mimikatz, Kerberoasting, `vssadmin`, RDP/SMB lateral movement), sequential human operator decisions/handoffs, and static exploit payloads.
   - Real-world **ARTEX-like** operations probe multiple paths concurrently, chain API tokens autonomously without human handoff stalls, re-encode payloads adaptively when blocked by generic WAF signatures, and stay low-volume on HTTP/API paths (evading volumetric SIEM thresholds).
   - `lanes: 3` vs. `1` (`line 2570`) is purely a visual SVG animation change in `showProbes()` (`wire.html:847-868`); it does not let ARTEX exploit/reach branches that a sequential human operator misses within a time budget (even though the unused `capability-45s` fixture in `js/wire-engine.js` was built for this).
3. **Minute-rounded clock hides the modeled sub-minute race:**
   - `wireTiming()` (`js/wire-engine.js:2536-2551`) places ARTEX's Layer 1 boundary crossing at `readTime - 50s` and Layer 2 pivot at `readTime - 35s` specifically to race against the 60-second SOAR containment window (`15s` decision + `60s` enforcement).
   - However, `formatEstimate()` (`wire.html:821-829`) rounds all timestamps `>= 60 s` to whole minutes. On screen, Layer 1, Layer 2, protected read, and late containment collapse into identical `~1 hr` (or `~59 min`) labels in `#model-clock` and the SOC ticket ticker.
   - Additionally, `playRun()` (`wire.html:1015`) paces every phase at `>= 650 ms` wall-clock time regardless of modeled time, so a 270-minute pre-2023 run and a 45-minute ARTEX run take nearly identical wall-clock playback time.

---

### 3. Defensive Mechanism Comparisons Are Incomplete or Distorted

1. **No standalone Canaries comparison:** `wire.html:529-544` only provides `Baseline`, `Virtual Patch`, `Agentic SOAR`, and `Agentic SOAR + Canary`. A user cannot evaluate **Canaries alone** (early detection and lead time without automated containment) against Virtual Patching and Agentic SOC, even though `COMPARISON_DEFENSES` (`js/wire-engine.js:1938`) defines `canaries`.
2. **Canaries fire on Layer 0 perimeter appliances instead of decoy assets:**
   - In `simulateWireRun`, `canaryAsset` (`js/wire-engine.js:969`) is dead code because it only activates for `mode === 'combined'`.
   - Instead, `recordTelemetry()` (`lines 1017-1023`) fakes an `"early"` canary by firing a canary alert on `!source` (the Layer 0 ingress gateway—e.g., F5 BIG-IP or Palo Alto GlobalProtect) and rendering a yellow `Canary alert` badge on that edge node (`wire.html:921-925`).
   - `canaryTouched` (`line 989`) is a single global boolean across all branches. For `blackcat` (`canary: 'late'`), an isolated Layer 0 `public-s3` read (`data_read`) at `t = 0` consumes `canaryTouched` before the Layer 3 database is ever touched, suppressing the late DB canary.
3. **Agentic SOC is blind to Layers 0, 2, and 3, and hides containment on the graph:**
   - `recordTelemetry()` (`line 1024`) only emits regular boundary telemetry when `target.layerIdx === 1` (excluding `staging-status`). Ingress exploitation, internal RCE/process anomalies, and data-tier exfiltration emit zero regular SOC signals.
   - There is no detection asymmetry between noisy Pre-2023 host/network activity and low-volume ARTEX API chaining.
   - When containment takes effect (`signals.get(scope) < timeSec`, `line 1042`), `processTransition` returns early without pushing any event. Downstream hops stay green, `blockedTransitions` stays `0`, and no SOC block ticket shows *where* the attack was stopped.
4. **Virtual Patching doesn't distinguish static vs. adaptive evasion:** Edge WAF rules (`patch`) behave identically for Pre-2023 static tools and ARTEX-like adaptive payload re-encoding, and never distinguish tight endpoint/protocol virtual patches from generic regex WAF rules.

---

### 4. Infrastructure, Catalog, and State Inconsistencies

1. **Reference catalog mismatch (`assets/wire-defense-catalog.json`):** All 25 `edge` catalog examples map to `groups: ["pan-globalprotect", "cust-api", "app-engine", "db-rds"]` (`focus: 0`). Consumer/SOHO router CVEs such as D-Link `CVE-2024-0769` or ASUS `CVE-2023-39780` highlight an enterprise Palo Alto GlobalProtect firewall (`CVE-2024-3400`) in the graph while the simulation ignores the catalog CVE's techniques.
2. **Contradictory `· Decommissioned` / `· P.o.C` labels (`wire.html:683-693`):** Multi-instance `waf-proxy`, `iam-idp`, and `threat-det` assets are cosmetically relabeled `· Decommissioned` and `· P.o.C` in the DOM while `wire-engine.js` continues to assign them active CVEs and route production traffic through them.
3. **`finishRun()` `data_read` ambiguity (`wire.html:962`):** `successes.find(e => e.grantedCapability === 'data_read')` matches the *first* `data_read` event. In the ~15% of mixed estates where `seedExercise` stops at Layer 2 (`length = 3`, `line 1304`), an unrelated Layer 0 `public-s3` read (`T1530`) makes `finishRun()` report a breach at `At start` (`t = 0`).
4. **Orphaned comparison engine (`js/wire-engine.js:1916-2513, 2573-3010`):** `createComparisonEstate`, `COMPARISON_FIXTURES` (including `speed-race`, `speed-covered-patch`, `capability-45s`, `capability-denied`, and edge cases), and `evaluateComparisonMatrix` already solve several of these problems cleanly, but `wire.html` does not expose them. Node tests (`scripts/test-wire-model.cjs`) pass all checks while the UI and engine remain split.

---

## Suggested Fixes (Prioritized)

### P0 — Restore Simulation Integrity & Controlled Comparisons
1. **Replace `seedExercise` shortcuts with real prerequisite-checked paths:** Generate the primary 4-layer route using valid `evaluateDistinctActions` prerequisites (CVE product/version/conditions, protocol compatibility, and scoped credentials) instead of `kind: 'exercise'` bypasses. Apply `KEV_MITIGATION_RULES` and `isNonHttpProtocol` uniformly to every node and branch in `wire.html`.
2. **Move telemetry and decoy settings from `WIRE_ATTACKERS` to the infrastructure:** Define `boundarySignal` and `canary` placement (`early`, `late`, `untouched`) on the **estate / defense configuration** rather than on `lockbit` vs. `revil`. Switching between `Pre-2023` and `ARTEX-like` will then test two attack profiles against the *same* defensive visibility.
3. **Expose the controlled 5-column comparison in `wire.html`:** Add **Canaries** as a standalone defense option alongside `Baseline`, `Virtual Patch`, `Agentic SOC`, and `Combined` (and surface `evaluateComparisonMatrix` / `COMPARISON_FIXTURES` as a structured comparison view alongside exploratory `New Infra` runs).

### P1 — Make Attack & Defense Differences Realistic
4. **Fix clock precision and playback pacing:**
   - Replace minute-rounded `formatEstimate()` in `wire.html` with `formatDurationSeconds()` (`HH:MM:SS` or `Xm Ys` from `js/wire-engine.js:2123`) so the 50-second ARTEX burst vs. 60-second SOAR race is visible on `#model-clock` and in the SOC tickets.
   - Keep the real-world `80–270 min` vs. `45–75 min` (with short execution bursts) model, and scale animation pacing so Pre-2023 vs. ARTEX tempo differences are visually legible during playback.
5. **Model behavioral & capability differences between Pre-2023 and ARTEX-like:**
   - **Pre-2023:** Sequential single-branch progression, human decision/handoff delays on context-dependent pivots, static exploit signatures (reliably stopped by matching WAF virtual patches), and noisier host/network artifacts (higher SOC detection probability at Layers 1–3).
   - **ARTEX-like:** True concurrent multi-branch probing (evaluating parallel opportunities rather than cosmetic SVG lanes), zero handoff stall on API/token chaining, adaptive re-encoding bypass against generic regex WAF rules (while still blocked by strict schema/protocol virtual patches), and low-volume API calls that reduce volumetric SIEM visibility.
6. **Fix Canary and Agentic SOC mechanics:**
   - Place Canaries on **dedicated decoy nodes or decoy credentials/tokens** (e.g., decoy S3/DB target, decoy token in exposed logs, or honeypot internal service) rather than firing canary alerts on Layer 0 perimeter firewalls; scope canary triggers per decoy rather than one global boolean.
   - Allow Agentic SOC to ingest signals across **Layers 0–3** using `KEV_MITIGATION_RULES[cve].ml` plus behavioral telemetry, and emit explicit `'contained'` events when `signals.get(scope) <= timeSec` so the graph and ticket ticker show *where* containment stopped the chain.

### P2 — Clean Up Infrastructure, Catalog, and Test Coverage
7. **Align `assets/wire-defense-catalog.json` with enterprise topology:** Map catalog CVEs only to matching asset families (or exclude out-of-context SOHO router CVEs from Palo Alto GlobalProtect highlights) and pass the drawn catalog CVE's techniques/focus cleanly into the explanation UI.
8. **Formalize or remove `· Decommissioned` / `· P.o.C` labels:** Either model `decommissioned` (no live path to Layer 3 data) and `poc` (excluded from WAF/SOC telemetry) in `wire-engine.js`, or remove the DOM-only string rewrite in `wire.html:687-692`.
9. **Fix `finishRun()` protected-read detection:** Require `layerIdx === 3 && grantedCapability === 'data_read'` (or `isProtectedRecord`) in `wire.html:962` so a Layer 0 `public-s3` read is reported separately from a Layer 3 protected record breach.
10. **Add browser-level verification:** Extend `scripts/test-wire-model.cjs` (or add a headless browser test) to verify `wire.html` renders all defense options (including standalone Canaries), displays seconds-level timestamps, and stays synchronized with `js/wire-engine.js`.
