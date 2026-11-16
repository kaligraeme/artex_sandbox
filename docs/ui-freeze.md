# UI freeze: Range Operations v2

Frozen at the user's request on 16 November 2026. Snapshot tag: `ui-freeze-v2-2026-11-16`.

## Approved state

- Charcoal Range Operations styling, cyan selection states and prominent defense icons matching the supplied design reference.
- Four defense cards: Baseline, Virtual Patch, Agentic SOAR and Defense-in-Depth (WAF + SOC + Canary).
- ARTEX / Pre-LLM Attacks title toggle, asset search, Replay, Results, New Infra and modeled stopwatch.
- Quiet green assets; pink attack halos, dashed paths and visible CVE callouts; distinct prevention, containment and alert cues.
- One human-shaped attacker versus three independently tracked ARTEX agents, with movement derived from scheduled work and subdued idle workers.
- [V2 comparison GIF](../assets/ARTEX_vs_PreLLM_v2.gif), capture/encoding scripts and [scenario notes](v2-animation.md).

## Verification at freeze

Model suites pass. Browser checks pass for 72 combinations across two attackers, four defense choices, three seeds and desktop/narrow viewports, including marker counts, replay, search, keyboard controls, animation progression and reduced motion. The GIF was decoded and visually checked; dimensions, eight runs, total duration and infinite looping were verified.

## Change boundary

Subsequent user-requested correction: canary-enabled modes show `Canary deployed` on an existing decoy from the start, changing to `Canary alert` on a real signal. This uses the existing badge styling and preserves the frozen layout and controls. The full-estate GIF adds a recording overview of all generated assets; it does not replace the application's layout. See [current tool state](current-tool-state.md).

Stop UI work here. Future work must preserve this presentation unless the user explicitly requests reopening UI changes. Model/backend changes do not imply approval to alter the frozen UI. The snapshot tag identifies the local frozen commit; remote publication depends on a successful push.
