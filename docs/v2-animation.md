# V2: ARTEX versus Pre-LLM attack replay

Artifact: [ARTEX_vs_PreLLM_v2.gif](../assets/ARTEX_vs_PreLLM_v2.gif).

The GIF pairs ARTEX and a conventional LockBit-style attacker for each of the four defense cards: Baseline, Virtual Patch, Agentic SOAR and Defense-in-Depth. Actor count is shown through movement: one human-shaped attacker versus three separately tracked bot markers. Markers follow actual action start/completion intervals; idle workers are subdued. No extra count label is used to stand in for the animation.

## Scenario and interpretation

The capture uses a focused nine-asset enterprise derived from generated mixed-estate seed 1853. It retains assets reached or prevented across the eight source runs, control targets and relevant credential dependencies. The focused estate is validated and all eight cases are simulated again; source-graph results are not substituted for its results. Topology, findings, credentials, deployment and response assumptions remain identical between comparisons.

This selected example demonstrates patching blocking a covered attempt while an uncovered route remains, an ARTEX protected read before SOC enforcement, a conventional run contained before protected data access, and real decoy interaction feeding the full defense's response lifecycle. Partial containment is reported as partial; it is not a claim that every session was eliminated. These are illustrative scenario outcomes, not effectiveness measurements.

The stopwatch follows engine model time. Event-driven capture accelerates presentation while retaining all event phases, displayed access/response effects and the final outcome. Each chapter shows movement between events, then the actual action and its vulnerability/control cue. A closing table compares the results. See [timing assumptions](timing-assumptions.md).

## Output and verification

- 1440 × 1060 pixels, infinite loop, 111.1 seconds.
- 280 encoded frames from 282 screenshots; identical frames are merged while preserving duration.
- Approximately 3.96 MiB, with a shared palette reserving UI text, attack, defense and agent colors.
- Verified all eight attacker/defense combinations, unchanged scenario inputs, expected marker counts, model test suites and the browser regression matrix.
- Decoded GIF frames were inspected for the three-agent and single-attacker views and the final comparison table. GIF dimensions, total duration and looping metadata were checked after encoding.

## Reproduce

Requires Playwright Core, Edge (or an `EDGE_PATH` override) and Pillow. `PLAYWRIGHT_CORE_PATH` may point to an externally installed package. Set `V2_FRAMES` to an output directory if the default sibling `.gif_capture_v2` is unsuitable.

```powershell
node scripts/capture-v2.cjs
python scripts/build-v2-gif.py --frames ../.gif_capture_v2 --output assets/ARTEX_vs_PreLLM_v2.gif
```

The capture directory contains the full manifest, focused estate, events, response assumptions and source screenshots. Encoding is driven by that manifest, not by unrelated leftover PNGs.
