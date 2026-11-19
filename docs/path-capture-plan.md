# Compact path capture

Scope: presentation for phases 3â€“5. The explicit user request reopens UI work for this capture view.

1. Simulate the complete original estate before choosing display assets. When protected reads occur, trace their executed prerequisites backwards and retain those outcome paths and relevant controls. Otherwise retain executed/blocked/suppressed/alert actions and control targets. Exclude eligibility checks and unexecuted exploration. Keep only relationships used by those actions. This is a retrospective path replay, not a claim to predict a route.
2. Add opt-in `wire.html?capture=path` with no controls, compact stage layout, legible labels, visible workers, a modeled elapsed clock and result. Preserve the normal interactive view.
3. Reuse original events, worker tracks and timing. Do not simulate a pruned estate or turn a hidden branch into a defense success. Retain explanatory failed and contained branches.
4. Capture ARTEX baseline on seeds 1853, 2468 and 3579, holding the final state between segments.

Acceptance: original event history unchanged; displayed assets exactly match the planned endpoints; no unrelated edges; three visible ARTEX markers; labels and badges fit; agents move; completed state and clock match the original simulation; ordinary view still has its controls. Inspect beginning, midpoint and result frames and decode the output GIF.

## Implementation and validation

- Open `wire.html?capture=path&seed=1853` for an automatically playing focused view. Optional `actor=pre2023` and `mode=combined` use the same presentation interface. `window.pathCapture.prepare/advance/state` support deterministic capture.
- A full simulation supplies the outcome paths; all original events remain in memory. Eligibility checks and unrelated successful branches are omitted from the presentation. Original worker assignments are retained and omitted jobs appear as idle time.
- Capture: `node capture-path.cjs`. Assemble: `python scripts/build-path-gif.py` with Pillow available.
- Browser verification passed on seeds 1853, 2468, 3579: event-history parity with the original full-estate simulation, 4/4/5 retained assets, three agent markers with movement, label and badge bounds, exact completion clocks, and the ordinary view's controls. No browser errors.
- Inspected intermediate and final frames. Output decoded successfully: 363 frames, 1360 Ã— 574, 97.5 seconds. The GIF uses one fixed canvas height to accommodate the final infrastructure's two data targets.

## Stacked comparison revision

The current `path-comparison.html` places ARTEX above a LockBit-style pre-2023 crime gang. Both use the same full estate and the union of their actual attempted assets and relationships in identical positions. The successful-outcome ancestor filter has been replaced: timed unsuccessful eligibility/access jobs remain visible, with amber paths and explicit no-access/prerequisite text. Untimed initial eligibility checks and truncated/unexecuted work remain excluded. Three numbered ARTEX agent markers preserve the original worker allocation; the human profile has one marker.

Clocks show modeled elapsed time in bold 34px `1h:33m` format. Both panels advance using one modeled time; completed panels retain their final clock. Playback spends 65% of each segment up to ARTEX completion and then advances the same clock to human completion. This changes only playback speed.

Validation: `node scripts/test-capture-plan.cjs` and `node capture-stacked-paths.cjs`. Browser checks passed for seeds 1853, 2468, 3579: full event parity, same estate and layout in both panels, 15/24/13 retained assets, failed-attempt endpoints and labels, exact clock text and bold size, all three ARTEX agents moving concurrently, one human marker, bounds, completed clocks, ordinary UI controls, and no page errors. Compare estate semantic fields across runtimes; generated display x/y floats can differ by machine precision between Node and Chromium, while both browser panels retain identical full estates.

Build: `python scripts/build-stacked-path-gif.py` with Pillow available. The GIF uses a fixed canvas for the largest of the three retained topologies.

## Used routes refinement

The latest request keeps unrelated branches only when they show actual exploration. Keep all timed jobs (including unsuccessful access checks), their source/target assets, and the initial access feeding them. Drop isolated zero-time starting successes that have no follow-on use, along with passive/untimed eligibility findings. Both panels still use the same planned union and unchanged full-estate simulations.

Label retained nodes BREACH CHAIN or EXPLORATION, based on backwards tracing successful protected-read prerequisites. Add a common external-origin illustration for the actual starting access. The large clocks explicitly measure modeled elapsed time since starting access; no new initial-access duration is fabricated.

Capture and verify: `node capture-used-routes.cjs`. Build: `python scripts/build-used-routes-gif.py` with Pillow available. Unit checks now explicitly exclude an isolated zero-time successful entry while retaining a timed failed exploration branch.
