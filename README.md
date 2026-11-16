# ARTEX Attack and Defense Demo

An interactive visual demonstration of an attacker moving through an enterprise environment and the potential effects of layered defenses. The wire diagram shows a generated infrastructure, representative attack paths, vulnerability details and a rolling stream of SOC tickets.

The demo is illustrative: its infrastructure, access paths, alerts and defense outcomes are generated for presentation. They are not observations of a real environment or measurements of a product's effectiveness.

![ARTEX wire diagram demo](assets/wire_current_demo.gif)

## Get and start the demo

Clone the current repository:

```powershell
git clone https://github.com/kostchei/artex_sandbox.git
cd artex_sandbox
```

On Windows, install Python 3 and make sure `python` or the Python launcher `py` is available on your PATH. Then double-click **`start.bat`** in the repository folder, or run it from PowerShell:

```powershell
.\start.bat
```

The batch file runs `start.py`, which starts a local HTTP server and opens [http://localhost:8080/wire.html](http://localhost:8080/wire.html) in your browser. Keep the launcher window open while using the demo; press **Ctrl+C** in that window to stop it.

If port 8080 is already in use, the launcher opens the existing service at that address rather than starting another server. If neither `python` nor `py` is available, `start.bat` attempts to open that address but does not start a server.

On macOS or Linux, run `./start.sh` from the repository folder. It looks for `python3` and then `python`.

## Demo branches

- **`main`** runs the demo on the full wire diagram. The site root and old Table View address (`/index.html`) redirect to `/wire.html`.
- **`artex-gemini`** (`e:\work\artex_sandbox-gemini` worktree) implements the realistic attack-and-defense improvements specified in [docs/wire-improvement-engineering-spec.md](docs/wire-improvement-engineering-spec.md).
- **`wire-combined`** preserves the demo before that change, including the standalone Range Operations dashboard and the original **Compare Combined** toggle. Use this branch to revisit that version.

## Run the wire diagram

1. Choose **Pre-2023** or **ARTEX-like** from the **Attacker** menu. Each new estate draws LockBit, Conti, BlackCat, Hive, or REvil in randomized order and keeps that group for replay and defense comparisons. Nominal path-duration assumptions are **80–270 minutes** for conventional examples and **45–75 minutes** for ARTEX-like. Actual completion includes queued work. These illustrative ranges are not measured breach-time distributions; see [timing assumptions and historical sources](docs/timing-assumptions.md). ARTEX-like uses three workers and conventional profiles use one.
2. Start with **Baseline**, then compare defenses, including **Layered Defense** for virtual patching + SOC + canary together. Changing the attacker or defense replays the same topology.
3. Use **Replay** to repeat the run or **Results** to jump to its outcome. The **Elapsed** clock shows cumulative modeled time from the assumed edge foothold.
4. Use **New Infra** to generate a fresh topology and a different mix of five to seven appliance families from the [Layer 1 appliance pool](docs/wire_diagram_logic.md#layer-1-appliance-pool). Most baseline runs include a simulated path to a sample record. Credential exposure in logs can appear as an opening in the same mix.

**New Infra** draws from 100 CISA KEV and CTID references. Each entry selects one of four representative infrastructure profiles, and the remaining topology is generated around it. The simulation shows which generated services were reached or defended. See the [JSON catalog](assets/wire-defense-catalog.json).

The estate may also contain an exposure from the [external misconfiguration pool](docs/wire_diagram_logic.md#external-misconfiguration-pool). The replay identifies the exposed service and the access established there.

## Scenarios

| Scenario | What the demo shows |
| --- | --- |
| **Baseline** | The estate model evaluates usable paths. Either profile can reach protected data if the generated estate supplies a complete path. |
| **Virtual Patch** | The WAF stops requests when the modeled rule covers the finding. |
| **Canaries** | Decoy contact alerts; it does not contain the session. |
| **Agentic SOAR** | Matching telemetry starts the estate's modeled collection, decision and response lifecycle. Coverage, authority, latency and enforcement success determine whether the affected session reads protected data before containment. |
| **Agentic SOAR + Canary** | Uses the same SOAR response policy. A touched decoy can give SOAR an earlier signal. Timing, signal availability, and session scope determine the outcome. |
| **Layered Defense** | Virtual patching, the same SOC response lifecycle, and explicit canary alerts together. |

WAF coverage, response timing, and outcomes are synthetic assumptions for this exercise.

## Infrastructure and tickets

The diagram spans internet-facing access, gateways and security controls, internal applications, and data stores. Measured labels are spaced within layer columns; dense estates scroll vertically and narrow screens can scroll horizontally. Click or keyboard-focus an asset to reveal adjacent connections and its complete details. ARTEX-like uses up to three workers; conventional profiles use one. Solid red lines show successful access. Every defense uses the same 1,000 evaluated-transition ceiling; label density never limits modeled access. Pending work at the ceiling is reported as incomplete, including when a read has already occurred.

The HUD distinguishes impact, incomplete exploration and partial or complete session containment. A missing read alone does not earn containment styling. Steps suppressed by effective containment do not count as new blocked attack attempts. Replay preserves the scenario and modeled event history; New Infra generates a new scenario.

An environment may include one network-monitoring system, selected from Cacti, LibreNMS, SolarWinds NPM, Zabbix, PRTG and ManageEngine OpManager. The selection has a 90% inclusion chance before topology filtering. Some products have a mapped historical CVE; others have no CVE assigned.

The SOC tickets are illustrative, generated as activity occurs. A node can produce one or several tickets, with a title, severity and short alert description. Severity and breach detection are demonstration choices, not CVSS scores or actual SIEM findings. Remediation tickets appear when a modeled virtual patch, agentic SOAR response or canary triggers.

See [wire diagram logic](docs/wire_diagram_logic.md) for the topology and scenario assumptions, [Pre-LLM vs. ARTEX comparison notes](docs/pre-llm-vs-artex-comparison.md) for field context and fixture limits, and the [threat matrix](docs/cisa_kev_threat_matrix.md) for additional vulnerability background.

## License

[Apache License 2.0](LICENSE).
