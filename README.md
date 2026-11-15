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

- **`main`** serves the Wire Diagram as the demo. The site root and old Table View address (`/index.html`) redirect to `/wire.html`. The Wire navigation offers **Comparison Demo** and **Exploratory Infra**.
- **`wire-combined`** preserves the demo before that change, including the standalone Range Operations dashboard and the original **Compare Combined** toggle. Use this branch to revisit that version.

## Run the wire diagram

1. **Comparison Demo (default):** Compare **Pre-2023 human-led** vs **ARTEX & Friends** on a fixed four-layer estate. Use **Attack example** to open a synthetic defense exercise under one of the six reference names (**LockBit**, **Conti**, **BlackCat**, **Hive**, **REvil**, or **ARTEX**). The choices reuse generic event traces for both attacker workflows. Select **Shared speed and capability exercises** to return to the four controlled comparisons. Click any matrix cell for its trace and SOC tickets. Playback uses a modeled hours, minutes, and seconds clock (`HH:MM:SS`).
2. **Exploratory Infra:** Generate a topology with **New Infra**, cycle presets (**Mixed**, **Demo-Ready**, **Cred-in-Logs**), and compare defenses against generated activity. Use the **Attacker** menu on the map to run the same timing race as **Pre-2023 human-led** or **ARTEX & Friends**. The two profiles share a fixed estate and the selected **Defense**. Use **Replay** or **Results** to control playback. Select **Generated activity** to return to the generated estate. **Mixed** opens with a signed-in diagnostics viewer and one of three equally weighted starting conditions: low exposure, misconfiguration, or a modeled low-impact vulnerability. The mix gives each scenario equal demo coverage. The synthetic credential grants access only to the Staging Status API. Other paths through the estate vary by seed. Generated activity shows elapsed playback time. The two fixed attacker traces show modeled scenario time.

## Scenarios

In **Comparison Demo**, the former **Combined** scenario appears as **Defense in Depth**. Its column is visible on load and can be hidden or restored with the **Defense in Depth** toggle.

| Scenario | What the demo shows |
| --- | --- |
| **Baseline** | Unmitigated outcome without the three modeled controls. |
| **Virtual Patching** | Blocks covered ingress events at the edge (`RULE MATCH · BLOCKED AT EDGE`); out-of-scope events continue (`OUTSIDE RULE COVERAGE`). |
| **Agentic SOC** | Exposes telemetry, decision/approval, and enforcement timestamps under a fixed 60-second containment policy, showing where the same response wins at Pre-2023 pace (`+29 min`) and loses at ARTEX pace (`−10 s`). |
| **Canaries** | Standalone decoy interaction (`DECOY TRIGGERED · ALERT ONLY`) showing detection lead time without containment. |
| **Defense in Depth** | An early canary signal feeds the same SOC policy, shifting containment ahead of the protected read (`+15 s`). |

For generated activity in **Exploratory Infra**, the defense modes are **Baseline**, **Virtual Patch**, **Agentic SOAR**, and **Defense in Depth** (WAF + Agentic SOAR + Canary). The map's fixed attacker traces use the Comparison Demo defenses. Defense rules, coverage, detection, and response are demo assumptions.

## Infrastructure and tickets

The diagram spans internet-facing access, gateways and security controls, internal applications, and data stores. Objects are assigned product-specific CVEs where modeled; other findings can represent public access or assumed credential use. The displayed attack descriptions identify the type of flaw, while an assigned exposure assumes an affected configuration.

An environment may include one network-monitoring system, selected from Cacti, LibreNMS, SolarWinds NPM, Zabbix, PRTG and ManageEngine OpManager. The selection has a 90% inclusion chance before topology filtering. Some products have a mapped historical CVE; others have no CVE assigned.

The SOC tickets are illustrative, generated as activity occurs. A node can produce one or several tickets, with a title, severity and short alert description. Severity and breach detection are demonstration choices, not CVSS scores or actual SIEM findings. Remediation tickets appear when a modeled virtual patch, agentic SOAR response or canary triggers.

See [wire diagram logic](docs/wire_diagram_logic.md) for the topology and scenario assumptions, [Pre-LLM vs. ARTEX comparison notes](docs/pre-llm-vs-artex-comparison.md) for field context and fixture limits, and the [threat matrix](docs/cisa_kev_threat_matrix.md) for additional vulnerability background.

## License

[Apache License 2.0](LICENSE).
