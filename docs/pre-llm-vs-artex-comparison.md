# Pre-LLM Cyberattacks (Pre-2023) vs. ARTEX: Timelines, Components, and IOCs

**Date:** 2026-11-15  
**Scope:** Comparison of pre-2023 human-operated cybercrime/ransomware operations against the local **ARTEX** autonomous penetration testing system (`E:/work/ARTEX`, `E:/work/artex_sandbox`) and published threat-intelligence reporting (Unit 42, Eye Security, SOCRadar, Mandiant, CrowdStrike, Sophos).

---

## 1. Attack Timeline Comparison (Pre-LLM vs. ARTEX)

| Metric | Pre-LLM (2021–2022) | ARTEX (LLM-Driven Agentic) | Source / Evidence |
| :--- | :--- | :--- | :--- |
| **Lateral Breakout Time** *(initial access → lateral move)* | **1 hr 38 min** (2021) → **1 hr 24 min** (2022) | **Seconds to minutes per hop** *(~18.75 s/hop avg in local 4-hop range)* | CrowdStrike GTR 2022/2023; `artex_executive_demo_guide.md` |
| **End-to-End Compromise / Dwell** | **5–11 days** median ransomware dwell *(16–21 days all intrusions)* | **~75 seconds** (4-hop local Docker range) · **5–15 minutes** (cloud/API campaigns) | Mandiant M-Trends 2022/2023; Sophos 2022/2023; Unit 42 / Dark Reading |
| **Raw Network / API Time** | Days of interactive C2, recon, and exfiltration | **88.6 ms** total across 4 HTTP hops (`18.1 + 16.0 + 15.6 + 38.9 ms`) | `artex_executive_demo_guide.md`, `scripts/timed-rehearsal.py` |
| **Defender MTTI + MTTC** | **277 days** (207d identify + 70d contain) | **< 10–20 ms** required for automated WAF/SOAR containment | IBM Cost of a Data Breach 2022; `artex_executive_demo_guide.md` |

### ARTEX Time-Per-Hop Breakdown (Local Range vs. Empirical LLM Studies)
In the local 4-hop ARTEX range (`edge` → `identity` → `workflow` → `records`):
* **Hop 1 (`POST /api/edge/export`):** `18.1 ms` wire latency
* **Hop 2 (`POST /api/identity/exchange`):** `16.0 ms` wire latency
* **Hop 3 (`POST /api/workflow/pivot`):** `15.6 ms` wire latency
* **Hop 4 (`GET /api/records/canary`):** `38.9 ms` wire latency
* **Total Wire Time:** `88.6 ms`
* **Total ARTEX Deliberation + Execution Time:** `~75 seconds` (~18–19 s per hop with local `openai/gpt-oss-20b` via LM Studio).

Across broader external evaluations (arXiv / Unit 42), LLM inference typically accounts for **5%–30%** of wall-clock time per step; the remaining **70%–95%** is spent waiting on dispatched CLI tools (scanners, fuzzers, HTTP probes). Even so, eliminating human "think time," documentation lookup, and manual proxy scripting compresses multi-day intrusions into minutes.

---

## 2. Top 5 Pre-2023 Ransomware Gangs + #6 ARTEX (IOCs & TTPs)

### 1. LockBit (2.0 / 3.0 "LockBit Black")
* **Pre-2023 Footprint:** Most prolific RaaS operation by 2022 (~1/3 of enterprise ransomware attacks).
* **IOCs (CISA AA23-075A / AA23-165A):**
  * **File Extensions:** `.abcd` (v1), `.lockbit` (v2.0), randomized affiliate extensions (v3.0).
  * **Ransom Notes:** `Restore-My-Files.txt`, `1.README.txt`.
  * **Host/Execution:** Runtime passkey CLI argument (v3.0), `vssadmin.exe delete shadows`, Windows event-log clearing, StealBit exfiltration, Cobalt Strike C2, desktop wallpaper swap.

### 2. Conti
* **Pre-2023 Footprint:** Dominant Russian RaaS syndicate through mid-2022 prior to the "Conti Leaks" split.
* **IOCs (CISA AA21-265A):**
  * **File Extensions:** Custom/randomized or `.conti`.
  * **Ransom Notes:** `readme.txt`, `CONTI_README.txt`.
  * **Host/Network:** TrickBot/BazarLoader initial access, Cobalt Strike, Kerberoasting, Mimikatz, PowerShell cradles, Defender-disabling registry edits, Windows Restart Manager API abuse, `vssadmin` shadow-copy deletion.

### 3. BlackCat (ALPHV / Noberus)
* **Pre-2023 Footprint:** Emerged late 2021; first major **Rust**-based cross-platform (Windows + Linux/ESXi) RaaS.
* **IOCs (CISA AA23-353A):**
  * **File Extensions:** Dynamic 7-character alphanumeric strings per victim (e.g., `.xy123ab`).
  * **Ransom Notes:** `RECOVER-[random_extension]-FILES.txt`.
  * **Host/Execution:** Compiled Rust binaries with `--access-token` CLI flag, embedded JSON config, `wevtutil` log clearing, hypervisor/DB service termination.

### 4. Hive
* **Pre-2023 Footprint:** Prolific Go/Rust RaaS targeting healthcare and critical infrastructure in 2021–2022 (disrupted by FBI in early 2023).
* **IOCs (CISA AA22-321A):**
  * **File Extensions:** `.hive`.
  * **Ransom Notes:** `HOW_TO_DECRYPT.txt`.
  * **Host/Network:** Helper scripts (`hive.bat`, `shadow.bat`), `rclone` exfiltration to Mega.nz, binaries mimicking Windows system executables, runtime argument gating.

### 5. REvil (Sodinokibi)
* **Pre-2023 Footprint:** Dominant in 2021 (including the Kaseya VSA supply-chain attack).
* **IOCs:**
  * **File Extensions:** 5–10 character random affiliate strings (`EXT` config key).
  * **Ransom Notes:** `[random_extension]-readme.txt`.
  * **Host/Registry:** Registry writes under `SOFTWARE\recfg` (victim UID/KEY), Safe Mode reboot (`bcdedit`), `vssadmin` shadow deletion, wallpaper swap.

### 6. ARTEX (LLM-Driven Autonomous Penetration / Red-Team Agent)
* **Era & Footprint:** Post-2023 agentic era; open-source Go + Next.js autonomous pentest framework (`E:/work/ARTEX`) also observed by Palo Alto Unit 42, Eye Security, and SOCRadar in real-world offensive campaigns.
* **Key Difference:** No encryptor binary, no ransom note, and no static C2 implant. Instead, an LLM reasoning loop dynamically chains exposed APIs, credentials, and trust boundaries.
* **IOCs (Unit 42, Eye Security, SOCRadar):**
  * **Dynamic Probe Files / Paths / Accounts:** `artex-probe-<digits>`, `artx-pod`, `artx_s5.php`, `artx-label-probe`, test accounts containing `ArtexProbe`. *(Generated dynamically by the LLM driver rather than hardcoded in the Go binary.)*
  * **HTTP User-Agents:** `Mozilla/5.0 (ARTEX)`, `Mozilla/5.0 (compatible; ArtExVerify/1.0)`.
  * **Payload / Verification Markers:** `ARTEX_WRITE_PROBE`, `ARTEX-PROBE-0001`, `ARTEX_PERSIST_OK`.
  * **Behavioral / Network Pattern:** Either high-frequency bursts against public APIs/OpenAPI specs/password-reset endpoints during recon, or **low-volume surgical single-request-per-hop chains** (4 requests total in the local 4-hop demo, evading >100 req/min SIEM rate thresholds).

---

## 3. Component & Architecture Comparison

| Dimension | Pre-2023 RaaS Gangs (LockBit / Conti / BlackCat / Hive / REvil) | Local ARTEX (`E:/work/ARTEX`) |
| :--- | :--- | :--- |
| **Core Driver** | Human affiliates + playbooks + manual Cobalt Strike / Mimikatz | Hierarchical LLM loop: `MainAgent` (`agent/mainagent.go`) → `Planner` (`agent/planner.go`) → `Worker` (`agent/worker.go`) → `Observer/Guard` (`guard/`) |
| **Orchestration & UI** | C2 team servers, leak-site panels, affiliate portals | Single Go binary + embedded Next.js UI (`:8787`), PostgreSQL state, intercepting proxy (`:8788`), MCP (`mcphttp/`), traffic store (`traffic/`), browser capture extension (`extension/`) |
| **Primary Target Surface** | Windows AD, SMB/RDP, VPN CVEs, ESXi hypervisors | Web/REST APIs, OpenAPI specs, federated identity/token exchanges, microservice trust boundaries, cloud IAM |
| **Adaptation on Block** | Human operator troubleshoots, swaps payloads, or waits hours/days | `Observer/Guard` detects HTTP 403/WAF/rate-limit in real time and prompts `Planner` to re-encode, tamper headers, or pivot within seconds |
| **Payload Footprint** | Compiled encryptor binaries (C/C++/Go/Rust), batch scripts, `rclone` | Standard HTTP/CLI tools (`WebFetch`, `Bash`, `curl`, `nmap`, `skills/`) + LLM-generated probe strings |

---

## 4. Defensive Takeaways

1. **Rate-limiting alone fails on chained API attacks:** A 4-hop ARTEX traversal can complete in 4 discrete requests (~88.6 ms network time, ~75 s total deliberation), staying well below volumetric SIEM thresholds.
2. **Human SOC triage is too slow:** Pre-2023 breaches already moved laterally in ~84 minutes; agentic hops resolve in seconds. Containment requires **virtual patching** at the ingress proxy (`< 10 ms`) and **automated behavioral/SOAR revocation** (`< 20 ms`).
3. **Hunt for agentic artifacts & trust-boundary abuse:** Monitor for `artx-*` / `artex-probe-*` naming, anomalous User-Agents, exposed OpenAPI/source-map files, and cross-service token reuse rather than relying solely on malware/ransomware file signatures.
