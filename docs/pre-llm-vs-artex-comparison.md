# Pre-LLM Cyberattacks (Pre-2023) vs. ARTEX: Timelines, Components, and IOCs

> Historical research notes. The table below mixes breakout, dwell, local lab and response measurements; it must not be used to infer a common speed ratio or a required millisecond response. The current Wire clock and its explicit scenario assumptions are documented in [timing-assumptions.md](timing-assumptions.md). The nominal profile ranges are illustrative, not measured enterprise breach-time distributions.

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

## 2. Landmark Pre-2023 Attack Patterns & RaaS Groups vs. #6 ARTEX (IOCs & TTPs)

Between 2020 and 2023, the pre-LLM threat landscape shifted toward **software supply-chain compromises**, **critical infrastructure disruption**, and **mass zero-day extortion**, alongside prolific human-operated **Ransomware-as-a-Service (RaaS)** syndicates. Evaluated by systemic blast radius, physical/economic disruption, and regulatory aftershocks, five landmark campaigns stand out alongside the five dominant RaaS affiliate operations modeled in the sandbox:

| Incident / Pattern | Year | Primary Vector | Threat Actor | Core Systemic Impact | Sandbox Pattern ID |
| --- | --- | --- | --- | --- | --- |
| **SolarWinds (SUNBURST)** | 2020 | CI/CD build pipeline compromise (`CVE-2020-10148` / trojanized Orion update) | APT29 (SVR) | Up to 18,000 organizations trojanized; reshaped U.S. federal software supply-chain mandates (EO 14028). | `solarwinds` |
| **Colonial Pipeline** | 2021 | Compromised legacy VPN credentials (no MFA) | DarkSide | Halted 45% of U.S. East Coast fuel supply; triggered federal OT/critical infrastructure directives. | `darkside` (`legacy-vpn`) |
| **Kaseya VSA** | 2021 | Zero-day authentication bypass & SQLi in RMM (`CVE-2021-30116`) | REvil | Cascaded ransomware through ~60 MSPs to 1,500+ downstream businesses globally. | `revil` |
| **Log4Shell (`CVE-2021-44228`)** | 2021 | Unauthenticated JNDI injection in `Log4j` | Nation-states & eCrime | Ubiquitous open-source dependency flaw affecting hundreds of millions of Java instances. | `log4shell` |
| **MOVEit Transfer (`CVE-2023-34362`)** | 2023 | Zero-day SQL injection in managed file transfer (`LEMURLOOT`) | Cl0p | Pure-extortion campaign compromising 2,700+ organizations and 93M+ individuals. | `cl0p` |

> **Spec alignment note ([wire-improvement-engineering-spec.md](wire-improvement-engineering-spec.md) §8.1, `R04`, `R14`):** In the simulation engine, historical incident and actor names supply sourced technique metadata, vector context, and display labels under the `operator_with_tools` behavior preset. They do not hardcode defender blindness or guaranteed exploit success.

### 2.1 Five Landmark Systemic Cyberattacks (2020–2023)

#### 1. SolarWinds Supply Chain Compromise (`solarwinds`, 2020)
* **Attack Mechanics:** Russian foreign intelligence (APT29/Nobelium) infiltrated SolarWinds' internal build environment and injected the **SUNBURST** backdoor into signed, legitimate software updates for the Orion network monitoring platform (tracked alongside Orion API authentication bypass `CVE-2020-10148`).
* **Blast Radius:** Approximately **18,000 customers** downloaded the trojanized update, including major U.S. federal agencies (Treasury, Commerce, Homeland Security, Justice) and Fortune 500 enterprises.
* **Strategic Impact:** Demonstrated that trusted software update channels could be weaponized for precision espionage at scale. It directly catalyzed **Executive Order 14028**, which mandated Software Bills of Materials (SBOMs), zero-trust architecture adoption, and stricter vendor attestation across U.S. federal procurement.
* **Sandbox Mapping:** Maps to the CI/CD build runner (`cicd-runner`) and network monitoring (`vuln-scan` / SolarWinds) surface (`T1195.002`, `T1078`).

#### 2. Colonial Pipeline Ransomware Attack (`darkside`, 2021)
* **Attack Mechanics:** The DarkSide ransomware affiliate group gained initial access via a single compromised password for an inactive legacy VPN account that lacked multi-factor authentication (MFA). While the malware hit the corporate IT network, Colonial proactively shut down operational technology (OT) systems to prevent lateral spread into pipeline controls.
* **Blast Radius:** Shut down the largest refined fuel pipeline in the United States for six days, cutting off roughly **45% of the East Coast's fuel supply**, sparking panic buying, airline fuel shortages, and a **\$4.4 million ransom payment** (part of which the DOJ later recovered in Bitcoin).
* **Strategic Impact:** Marked the watershed moment where ransomware transitioned from a corporate balance-sheet problem into a national security crisis. It led to mandatory TSA cybersecurity directives for pipeline and rail operators and elevated incident reporting requirements for critical infrastructure.
* **Sandbox Mapping:** Maps directly to the `legacy-vpn` external misconfiguration opening (`Legacy VPN account still enabled without MFA`) and non-MFA credential authentication (`T1078`, `T1133`).

#### 3. Kaseya VSA Supply Chain Ransomware Attack (`revil`, 2021)
* **Attack Mechanics:** Exploiting a chain of zero-day vulnerabilities (`CVE-2021-30116`) in Kaseya’s Virtual System Administrator (VSA)—a remote monitoring and management (RMM) tool used by Managed Service Providers (MSPs)—the **REvil** ransomware group pushed a malicious update masquerading as a legitimate certificate update.
* **Blast Radius:** Because MSPs hold administrative privileges over their clients' networks, compromising roughly 60 MSPs allowed REvil to simultaneously encrypt **over 1,500 downstream businesses** across at least 17 countries, forcing Swedish supermarket chain Coop to temporarily close ~800 stores.
* **Strategic Impact:** Exposed the "one-to-many" force-multiplier risk inherent in MSPs and RMM tooling. It prompted international law enforcement crackdowns that dismantled REvil's infrastructure later that year and drove stricter access-control standards for third-party IT service providers.
* **Sandbox Mapping:** Consolidated with the **REvil** (`revil`) pre-2023 profile and endpoint/management infrastructure tier (`CVE-2021-30116`, `T1190`, `T1199`).

#### 4. Log4Shell / Apache Log4j Exploitation (`log4shell`, 2021)
* **Attack Mechanics:** Disclosed in December 2021, `CVE-2021-44228` allowed unauthenticated remote code execution (RCE) simply by forcing an application using Apache Log4j 2 to log a specially crafted string (`${jndi:ldap://...}`) that triggered a JNDI lookup to an attacker-controlled server.
* **Blast Radius:** Because Log4j is embedded deep inside millions of enterprise Java applications, cloud services, and appliances as a transitive dependency, security teams struggled simply to inventory where it existed. Both state-sponsored APTs and ransomware operators weaponized it within hours of public disclosure.
* **Strategic Impact:** Highlighted the fragility of the open-source software ecosystem—where a critical, unpaid volunteer-maintained library underpins global enterprise infrastructure—and accelerated industry-wide adoption of automated dependency scanning, SBOMs, and open-source security funding.
* **Sandbox Mapping:** Modeled in Layer 3 (`log4j-svc`, `iot-hub`) with `CVE-2021-44228` (`T1190`, `T1059`), where obfuscated JNDI payloads evade basic perimeter pattern matching and require behavioral egress/subprocess detection.

#### 5. MOVEit Transfer Zero-Day Campaign (`cl0p`, 2023)
* **Attack Mechanics:** The **Cl0p** extortion group exploited a zero-day SQL injection flaw (`CVE-2023-34362`) in Progress Software's MOVEit Transfer managed file transfer (MFT) application, deploying a custom web shell (`LEMURLOOT`) to systematically exfiltrate stored files without deploying encryption payloads.
* **Blast Radius:** Automated mass exploitation compromised **over 2,700 organizations** and exposed the personal data of **more than 93 million individuals**, hitting major pension funds, universities, government agencies (including the U.S. Department of Energy), and enterprise corporations.
* **Strategic Impact:** Cemented the industry shift away from noisy file-encryption ransomware toward **pure data-theft extortion**. It also exposed the systemic concentration risk of internet-facing MFT appliances, where third-party vendors' file transfer servers became single points of failure for hundreds of downstream enterprises.
* **Sandbox Mapping:** Modeled on the `moveit-sftp` MFT service (`CVE-2023-34362`, `T1190`, `T1505.003`, `T1041`) feeding directly into customer data lakes (`lake-cust`).

---

### 2.2 Pre-2023 RaaS Affiliate Profiles & #6 ARTEX

#### 1. LockBit (`lockbit` — 2.0 / 3.0 "LockBit Black")
* **Pre-2023 Footprint:** Most prolific RaaS operation by 2022 (~1/3 of enterprise ransomware attacks).
* **IOCs (CISA AA23-075A / AA23-165A):**
  * **File Extensions:** `.abcd` (v1), `.lockbit` (v2.0), randomized affiliate extensions (v3.0).
  * **Ransom Notes:** `Restore-My-Files.txt`, `1.README.txt`.
  * **Host/Execution:** Runtime passkey CLI argument (v3.0), `vssadmin.exe delete shadows`, Windows event-log clearing, StealBit exfiltration, Cobalt Strike C2, desktop wallpaper swap.

#### 2. Conti (`conti`)
* **Pre-2023 Footprint:** Dominant Russian RaaS syndicate through mid-2022 prior to the "Conti Leaks" split.
* **IOCs (CISA AA21-265A):**
  * **File Extensions:** Custom/randomized or `.conti`.
  * **Ransom Notes:** `readme.txt`, `CONTI_README.txt`.
  * **Host/Network:** TrickBot/BazarLoader initial access, Cobalt Strike, Kerberoasting, Mimikatz, PowerShell cradles, Defender-disabling registry edits, Windows Restart Manager API abuse, `vssadmin` shadow-copy deletion.

#### 3. BlackCat (`blackcat` — ALPHV / Noberus)
* **Pre-2023 Footprint:** Emerged late 2021; first major **Rust**-based cross-platform (Windows + Linux/ESXi) RaaS.
* **IOCs (CISA AA23-353A):**
  * **File Extensions:** Dynamic 7-character alphanumeric strings per victim (e.g., `.xy123ab`).
  * **Ransom Notes:** `RECOVER-[random_extension]-FILES.txt`.
  * **Host/Execution:** Compiled Rust binaries with `--access-token` CLI flag, embedded JSON config, `wevtutil` log clearing, hypervisor/DB service termination.

#### 4. Hive (`hive`)
* **Pre-2023 Footprint:** Prolific Go/Rust RaaS targeting healthcare and critical infrastructure in 2021–2022 (disrupted by FBI in early 2023).
* **IOCs (CISA AA22-321A):**
  * **File Extensions:** `.hive`.
  * **Ransom Notes:** `HOW_TO_DECRYPT.txt`.
  * **Host/Network:** Helper scripts (`hive.bat`, `shadow.bat`), `rclone` exfiltration to Mega.nz, binaries mimicking Windows system executables, runtime argument gating.

#### 5. REvil (`revil` — Sodinokibi / Kaseya VSA Campaign)
* **Pre-2023 Footprint:** Dominant in 2021, culminating in the `CVE-2021-30116` Kaseya VSA MSP supply-chain ransomware attack.
* **IOCs:**
  * **File Extensions:** 5–10 character random affiliate strings (`EXT` config key).
  * **Ransom Notes:** `[random_extension]-readme.txt`.
  * **Host/Registry:** Kaseya VSA `agent.crt` malicious payload delivery, registry writes under `SOFTWARE\recfg` (victim UID/KEY), Safe Mode reboot (`bcdedit`), `vssadmin` shadow deletion, wallpaper swap.

#### 6. ARTEX (`artex` — LLM-Driven Autonomous Penetration / Red-Team Agent)
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

---

## 5. Evidence, Fixture Limits, and Wire Comparison

The Wire Diagram shows five named pre-2023 gang examples and an ARTEX-like case on the same generated estate. The pre-2023 examples use a modeled **80–270 minute** range from foothold to sample record read, and ARTEX-like uses **45–75 minutes**. The [Wire timing exercise](wire_diagram_logic.md#wire-diagram-timing-exercise) documents the draw, milestones, and signal conditions.

* **Pre-2023 field context (external):** CrowdStrike reported mean interactive eCrime breakout times of **98 minutes** (2021) and **84 minutes** (2022) from initial host compromise to first lateral movement ([CrowdStrike 2023 Global Threat Report, p. 9](https://www.crowdstrike.com/wp-content/uploads/2023/05/CrowdStrike2023GlobalThreatReport.pdf#page=9)). Mandiant reported a 2022 median dwell of **16 days** from compromise to discovery ([Mandiant M-Trends 2023](https://cloud.google.com/blog/transform/m-trends-2023-lessons-cyberattack-frontlines)).
* **2023 onward field context (external):** CrowdStrike reported a **62-minute** mean eCrime breakout and a **2 minutes 7 seconds** fastest observed breakout for 2023 ([CrowdStrike 2024 GTR overview](https://www.crowdstrike.com/en-us/blog/crowdstrike-2024-global-threat-report/)). Anthropic's 2025 campaign report illustrates agentic orchestration and concurrency with human supervision at critical decisions ([Anthropic campaign report](https://www.anthropic.com/news/disrupting-AI-espionage)). Neither source quantifies AI's share of the breakout trend or supplies a comparable average time to a protected read.
* **Local ARTEX reference (guide figure):** The repository's [executive demo guide](artex_executive_demo_guide.md) reports approximately **75 seconds** of ARTEX deliberation for a four-hop lab run. Treat this as a local guide figure, not a general benchmark.
* **Wire fixture limits (modeled):** All Wire timestamps, 60-second containment latencies, 45-second capability budgets, and review counts are **synthetic acceptance fixtures** running entirely in-browser. Historical breakout, dwell, local lab duration, and Wire scenario times are kept in separately labeled fields without computing speed ratios across sources.
