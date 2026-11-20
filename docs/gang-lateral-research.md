# Ransomware lateral-method review

Reviewed and implemented 20 November 2026. Scope: the four other named profiles (LockBit, Conti, BlackCat and Hive), with the same explicit tool checks shared by REvil. These are historical-style operators applied to a modern synthetic estate. Public reporting establishes capabilities and incident workflows; it does not establish a reliable universal ranking of each gang's favorite methods.

## Evidence, gaps and changes

| Gang | Evidence reviewed | Gap in the preceding model | Implemented scenario preference |
| --- | --- | --- | --- |
| LockBit | [Joint government advisory](https://www.cyber.gov.au/advisory/understanding-ransomware-threat-actors-lockbit) identifies PsExec, SMB/admin shares, Cobalt Strike and remote-desktop movement. | PsExec was not a named executable option; first-listed SMB could win regardless of the authored workflow. | PsExec, then Beacon remote service, then direct SMB, RDP and Beacon/WMI alternatives. |
| Conti | [DFIR Report, November 2021](https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/) directly observed WMI creation of a remote Beacon and later RDP access. [HHS, May 2022, slide 8](https://www.hhs.gov/sites/default/files/ransomware-trends-q1-2022.pdf) lists PsExec use. | Beacon/WMI existed but default SMB ordering could prevent its selection; named PsExec was missing. | Beacon/WMI, then Beacon remote service, PsExec, RDP and direct SMB alternatives. |
| BlackCat | [Microsoft, June 2022](https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/) documents configurable propagation using PsExec and credentials, alongside differing affiliate workflows. Existing [Sygnia evidence](https://www.sygnia.co/blog/blackcat-ransomware/) supports RDP and Cobalt Strike. | Named PsExec propagation was missing; generic WMI/array ordering could select the method. | PsExec, then RDP, Beacon and direct SMB/WMI alternatives. |
| Hive | [Trend Micro, March 2022](https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-hive) reports RDP, WMI and PsExec movement. [HHS, May 2022, slide 8](https://www.hhs.gov/sites/default/files/ransomware-trends-q1-2022.pdf) associates Hive with Cobalt Strike and PsExec. | Hive was restricted to RDP; direct WMI, PsExec and Cobalt Strike were omitted for lack of imported software mappings. | RDP, then direct WMI, PsExec and Beacon alternatives. |

PsExec is also added to REvil's available repertoire based on the existing [Unit 42 investigation](https://unit42.paloaltonetworks.com/revil-threat-actors/). Its prior Beacon-first order is retained in this review. A source associating a gang with Cobalt Strike does not establish that the gang used every supported transport: those transport variants remain explicitly authored choices from the [tool documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_lateral-movement.htm).

## Model behavior

The gang's method order breaks ties between usable methods for the same target. It does not outrank data-collection priorities, change the network, supply missing credentials, defeat MFA or declare an otherwise ineligible preferred method successful. Eligible findings on one route and alternative routes to the same target are both ranked. Reversing the finding and relationship arrays cannot change the preferred choice. If a tool is unavailable, a credential lacks rights, or RDP requires unsatisfied MFA, another eligible method remains available.

PsExec is represented as a `remote_service` finding with `tool:'psexec'`, technique T1569.002 and SMB transport. [Microsoft's PsExec documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) supports remote-process and service behavior; the engine additionally requires an explicit `service_execute` credential permission, actual source execution, enabled target login and valid endpoint scope. Its SMB route, technique and permission must match the tool's declared method. Cobalt Strike follows the same tool/method validation. No real tool is launched. Tools are modeled as pre-staged inventory; installation and C2 establishment are not simulated milestones.

Events carry separately attributed tool evidence and `selectionPreference` labeled `authored_order_among_reported_methods`. Run assumptions expose the full method order. The ranking is a scenario design choice informed by reports, not measured prevalence or a claim that all affiliates follow one playbook.

ARTEX-like keeps its existing general modeled RDP capability. It receives neither PsExec nor Cobalt Strike in its default inventory. Either tool can be explicitly supplied for a custom experiment, with `modeled_action` provenance. These are not claimed as observed ARTEX behavior.

This work affects phases 1–3 (findings, capabilities and method selection) and verifies phases 4–6 (time, defenses and replay). It preserves the frozen layout, controls and animation presentation. Existing tool/technique activity titles describe the selected action. New Infra is required to add PsExec findings to older saved estates.

## Validation

`node scripts/test-lateral-tools.cjs` covers all gang tool methods, explicit preferences, array-order independence, unavailable-method fallback, source execution, credential rights and validity, RDP MFA, actual routes, configured ARTEX tools, WAF scope, containment and replay. The gang-policy, progression, data-export, endpoint-fleet, discovery, remediation and model tests also pass. Browser suites check the existing feed and complete workflows at desktop and mobile sizes.

`node scripts/audit-gang-lateral.cjs` runs five actors against the same 50 generated estates (mixed preset, exercise paths enabled, seeds 1–50, baseline mode), asserting source-access chronology and immutable estates. Saved results: [250-run audit](gang-lateral-method-audit.json).

| Profile | Runs with any cross-asset execution | Observed Windows-method examples in this synthetic check |
| --- | ---: | --- |
| LockBit | 41/50 | PsExec selected in 35 runs; direct SMB selected in 17. |
| Conti | 35/50 | Beacon/WMI selected in 35 runs; RDP selected in one. |
| BlackCat | 32/50 | PsExec selected in seven runs; RDP selected in five. |
| Hive | 42/50 | RDP selected in 36 runs; direct WMI selected in nine. |
| REvil | 33/50 | Beacon remote service selected in 33 runs; Beacon/WMI selected in nine. |

Counts can overlap because one run can select multiple methods. Cross-asset execution also includes non-Windows paths; the Windows examples need not sum to the total. No run was truncated. These are coverage checks of the current generator and authored preferences, not historical gang success rates.

## Remaining abstraction

The sources also describe other behaviors, including GPO distribution and third-party remote-access tools. Those need their own directory-policy permissions, deployment scopes or installed service channels; they are not represented by silently relabeling an SMB or RDP route. Credential acquisition remains the existing source-capability/scoped-secret model. This update adds the main missing methods that the current estate and access model can express without inventing those prerequisites.
