# REvil: 50-run lateral movement audit

Run on 20 November 2026 before the internal-RDP/Cobalt Strike additions. Per-seed results for that version: [JSON](revil-lateral-50.json). Run `node scripts/audit-revil-lateral.cjs` to audit the current engine; later results can differ from this saved historical snapshot.

## Method

50 distinct generated estates, seeds 1–50, mixed preset, `seedExercise:true`, REvil profile, baseline defenses, default timing and exploration budget. This matches dual-view generation. The exercise option seeds a verified infrastructure path; the generated phishable desktop supplies a foothold. These estates are synthetic exercises, not a representative sample of real enterprises or REvil incidents.

Successful lateral movement means a successful cross-asset execution grant (`app_exec`) over an explicit relationship from a source already reached before the action started. External entries, local encryption, reads and decoys do not count. The script asserts source access chronology for every counted hop.

## Results

| Outcome | Runs | Percentage |
| --- | ---: | ---: |
| Execution foothold | 50 | 100% |
| Successful lateral execution | 33 | 66% |
| No successful lateral execution | 17 | 34% |
| Execution on a department desktop fleet | 23 | 46% |
| More than one endpoint encrypted | 21 | 42% |
| Exploration truncated | 0 | 0% |

Of the 17 without successful lateral execution, 11 recorded failed remote prerequisite checks; six recorded no usable continuation. Thus the 34% must not all be described as failed on-network attempts. Successful runs can also contain failed alternative checks. All 33 runs with lateral execution used T1047 (WMI). Counts for desktop fleets represent access to permitted endpoint subsets, not every member of each fleet.

## Historical comparison and limits

No directly comparable official REvil-specific percentage was found in the sources reviewed. The US Department of Justice's [REvil sentencing release](https://www.justice.gov/usao-ndtx/pr/sodinokibirevil-affiliate-sentenced-role-700m-ransomware-scheme) reports attack scale and extortion, not a denominator and numerator for lateral movement.

Sophos's [2022 report announcement](https://www.sophos.com/ja-jp/press/press-releases/2022/06/attacker-dwell-time-increased-by-36-percent-sophos-active-adversary-playbook-2022-reveals) reports internal lateral RDP use in 82% of its 144 investigated incidents from 2021. This is vendor first-party research across multiple adversaries, not a government REvil rate. Its case selection and protocol-specific metric differ from these synthetic runs; the numerical 16-point difference does not establish that the simulator underestimates REvil by 16 points.

[Unit 42's REvil investigation](https://unit42.paloaltonetworks.com/revil-threat-actors/?_wpnonce=93dadb8c15&lg=en&pdf=print) describes lateral movement using Cobalt Strike BEACON and RDP with compromised credentials, with ScreenConnect and AnyDesk also observed. PsExec was used to deploy encryptors. It supplies behavioral evidence, not an overall lateral-success percentage.

The original audit exposed a model fidelity limitation: [MITRE's REvil WMI mapping](https://attack.mitre.org/software/S0496/) describes monitoring and terminating processes. That version treated the technique ID as permission to choose remote WMI execution. That mapping alone does not substantiate this lateral behavior. A software technique list also omits some affiliate behavior documented in incident investigations. The measured 66% is therefore a property of that estate generator and action policy, not a historically calibrated probability.

## Repeat after adding internal RDP and Cobalt Strike

The subsequent implementation adds separately attributed RDP and Cobalt Strike capabilities and rejects generic REvil remote WMI execution based solely on the software mapping. See the [updated policy](gang-technique-policy.md#internal-rdp-and-cobalt-strike-additions--20-november-2026). The same 50-seed audit was repeated with unchanged generation options: [new results](revil-lateral-50-with-tools.json).

Lateral execution remains 33/50 (66%); fleet access remains 23/50 (46%); encryption of multiple endpoints remains 21/50 (42%). All 33 successful runs use the Cobalt Strike remote-service opportunity; nine additionally use its WMI opportunity on other targets. No RDP method is selected in these default runs because an earlier feasible tool method already supplies execution. Forced-RDP fixtures verify that all gang profiles can select RDP when it is the available route, and tool-disabled fixtures verify the fallback. Tool transport choices and availability remain explicit synthetic assumptions, not measured historical frequencies.
