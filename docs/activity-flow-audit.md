# Five paired activity-flow reviews

Each pair uses the identical generated estate for ARTEX and one gang. Five fixed seeds were selected before changing progression; they are not selected for successful outcomes. Four defense modes are checked for every pair (40 runs); the detailed logs below show baseline. Times are elapsed H:MM:SS. This review concerns causal order and consistency, not field-duration calibration.

## Findings and corrections

- Gang runs previously opened multiple footholds at the same instant and interleaved unrelated branches. They now prefer progressing an established foothold; additional access attempts consume five minutes. The starting foothold remains at time zero.
- Data transfers previously waited behind unrelated expansion. They now get prompt worker priority after a read. Gang impact follows collection, transfer attempts and exploration; ARTEX pipelines access, collection and export across three workers.
- Duplicate capabilities and excluded techniques previously consumed full action durations. They now consume no worker time. Concurrent attempts for the same capability wait for the first result; an alternate path remains available if the first fails.
- Genuine failed probes and route reviews retain their elapsed time and appear as NO ACCESS or PATH REVIEW. Reviews name the known source, without exposing an unvisited target.
- A session-to-execution upgrade previously failed to reopen outgoing routes. Route keys now include source capabilities and are captured when an attempt starts. Capability ownership preserves the relevant session for containment.
- A running check cannot retroactively use a credential recovered after it started. Newly learned access needs another scheduled attempt.

Different routes are not forced: shared documented techniques may overlap, and blocked exports or limited footholds remain legitimate outcomes. The first foothold and five-minute additional access cost are explicit scenario assumptions, not incident measurements.

## Pair summaries

| Gang / seed | Gang result | ARTEX result | Gang timed dead ends | ARTEX timed dead ends |
| --- | --- | --- | ---: | ---: |
| lockbit / 1853 | Endpoint encryption | Data exfiltrated | 26 | 19 |
| conti / 3 | Endpoint encryption | No protected read established | 9 | 12 |
| blackcat / 8 | Protected record read | Protected record read | 11 | 11 |
| hive / 42 | Endpoint encryption | Data exfiltrated | 19 | 16 |
| revil / 99 | Endpoint encryption | Protected record read | 1 | 13 |

## Detailed activity logs

These show the completed sequence, including timed dead ends; the UI presents the same activity newest first. Source-only PATH REVIEW entries describe reasoning about an unavailable continuation, rather than claiming an unreachable target was probed.

### lockbit · seed 1853

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | T1133 | Windows Remote Desktop · Internet Login | succeeded |
| 0:00:00 → 0:27:39 | T1021.002 | Windows Management Server | succeeded |
| 0:27:39 → 0:55:18 | T1078 | Active Directory Domain Controller | succeeded |
| 0:55:18 → 2:03:26 | T1021.002 | Windows File Server | succeeded |
| 2:03:26 → 3:11:34 | T1021.002 | Finance Desktop Fleet · 30 endpoints | succeeded |
| 3:11:34 → 3:13:34 | NO ACCESS | Finance Desktop Fleet · 30 endpoints | ineligible |
| 3:13:34 → 4:21:42 | T1021.002 | Operations Desktop Fleet · 21 endpoints | succeeded |
| 4:21:42 → 4:23:42 | NO ACCESS | Operations Desktop Fleet · 21 endpoints | ineligible |
| 4:23:42 → 5:31:50 | T1078 | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | succeeded |
| 5:31:50 → 7:31:03 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 7:31:03 → 9:30:16 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 9:30:16 → 11:29:29 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 11:29:29 → 13:28:42 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 13:28:42 → 13:56:21 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 13:56:21 → 14:24:00 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 14:24:00 → 16:23:13 | NO ACCESS | Confidential Department Share | ineligible |
| 16:23:13 → 17:31:21 | NO ACCESS | Engineering Desktop Fleet · 65 endpoints | ineligible |
| 17:31:21 → 18:39:29 | NO ACCESS | Engineering Desktop Fleet · 65 endpoints | ineligible |
| 18:39:29 → 19:47:37 | NO ACCESS | Engineering Desktop Fleet · 65 endpoints | ineligible |
| 19:47:37 → 19:52:37 | CVE-2023-28771 | Zyxel ATP Firewall | succeeded |
| 19:52:37 → 20:20:16 | T1078 | Red Hat Keycloak IdP | succeeded |
| 20:20:16 → 21:28:24 | CVE-2022-22965 | Spring MVC WAR (Tomcat / JDK 9+) B | succeeded |
| 21:28:24 → 23:27:37 | DATA FOUND | Cassandra DB (Streaming · Event Team) | succeeded |
| 23:27:37 → 23:29:41 | DATA EXFILTRATED · 1756 records · Rclone | Cassandra DB (Streaming · Event Team) | succeeded |
| 23:29:41 → 25:28:54 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 25:28:54 → 26:37:02 | PATH REVIEW | Red Hat Keycloak IdP | ineligible |
| 26:37:02 → 27:04:41 | NO ACCESS | WSO2 B2B Webhook Gateway | ineligible |
| 27:04:41 → 29:03:54 | NO ACCESS | Customer Postgres RDS (Primary · Core DBA) | ineligible |
| 29:03:54 → 29:31:33 | NO ACCESS | WSO2 Partner API Gateway | ineligible |
| 29:31:33 → 30:39:41 | PATH REVIEW | Red Hat Keycloak IdP | ineligible |
| 30:39:41 → 31:47:49 | PATH REVIEW | Red Hat Keycloak IdP | ineligible |
| 31:47:49 → 31:52:49 | CVE-2024-24919 | Check Point Quantum Gateway | succeeded |
| 31:52:49 → 32:20:28 | PATH REVIEW | Check Point Quantum Gateway | ineligible |
| 32:20:28 → 32:48:07 | PATH REVIEW | Check Point Quantum Gateway | ineligible |
| 32:48:07 → 32:53:07 | T1566.001 | Windows Desktop · Phishable User | succeeded |
| 32:53:07 → 32:55:07 | NO ACCESS | Windows Desktop · Phishable User | ineligible |
| 32:55:07 → 33:22:46 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 33:22:46 → 33:50:25 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 33:50:25 → 33:55:25 | encryption | Windows Desktop · Phishable User | succeeded |
| 33:55:25 → 34:00:25 | NO ACCESS | Finance Desktop Fleet · 30 endpoints | ineligible |
| 34:00:25 → 34:05:25 | NO ACCESS | Operations Desktop Fleet · 21 endpoints | ineligible |

### ARTEX · seed 1853

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | CVE-2023-28771 | Zyxel ATP Firewall | succeeded |
| 0:00:00 → 0:05:00 | diagnostic_access | Support Diagnostics Portal | succeeded |
| 0:00:00 → 0:05:00 | T1530 | Public Container Management Interface | succeeded |
| 0:05:00 → 0:10:00 | CVE-2024-24919 | Check Point Quantum Gateway | succeeded |
| 0:10:00 → 0:15:00 | T1133 | Windows Remote Desktop · Internet Login | succeeded |
| 0:00:00 → 0:29:03 | T1078 | Red Hat Keycloak IdP | succeeded |
| 0:05:00 → 0:34:03 | T1078 | Staging Status API | succeeded |
| 0:15:00 → 0:44:03 | T1021.002 | Windows Management Server | succeeded |
| 0:29:03 → 0:47:41 | CVE-2022-22965 | Spring MVC WAR (Tomcat / JDK 9+) B | succeeded |
| 0:34:03 → 0:52:41 | PATH REVIEW | Red Hat Keycloak IdP | ineligible |
| 0:47:41 → 1:01:00 | DATA FOUND | Cassandra DB (Streaming · Event Team) | succeeded |
| 1:01:00 → 1:03:04 | DATA EXFILTRATED · 1756 records · HTTP/API bulk extraction | Cassandra DB (Streaming · Event Team) | succeeded |
| 0:52:41 → 1:11:19 | T1021.002 | Windows File Server | succeeded |
| 0:44:03 → 1:13:06 | T1078 | Active Directory Domain Controller | succeeded |
| 1:03:04 → 1:21:42 | T1021.002 | Finance Desktop Fleet · 30 endpoints | succeeded |
| 1:11:19 → 1:29:57 | T1021.002 | Operations Desktop Fleet · 21 endpoints | succeeded |
| 1:21:42 → 1:35:01 | NO ACCESS | Customer Postgres RDS (Primary · Core DBA) | ineligible |
| 1:13:06 → 1:42:09 | NO ACCESS | WSO2 B2B Webhook Gateway | ineligible |
| 1:29:57 → 1:48:35 | T1078 | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | succeeded |
| 1:42:09 → 2:00:47 | PATH REVIEW | Red Hat Keycloak IdP | ineligible |
| 1:35:01 → 2:04:04 | NO ACCESS | WSO2 Partner API Gateway | ineligible |
| 2:00:47 → 2:19:25 | PATH REVIEW | Red Hat Keycloak IdP | ineligible |
| 2:07:13 → 2:20:32 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 2:19:25 → 2:32:44 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 2:04:04 → 2:33:07 | PATH REVIEW | Check Point Quantum Gateway | ineligible |
| 2:20:32 → 2:33:51 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 2:32:44 → 2:46:03 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 2:33:07 → 3:02:10 | PATH REVIEW | Check Point Quantum Gateway | ineligible |
| 2:46:03 → 3:15:06 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 3:15:06 → 3:28:25 | NO ACCESS | Confidential Department Share | ineligible |
| 3:02:10 → 3:31:13 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 3:02:54 → 3:31:57 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 3:28:25 → 3:47:03 | NO ACCESS | Engineering Desktop Fleet · 65 endpoints | ineligible |
| 3:31:13 → 3:49:51 | NO ACCESS | Engineering Desktop Fleet · 65 endpoints | ineligible |
| 3:31:57 → 3:50:35 | NO ACCESS | Engineering Desktop Fleet · 65 endpoints | ineligible |

### conti · seed 3

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | T1566.001 | Windows Desktop · Phishable User | succeeded |
| 0:00:00 → 0:33:39 | T1021.002 | Windows Management Server | succeeded |
| 0:33:39 → 1:07:18 | T1078 | Active Directory Domain Controller | succeeded |
| 1:07:18 → 2:07:33 | T1021.002 | Windows File Server | succeeded |
| 2:07:33 → 3:30:39 | DATA FOUND | Confidential Department Share | succeeded |
| 3:30:39 → 3:32:48 | EXFILTRATION BLOCKED · 4145 records · Rclone | Confidential Department Share | blocked |
| 3:32:48 → 4:33:03 | T1021.002 | Operations Desktop Fleet · 50 endpoints | succeeded |
| 4:33:03 → 5:33:18 | T1078 | Spring MVC WAR / Tomcat / JDK 9+ (Core) | succeeded |
| 5:33:18 → 6:33:33 | T1021.002 | Engineering Desktop Fleet · 45 endpoints | succeeded |
| 6:33:33 → 7:56:39 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Core) | ineligible |
| 7:56:39 → 9:19:45 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Core) | ineligible |
| 9:19:45 → 10:42:51 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Core) | ineligible |
| 10:42:51 → 11:16:30 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 11:16:30 → 12:16:45 | NO ACCESS | Finance Desktop Fleet · 80 endpoints | ineligible |
| 12:16:45 → 13:17:00 | NO ACCESS | Finance Desktop Fleet · 80 endpoints | ineligible |
| 13:17:00 → 14:17:15 | NO ACCESS | Finance Desktop Fleet · 80 endpoints | ineligible |
| 14:17:15 → 14:22:15 | encryption | Windows Desktop · Phishable User | succeeded |
| 14:22:15 → 14:27:15 | NO ACCESS | Operations Desktop Fleet · 50 endpoints | ineligible |
| 14:27:15 → 14:32:15 | NO ACCESS | Engineering Desktop Fleet · 45 endpoints | ineligible |

### ARTEX · seed 3

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | CVE-2021-20016 | SonicWall SMA 100 | succeeded |
| 0:00:00 → 0:05:00 | diagnostic_access | Support Diagnostics Portal | succeeded |
| 0:00:00 → 0:05:00 | CVE-2018-13379 | Fortinet FortiGate SSL VPN | succeeded |
| 0:00:00 → 0:28:49 | T1078 | VMware Workspace ONE Access IdP | succeeded |
| 0:05:00 → 0:33:49 | T1078 | Staging Status API | succeeded |
| 0:05:00 → 0:33:49 | PATH REVIEW | SonicWall SMA 100 | ineligible |
| 0:28:49 → 0:35:10 | CVE-2022-22965 | Spring MVC WAR (Tomcat / JDK 9+) A | succeeded |
| 0:33:49 → 0:40:10 | PATH REVIEW | VMware Workspace ONE Access IdP | ineligible |
| 0:33:49 → 0:40:10 | PATH REVIEW | VMware Workspace ONE Access IdP | ineligible |
| 0:40:10 → 0:46:31 | PATH REVIEW | VMware Workspace ONE Access IdP | ineligible |
| 0:35:10 → 1:06:00 | NO ACCESS | Customer Postgres RDS (Replica 1 · Read Ops) | ineligible |
| 0:40:10 → 1:11:00 | NO ACCESS | MongoDB Cluster (DocStore · Mobile App Team) | ineligible |
| 0:46:31 → 1:15:20 | PATH REVIEW | Fortinet FortiGate SSL VPN | ineligible |
| 1:06:00 → 1:34:49 | PATH REVIEW | Fortinet FortiGate SSL VPN | ineligible |
| 1:11:00 → 1:39:49 | PATH REVIEW | Fortinet FortiGate SSL VPN | ineligible |
| 1:15:20 → 1:44:09 | PATH REVIEW | Fortinet FortiGate SSL VPN | ineligible |
| 1:34:49 → 2:03:38 | PATH REVIEW | Fortinet FortiGate SSL VPN | ineligible |
| 1:39:49 → 2:08:38 | PATH REVIEW | Fortinet FortiGate SSL VPN | ineligible |

### blackcat · seed 8

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | T1133 | Windows Remote Desktop · Internet Login | succeeded |
| 0:00:00 → 1:09:50 | T1047 | Windows Management Server | succeeded |
| 1:09:50 → 2:19:40 | T1078 | Active Directory Domain Controller | succeeded |
| 2:19:40 → 3:27:29 | T1047 | Windows File Server | succeeded |
| 3:27:29 → 4:32:50 | NO ACCESS | Confidential Department Share | ineligible |
| 4:32:50 → 5:40:39 | NO ACCESS | Finance Desktop Fleet · 28 endpoints | ineligible |
| 5:40:39 → 6:48:28 | NO ACCESS | Finance Desktop Fleet · 28 endpoints | ineligible |
| 6:48:28 → 7:56:17 | NO ACCESS | Finance Desktop Fleet · 28 endpoints | ineligible |
| 7:56:17 → 9:04:06 | NO ACCESS | Operations Desktop Fleet · 33 endpoints | ineligible |
| 9:04:06 → 10:11:55 | NO ACCESS | Operations Desktop Fleet · 33 endpoints | ineligible |
| 10:11:55 → 11:19:44 | NO ACCESS | Operations Desktop Fleet · 33 endpoints | ineligible |
| 11:19:44 → 11:24:44 | T1190 | GitLab · Project | succeeded |
| 11:24:44 → 12:34:34 | T1078 | Microsoft AD FS IdP | succeeded |
| 12:34:34 → 13:42:23 | CVE-2023-42793 | JetBrains TeamCity Build Server | succeeded |
| 13:42:23 → 14:47:44 | DATA FOUND | Customer Postgres RDS (Primary · Core DBA) | succeeded |
| 14:47:44 → 14:49:47 | EXFILTRATION BLOCKED · 1050 records · MEGAsync / Rclone | Customer Postgres RDS (Primary · Core DBA) | blocked |
| 14:49:47 → 15:57:36 | PATH REVIEW | Microsoft AD FS IdP | ineligible |
| 15:57:36 → 17:05:25 | PATH REVIEW | Microsoft AD FS IdP | ineligible |
| 17:05:25 → 18:13:14 | PATH REVIEW | Microsoft AD FS IdP | ineligible |
| 18:13:14 → 18:18:14 | CVE-2022-1040 | Sophos Firewall | succeeded |
| 18:18:14 → 19:28:04 | CVE-2021-26855 | Microsoft Exchange Server | succeeded |
| 19:28:04 → 20:35:53 | NO ACCESS | Confluence Server 8.5.1 | ineligible |
| 20:35:53 → 20:40:53 | T1078 | External Device Admin Portal | succeeded |

### ARTEX · seed 8

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | T1190 | GitLab · Project | succeeded |
| 0:00:00 → 0:05:00 | diagnostic_access | Support Diagnostics Portal | succeeded |
| 0:00:00 → 0:05:00 | T1078 | External Device Admin Portal | succeeded |
| 0:05:00 → 0:10:00 | CVE-2022-1040 | Sophos Firewall | succeeded |
| 0:00:00 → 0:12:25 | T1078 | Microsoft AD FS IdP | succeeded |
| 0:05:00 → 0:17:25 | T1078 | Staging Status API | succeeded |
| 0:10:00 → 0:22:25 | CVE-2021-26855 | Microsoft Exchange Server | succeeded |
| 0:17:25 → 0:22:25 | T1133 | Windows Remote Desktop · Internet Login | succeeded |
| 0:22:25 → 0:34:50 | T1021.002 | Windows Management Server | succeeded |
| 0:12:25 → 0:45:59 | CVE-2023-42793 | JetBrains TeamCity Build Server | succeeded |
| 0:34:50 → 0:47:15 | T1078 | Active Directory Domain Controller | succeeded |
| 0:22:25 → 0:55:59 | PATH REVIEW | Microsoft AD FS IdP | ineligible |
| 0:45:59 → 1:06:00 | DATA FOUND | Customer Postgres RDS (Primary · Core DBA) | succeeded |
| 1:06:00 → 1:08:03 | EXFILTRATION BLOCKED · 1050 records · HTTP/API bulk extraction | Customer Postgres RDS (Primary · Core DBA) | blocked |
| 0:47:15 → 1:20:49 | T1021.002 | Windows File Server | succeeded |
| 0:55:59 → 1:29:33 | PATH REVIEW | Microsoft AD FS IdP | ineligible |
| 1:08:03 → 1:41:37 | PATH REVIEW | Microsoft AD FS IdP | ineligible |
| 1:29:33 → 1:49:34 | NO ACCESS | Confidential Department Share | ineligible |
| 1:20:49 → 1:54:23 | NO ACCESS | Confluence Server 8.5.1 | ineligible |
| 1:41:37 → 2:15:11 | NO ACCESS | Finance Desktop Fleet · 28 endpoints | ineligible |
| 1:49:34 → 2:23:08 | NO ACCESS | Finance Desktop Fleet · 28 endpoints | ineligible |
| 1:54:23 → 2:27:57 | NO ACCESS | Finance Desktop Fleet · 28 endpoints | ineligible |
| 2:15:11 → 2:48:45 | NO ACCESS | Operations Desktop Fleet · 33 endpoints | ineligible |
| 2:23:08 → 2:56:42 | NO ACCESS | Operations Desktop Fleet · 33 endpoints | ineligible |
| 2:27:57 → 3:01:31 | NO ACCESS | Operations Desktop Fleet · 33 endpoints | ineligible |

### hive · seed 42

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | T1566.001 | Windows Desktop · Phishable User | succeeded |
| 0:00:00 → 0:23:44 | T1021.001 | Windows Management Server | succeeded |
| 0:23:44 → 0:47:28 | T1078 | Active Directory Domain Controller | succeeded |
| 0:47:28 → 2:09:03 | T1021.001 | Windows File Server | succeeded |
| 2:09:03 → 3:30:38 | T1021.001 | Finance Desktop Fleet · 75 endpoints | succeeded |
| 3:30:38 → 4:52:13 | T1078 | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | succeeded |
| 4:52:13 → 6:13:48 | T1021.001 | Operations Desktop Fleet · 39 endpoints | succeeded |
| 6:13:48 → 7:34:29 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 7:34:29 → 8:55:10 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 8:55:10 → 10:15:51 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 10:15:51 → 11:36:32 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 11:36:32 → 12:00:16 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 12:00:16 → 12:24:00 | PATH REVIEW | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | ineligible |
| 12:24:00 → 13:44:41 | NO ACCESS | Confidential Department Share | ineligible |
| 13:44:41 → 13:49:41 | CVE-2022-1388 | F5 BIG-IP Management Interface | succeeded |
| 13:49:41 → 14:13:25 | T1078 | Fortinet FortiWeb WAF | succeeded |
| 14:13:25 → 15:35:00 | CVE-2022-22965 | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | succeeded |
| 15:35:00 → 16:55:41 | DATA FOUND | Debian Redis Session Cache | succeeded |
| 16:55:41 → 16:57:42 | EXFILTRATION BLOCKED · 131 records · Rclone | Debian Redis Session Cache | blocked |
| 16:57:42 → 17:21:26 | PATH REVIEW | Active Directory Domain Controller | ineligible |
| 17:21:26 → 17:45:10 | NO ACCESS | Citrix NetScaler WAF + Gateway | ineligible |
| 17:45:10 → 19:06:45 | PATH REVIEW | Fortinet FortiWeb WAF | ineligible |
| 19:06:45 → 20:28:20 | PATH REVIEW | Fortinet FortiWeb WAF | ineligible |
| 20:28:20 → 20:52:04 | NO ACCESS | Imperva SecureSphere WAF | ineligible |
| 20:52:04 → 22:12:45 | NO ACCESS | Customer Postgres RDS (Primary · Core DBA) | ineligible |
| 22:12:45 → 22:36:29 | NO ACCESS | WSO2 API Manager | ineligible |
| 22:36:29 → 23:57:10 | NO ACCESS | MongoDB Cluster (DocStore · Mobile App Team) | ineligible |
| 23:57:10 → 24:20:54 | NO ACCESS | WSO2 B2B Webhook Gateway | ineligible |
| 24:20:54 → 24:44:38 | NO ACCESS | WSO2 Customer API GW #01 | ineligible |
| 24:44:38 → 26:05:19 | NO ACCESS | Customer Lake S3 (Parquet · Data Platform) | ineligible |
| 26:05:19 → 26:10:19 | encryption | Windows Desktop · Phishable User | succeeded |
| 26:10:19 → 26:15:19 | NO ACCESS | Finance Desktop Fleet · 75 endpoints | ineligible |
| 26:15:19 → 26:20:19 | encryption | Operations Desktop Fleet · 39 endpoints | succeeded |

### ARTEX · seed 42

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | CVE-2022-1388 | F5 BIG-IP Management Interface | succeeded |
| 0:00:00 → 0:05:00 | diagnostic_access | Support Diagnostics Portal | succeeded |
| 0:00:00 → 0:19:17 | T1078 | Fortinet FortiWeb WAF | succeeded |
| 0:00:00 → 0:19:17 | CVE-2022-29464 | WSO2 Partner API Gateway | succeeded |
| 0:05:00 → 0:24:17 | T1078 | Staging Status API | succeeded |
| 0:19:17 → 0:36:09 | CVE-2022-22965 | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | succeeded |
| 0:19:17 → 0:36:09 | CVE-2023-34362 | MOVEit Transfer (B2B EDI Integration) | succeeded |
| 0:24:17 → 0:43:34 | NO ACCESS | Citrix NetScaler WAF + Gateway | ineligible |
| 0:36:09 → 0:50:00 | DATA FOUND | Debian Redis Session Cache | succeeded |
| 0:50:00 → 0:52:01 | DATA EXFILTRATED · 131 records · HTTP/API bulk extraction | Debian Redis Session Cache | succeeded |
| 0:36:09 → 0:53:01 | PATH REVIEW | Fortinet FortiWeb WAF | ineligible |
| 0:43:34 → 1:00:26 | PATH REVIEW | Fortinet FortiWeb WAF | ineligible |
| 0:52:01 → 1:08:53 | NO ACCESS | IoT Ingestion using Log4j 2 | ineligible |
| 0:53:01 → 1:12:18 | NO ACCESS | Imperva SecureSphere WAF | ineligible |
| 1:00:26 → 1:14:17 | NO ACCESS | Customer Postgres RDS (Primary · Core DBA) | ineligible |
| 1:12:18 → 1:26:09 | NO ACCESS | MongoDB Cluster (DocStore · Mobile App Team) | ineligible |
| 1:08:53 → 1:28:10 | NO ACCESS | WSO2 API Manager | ineligible |
| 1:14:17 → 1:33:34 | NO ACCESS | WSO2 B2B Webhook Gateway | ineligible |
| 1:28:10 → 1:45:02 | NO ACCESS | GoAnywhere MFT (FinOps Data Exchange) | ineligible |
| 1:26:09 → 1:45:26 | NO ACCESS | WSO2 Customer API GW #01 | ineligible |
| 1:33:34 → 1:47:25 | NO ACCESS | Customer Lake S3 (Parquet · Data Platform) | ineligible |
| 1:45:02 → 1:58:53 | NO ACCESS | Customer Lake S3 (Parquet · Data Platform) | ineligible |
| 1:45:26 → 2:04:43 | NO ACCESS | Windows Management Server | ineligible |
| 1:47:25 → 2:06:42 | NO ACCESS | Windows Management Server | ineligible |
| 1:58:53 → 2:18:10 | NO ACCESS | Windows Management Server | ineligible |

### revil · seed 99

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | T1566.001 | Windows Desktop · Phishable User | succeeded |
| 0:00:00 → 0:44:36 | NO ACCESS | Windows Management Server | ineligible |
| 0:44:36 → 0:49:36 | encryption | Windows Desktop · Phishable User | succeeded |

### ARTEX · seed 99

| Start → end | Event | Asset / known source | Outcome |
| --- | --- | --- | --- |
| 0:00:00 → 0:00:00 | T1552.001 | Ivanti Connect Secure VPN | succeeded |
| 0:00:00 → 0:05:00 | diagnostic_access | Support Diagnostics Portal | succeeded |
| 0:00:00 → 0:05:00 | CVE-2024-3400 | PAN-OS GlobalProtect Gateway | succeeded |
| 0:05:00 → 0:10:00 | T1133 | Windows Remote Desktop · Internet Login | succeeded |
| 0:00:00 → 0:13:13 | T1078 | VMware Workspace ONE Access IdP | succeeded |
| 0:05:00 → 0:18:13 | T1078 | Staging Status API | succeeded |
| 0:10:00 → 0:23:13 | PATH REVIEW | Ivanti Connect Secure VPN | ineligible |
| 0:13:13 → 0:31:51 | CVE-2022-22965 | Spring MVC WAR / Tomcat / JDK 9+ (Billing) | succeeded |
| 0:18:13 → 0:36:51 | PATH REVIEW | VMware Workspace ONE Access IdP | ineligible |
| 0:23:13 → 0:41:51 | PATH REVIEW | VMware Workspace ONE Access IdP | ineligible |
| 0:31:51 → 0:54:00 | DATA FOUND | Customer Lake S3 (Parquet · Data Platform) | succeeded |
| 0:54:00 → 0:56:08 | EXFILTRATION BLOCKED · 3775 records · HTTP/API bulk extraction | Customer Lake S3 (Parquet · Data Platform) | blocked |
| 0:36:51 → 0:59:00 | NO ACCESS | Customer Postgres RDS (Primary · Core DBA) | ineligible |
| 0:41:51 → 1:04:00 | NO ACCESS | Debian Redis Session Cache | ineligible |
| 0:56:08 → 1:14:46 | PATH REVIEW | VMware Workspace ONE Access IdP | ineligible |
| 1:04:00 → 1:17:13 | PATH REVIEW | Ivanti Connect Secure VPN | ineligible |
| 0:59:00 → 1:21:09 | NO ACCESS | MongoDB Cluster (DocStore · Mobile App Team) | ineligible |
| 1:14:46 → 1:27:59 | NO ACCESS | Red Hat Keycloak IdP | ineligible |
| 1:17:13 → 1:30:26 | NO ACCESS | WSO2 Customer API GW #02 | ineligible |
| 1:21:09 → 1:34:22 | NO ACCESS | Windows Management Server | ineligible |
| 1:27:59 → 1:41:12 | NO ACCESS | Windows Management Server | ineligible |
| 1:30:26 → 1:43:39 | NO ACCESS | Windows Management Server | ineligible |

## Reproduce

Run `node scripts/audit-activity-flows.cjs`. Add `--write-report docs/activity-flow-audit.md` to regenerate this report. The same checks run across baseline, virtual patching, SOC and combined defenses. `scripts/test-activity-progression.cjs` covers the capability-upgrade, scope and concurrency regressions.
