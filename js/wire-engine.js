(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.WireEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const SCHEMA_VERSION = 3;
  const MAX_ONWARD_PER_SOURCE = 2;
  const MAX_SUCCESS_PER_LAYER = 3;
  const WAF_PORTAL_COVERAGE = 0.66;
  const SOAR_DETECTION_RATE = 0.32;

  const TRUST_ZONES = ['internet-dmz', 'identity-edge', 'internal-mesh', 'data-tier'];

  // Demo-design budgets per layer (starting targets for exploitable findings, not risk rates)
  const LAYER_FINDING_BUDGETS = [
    { min: 1, max: 2 },
    { min: 2, max: 3 },
    { min: 2, max: 3 },
    { min: 1, max: 2 }
  ];

  // Individually reviewed example deployments. Versions and conditions are
  // synthetic; links describe the underlying vulnerability, not this estate.
  const REVIEWED_EXAMPLES = {
    'f5-gateway': { cve: 'CVE-2022-1388', product: 'F5 BIG-IP', version: '16.1.0', conditions: { managementReachable: true }, source: 'https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf' },
    'cust-api': { cve: 'CVE-2022-29464', product: 'WSO2 API Manager', version: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, source: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf' },
    'app-engine': { cve: 'CVE-2022-22965', product: 'Spring Framework', version: '5.3.17', conditions: { jdk9Plus: true, tomcatVulnerable: true, warDeployment: true, mvcDataBinding: true }, source: 'https://spring.io/security/cve-2022-22965/' }
  };

  // Concise attack descriptions based on the linked vulnerability records.
  const CVE_ATTACK_DESCRIPTIONS = {
    "CVE-2018-13379": "FortiOS SSL VPN path traversal can expose system files, including session information.",
    "CVE-2018-5412": "Imperva SecureSphere local code execution vulnerability.",
    "CVE-2018-8340": "AD FS authentication bypass can allow an attacker to bypass multi-factor authentication.",
    "CVE-2019-11510": "Pulse Connect Secure path traversal lets an unauthenticated attacker read server files.",
    "CVE-2020-0618": "SQL Server Reporting Services deserialization can lead to remote code execution.",
    "CVE-2020-1472": "Zerologon abuses Netlogon authentication to gain domain controller privileges.",
    "CVE-2020-14882": "WebLogic console access controls can be bypassed, allowing remote compromise.",
    "CVE-2020-4888": "IBM QRadar deserialization of crafted Java objects can execute commands.",
    "CVE-2021-26855": "ProxyLogon uses server-side request forgery to send requests through Exchange.",
    "CVE-2021-35225": "A SolarWinds NPM flaw can disclose information to a user with limited access.",
    "CVE-2021-3827": "A Keycloak flaw can allow authentication protections to be bypassed.",
    "CVE-2021-42013": "Apache path traversal can expose files and, in some configurations, execute commands.",
    "CVE-2021-44228": "Log4Shell: attacker-controlled log content can trigger a malicious JNDI lookup and remote code execution.",
    "CVE-2022-0543": "A Debian Redis Lua sandbox escape can allow a client to execute system commands.",
    "CVE-2022-1388": "F5 BIG-IP iControl REST authentication bypass can allow remote command execution.",
    "CVE-2022-22954": "VMware Workspace ONE template injection can allow remote code execution.",
    "CVE-2022-22965": "Spring4Shell abuses data binding in affected deployments to execute code.",
    "CVE-2022-26134": "Confluence OGNL injection can allow an unauthenticated attacker to execute code.",
    "CVE-2022-26923": "Certifried abuses Active Directory certificate enrollment to impersonate a computer account.",
    "CVE-2022-29464": "A WSO2 file-upload flaw can let an attacker upload files and execute code.",
    "CVE-2022-29712": "Command injection through LibreNMS service configuration parameters.",
    "CVE-2022-30190": "Follina uses a crafted document to invoke MSDT and execute code.",
    "CVE-2022-42475": "A FortiOS SSL VPN heap overflow can allow unauthenticated remote code execution.",
    "CVE-2022-46169": "Cacti command injection can allow unauthenticated code execution when a vulnerable polling configuration is present.",
    "CVE-2022-47966": "ManageEngine SAML processing can allow remote code execution through a vulnerable XML library.",
    "CVE-2023-0669": "GoAnywhere MFT deserialization can allow unauthenticated remote code execution.",
    "CVE-2023-20198": "Cisco IOS XE web UI access controls can be bypassed to create a privileged account.",
    "CVE-2023-22515": "Confluence broken access control can let an attacker create an administrator account.",
    "CVE-2023-22527": "Confluence template injection can allow unauthenticated remote code execution.",
    "CVE-2023-24489": "A ShareFile storage zones controller flaw can allow unauthenticated remote compromise.",
    "CVE-2023-27350": "PaperCut authentication bypass can allow code execution with SYSTEM privileges.",
    "CVE-2023-2868": "Barracuda Email Security Gateway command injection can enable remote code execution.",
    "CVE-2023-29357": "SharePoint authentication bypass can let an attacker gain administrator privileges using forged tokens.",
    "CVE-2023-32707": "A Splunk Enterprise vulnerability can allow privilege escalation.",
    "CVE-2023-34362": "MOVEit Transfer SQL injection can give an unauthenticated attacker access to its database.",
    "CVE-2023-3519": "NetScaler ADC and Gateway code injection can allow unauthenticated remote code execution.",
    "CVE-2023-36884": "A crafted Office document can exploit a Windows and Office remote code execution vulnerability.",
    "CVE-2023-38035": "Ivanti Sentry authentication bypass can expose restricted administrative functionality.",
    "CVE-2023-42793": "TeamCity authentication bypass can allow access to administrative functions.",
    "CVE-2023-46604": "ActiveMQ OpenWire deserialization can allow remote shell command execution.",
    "CVE-2023-46747": "F5 BIG-IP configuration utility authentication bypass can allow remote system commands.",
    "CVE-2023-46805": "Ivanti Connect Secure authentication bypass can expose restricted resources.",
    "CVE-2023-48788": "FortiClient EMS SQL injection can allow unauthorized code or command execution.",
    "CVE-2023-4966": "Citrix Bleed can leak NetScaler session tokens from appliance memory.",
    "CVE-2024-1086": "A Linux netfilter use-after-free can allow a local attacker to escalate privileges.",
    "CVE-2024-1709": "ScreenConnect authentication bypass can allow unauthorized administrative access.",
    "CVE-2024-21887": "Ivanti Connect Secure command injection can allow an attacker with administrative access to execute commands.",
    "CVE-2024-27198": "TeamCity authentication bypass can allow an unauthenticated attacker to gain administrative access.",
    "CVE-2024-29824": "Ivanti EPM SQL injection can let an unauthenticated attacker on the same network execute code.",
    "CVE-2024-3400": "PAN-OS GlobalProtect command injection can allow unauthenticated code execution as root.",
    "CVE-2024-37085": "ESXi authentication bypass can grant elevated access through a specially named Active Directory group.",
    "CVE-2024-4577": "PHP CGI argument injection can allow remote code execution in affected Windows configurations.",
    "CVE-2025-64446": "FortiWeb path traversal can let a remote attacker reach restricted management functionality.",
    "CVE-2026-25769": "A compromised Wazuh worker can exploit deserialization to execute code on the cluster master.",
    "CVE-2026-42271": "LiteLLM MCP test endpoint command injection can allow a user with a valid API key to execute commands.",
    "CVE-2026-78597": "A low-privileged Kibana user can invoke an Entity Store operation to create unauthorized API credentials."
  };

  // CISA KEV catalog grouped by simulation layer; only explicit product mappings are assigned.
  const LAYER_KEVS = [
    [
      { id: 'CVE-2024-4577', title: 'PHP CGI Arg Injection RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-46805', title: 'Ivanti Connect Secure Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2024-3400', title: 'PAN-OS Command Injection RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-3519', title: 'Citrix NetScaler ADC Unauth RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-20198', title: 'Cisco IOS XE Priv Escalation', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2024-21887', title: 'Ivanti Connect Policy Injection', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-1388', title: 'F5 BIG-IP iControl REST Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-42475', title: 'FortiOS SSL-VPN Heap Buffer Overflow', tech: 'T1190', inKev: true, reqInterface: 'vpn', yields: 'app_exec' },
      { id: 'CVE-2018-13379', title: 'FortiOS SSL-VPN Path Traversal', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2019-11510', title: 'Pulse Connect Secure Arbitrary File Read', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2021-42013', title: 'Apache HTTP Server Path Traversal', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' }
    ],
    [
      { id: 'CVE-2023-22515', title: 'Confluence Broken Access Control', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2024-27198', title: 'TeamCity Admin Token Minting', tech: 'T1552', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2023-38035', title: 'Ivanti Sentry API Auth Bypass', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-4966', title: 'Citrix Bleed Session Leak', tech: 'T1552', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2024-1709', title: 'ScreenConnect Auth Bypass', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2021-26855', title: 'ProxyLogon Exchange SSRF', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-26923', title: 'Active Directory Certifried Spoofing', tech: 'T1068', inKev: true, reqInterface: 'ad-rpc', yields: 'account_session' },
      { id: 'CVE-2023-29357', title: 'SharePoint OAuth Token Bypass', tech: 'T1552', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2022-29464', title: 'WSO2 API Arbitrary File Upload', tech: 'T1505', inKev: true, reqInterface: 'api-https', yields: 'app_exec' },
      { id: 'CVE-2024-29824', title: 'Ivanti EPM Core SQL Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-46747', title: 'F5 BIG-IP Configuration Utility Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-22954', title: 'VMware Workspace ONE Access Template Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-32707', title: 'Splunk Enterprise Privilege Escalation', tech: 'T1068', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2025-64446', title: 'FortiWeb Management Path Traversal', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2023-3519', title: 'NetScaler ADC Remote Code Execution', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2018-5412', title: 'Imperva SecureSphere Local Code Execution', tech: 'T1068', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2021-3827', title: 'Keycloak MFA Bypass', tech: 'T1556', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2018-8340', title: 'AD FS MFA Bypass', tech: 'T1556', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2020-4888', title: 'IBM QRadar Deserialization', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2026-78597', title: 'Kibana Entity Store Credential Creation', tech: 'T1098', inKev: false, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2026-25769', title: 'Wazuh Server Deserialization', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' }
    ],
    [
      { id: 'CVE-2026-42271', title: 'LiteLLM MCP command execution (valid API key required)', tech: 'T1059', inKev: false, reqInterface: 'api-https', requiresAuth: true, yields: 'app_exec' },
      { id: 'CVE-2023-48788', title: 'FortiClient EMS SQL injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2020-0618', title: 'SQL Server Reporting Services RCE', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2021-44228', title: 'Log4Shell JNDI Remote Code Execution', tech: 'T1059', inKev: true, reqInterface: 'api-https', yields: 'app_exec' },
      { id: 'CVE-2023-22527', title: 'Confluence OGNL Template Injection', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-22965', title: 'Spring4Shell Data Binding RCE', tech: 'T1190', inKev: true, reqInterface: 'api-https', yields: 'app_exec' },
      { id: 'CVE-2023-2868', title: 'Barracuda ESG Command Injection', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-30190', title: 'MSDT Follina Command RCE', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-46604', title: 'ActiveMQ OpenWire Deserialization RCE', tech: 'T1059', inKev: true, reqInterface: 'amqp', yields: 'app_exec' },
      { id: 'CVE-2022-46169', title: 'Cacti Unauth Command Injection RCE', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-29712', title: 'LibreNMS service parameter command injection', tech: 'T1059', inKev: false, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2021-35225', title: 'SolarWinds NPM information disclosure', tech: 'T1552', inKev: false, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2023-42793', title: 'TeamCity Authentication Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2020-14882', title: 'Oracle WebLogic Console Access Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-22515', title: 'Confluence Broken Access Control', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'account_session' },
      { id: 'CVE-2023-34362', title: 'MOVEit Transfer SQL Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-0669', title: 'GoAnywhere MFT Deserialization RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' }
    ],
    [
      { id: 'CVE-2023-27350', title: 'PaperCut Setup Wizard DB Dump', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2020-1472', title: 'Zerologon Cryptographic Hash Dump', tech: 'T1003', inKev: true, reqInterface: 'ad-rpc', yields: 'data_read' },
      { id: 'CVE-2023-36884', title: 'Office Document File Exfiltration', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2023-48788', title: 'FortiClient EMS SQLi Database Dump', tech: 'T1041', inKev: true, reqInterface: 'db-mssql', yields: 'data_read' },
      { id: 'CVE-2022-47966', title: 'ManageEngine SAML RCE & PostgreSQL Dump', tech: 'T1041', inKev: true, reqInterface: 'db-pg', yields: 'data_read' },
      { id: 'CVE-2024-37085', title: 'VMware ESXi AD Bypass & VMFS Disk Dump', tech: 'T1005', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2023-24489', title: 'Citrix ShareFile Storage Zone Exfiltration', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2022-26134', title: 'Confluence OGNL DB Pool Credential Harvest', tech: 'T1003', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2024-1086', title: 'Linux Netfilter PrivEsc & Vault DB Dump', tech: 'T1003', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2022-22954', title: 'VMware Workspace ONE SSTI DB Secrets Dump', tech: 'T1041', inKev: true, reqInterface: 'https', yields: 'data_read' },
      { id: 'CVE-2022-0543', title: 'Debian Redis Lua Sandbox Escape', tech: 'T1059', inKev: true, reqInterface: 'redis', yields: 'data_read' },
      { id: 'CVE-2020-0618', title: 'SQL Server Reporting Services RCE', tech: 'T1059', inKev: false, reqInterface: 'db-mssql', yields: 'data_read' }
    ]
  ];

  const KEV_MITIGATION_RULES = {
    'CVE-2026-42271': { waf: { mitigates: false, reason: 'The internal LiteLLM proxy is not assumed to be covered by the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Scenario assumption: agentic response detects unexpected subprocess execution by the proxy.' } },
    'CVE-2024-4577': { waf: { mitigates: true, control: 'NIST SI-2 / SC-7', reason: 'WAF query regex drops %ad PHP CGI argument injection' }, ml: { mitigates: false, reason: 'Edge CGI exploit bypasses internal behavioral telemetry' } },
    'CVE-2023-46805': { waf: { mitigates: true, control: 'NIST SC-7', reason: 'WAF virtual patch restricts unauthenticated /api/v1/cav/client endpoints' }, ml: { mitigates: false, reason: 'Perimeter auth bypass occurs before internal ML baseline can flag session' } },
    'CVE-2024-3400': { waf: { mitigates: true, control: 'NIST SI-2 / SC-7', reason: 'Simulated targeted virtual patch filters malicious HTTP requests to the GlobalProtect portal when covered.' }, ml: { mitigates: false, reason: 'Edge firewall OS injection executes at edge appliance firmware layer' } },
    'CVE-2023-3519': { waf: { mitigates: true, control: 'NIST SC-7', reason: 'WAF protocol validator drops malformed HTTP Host header buffer overflow' }, ml: { mitigates: false, reason: 'Edge ADC stack overflow executes pre-auth before user identity creation' } },
    'CVE-2023-20198': { waf: { mitigates: false, reason: 'Direct REST management endpoint bypasses edge reverse proxy' }, ml: { mitigates: false, reason: 'Direct network boundary exploitation circumvents internal host ML agents' } },
    'CVE-2024-21887': { waf: { mitigates: false, reason: 'In-line edge gateway exploit triggers prior to internal microservice logs' }, ml: { mitigates: false, reason: 'In-line edge gateway exploit triggers prior to internal microservice logs' } },
    'CVE-2022-1388': { waf: { mitigates: true, control: 'NIST SC-7', reason: 'WAF drops hop-by-hop Connection header smuggling to /mgmt/shared/authn' }, ml: { mitigates: false, reason: 'Edge appliance admin bypass executes outside host mesh' } },
    'CVE-2022-42475': { waf: { mitigates: false, reason: 'VPN binary protocol heap overflow bypasses L7 HTTP reverse proxy' }, ml: { mitigates: false, reason: 'Edge VPN daemon heap overwrite occurs before telemetry ingestion' } },
    'CVE-2023-22515': { waf: { mitigates: false, reason: 'Legitimate HTTP requests to /setup endpoints pass perimeter WAF inspection' }, ml: { mitigates: true, control: 'NIST SI-4 / AC-3', reason: 'Agentic SOC Mitigation flags setup wizard execution on established production instance' } },
    'CVE-2024-27198': { waf: { mitigates: false, reason: 'OAuth/Auth endpoint traversal passes standard perimeter HTTP parsers' }, ml: { mitigates: true, control: 'NIST IA-5 / AC-3', reason: 'Agentic SOC Mitigation isolates service on forged administrative token minting' } },
    'CVE-2023-38035': { waf: { mitigates: true, control: 'NIST SC-7', reason: 'Edge WAF blocks unauthenticated HTTP requests to MICS port 8443 interface' }, ml: { mitigates: false, reason: 'Admin API interface lacks granular internal behavioral baseline' } },
    'CVE-2023-4966': { waf: { mitigates: false, reason: 'Outbound session token memory disclosure occurs in TLS response stream' }, ml: { mitigates: true, control: 'NIST AC-3 / IA-5', reason: 'Zero-Trust ML halts stolen session token used across divergent IP/fingerprint' } },
    'CVE-2024-1709': { waf: { mitigates: false, reason: 'Setup wizard URI /SetupWizard.aspx is considered valid application traffic by WAF' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation blocks unauthorized admin account creation out-of-band' } },
    'CVE-2021-26855': { waf: { mitigates: true, control: 'NIST SI-2 / SC-7', reason: 'WAF virtual patch filters X-AnonResource-Backend SSRF header' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects internal SSRF lateral probe to backend Exchange RPC' } },
    'CVE-2022-26923': { waf: { mitigates: false, reason: 'Active Directory certificate enrollment traffic is outside HTTP WAF scope' }, ml: { mitigates: true, control: 'NIST IA-5 / AC-3', reason: 'Agentic SOC Mitigation detects anomalous dNSHostName attribute modification on computer account' } },
    'CVE-2023-29357': { waf: { mitigates: false, reason: 'Forged JWT signing alg=none tokens pass initial TLS termination proxies' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation isolates spoofed farm administrator claims without valid IdP signature' } },
    'CVE-2021-44228': { waf: { mitigates: false, reason: 'Nested/obfuscated JNDI ${jndi:ldap://...} strings bypass edge WAF pattern matching' }, ml: { mitigates: true, control: 'NIST SI-4 / SC-7', reason: 'Agentic SOC Mitigation terminates unexpected outbound LDAP/RMI egress from worker node' } },
    'CVE-2023-22527': { waf: { mitigates: false, reason: 'OGNL template injection resides inside legitimate JSON/POST application payload' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects anomalous subprocess spawning /bin/sh from java.exe' } },
    'CVE-2022-22965': { waf: { mitigates: false, reason: 'Spring parameter binding injection evades standard perimeter URL signatures' }, ml: { mitigates: true, control: 'NIST SI-4 / SI-3', reason: 'Agentic SOC Mitigation halts unexpected file write to Tomcat webapps/ROOT/shell.jsp' } },
    'CVE-2022-29464': { waf: { mitigates: false, reason: 'Multipart file upload endpoint accepts standard HTTP multipart requests' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Zero-Trust agent blocks execution of newly dropped unapproved JSP binary' } },
    'CVE-2023-2868': { waf: { mitigates: false, reason: 'Perimeter WAF does not inspect deep internal tar archive attachments' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects anomalous reverse shell connection to foreign IP' } },
    'CVE-2022-30190': { waf: { mitigates: false, reason: 'MSDT URI handler protocol payload passes perimeter proxies as normal doc link' }, ml: { mitigates: true, control: 'NIST SI-4 / AC-3', reason: 'Agentic SOC Mitigation terminates rogue sdiagnhost.exe process execution' } },
    'CVE-2023-46604': { waf: { mitigates: false, reason: 'OpenWire TCP 61616 protocol traffic bypasses perimeter HTTP WAF' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation terminates anomalous Java ClassPathXmlApplicationContext load' } },
    'CVE-2022-46169': { waf: { mitigates: false, reason: 'Forwarded-For header spoofing bypasses remote agent authentication' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation flags shell command injection in poller.php execution' } },
    'CVE-2023-42793': { waf: { mitigates: false, reason: 'The internal TeamCity management service is outside the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Behavioral monitoring detects an anomalous TeamCity administrative session and build execution.' } },
    'CVE-2023-34362': { waf: { mitigates: true, control: 'NIST SI-2', reason: 'WAF SQLi virtual patch inspects & blocks malformed X-MOVEit headers' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects abnormal mass query exfiltration on core SQL tables' } },
    'CVE-2023-27350': { waf: { mitigates: false, reason: 'Setup wizard bypass occurs over legitimate administrative web interface' }, ml: { mitigates: true, control: 'NIST SI-4 / AC-3', reason: 'Agentic SOC Mitigation blocks unauthenticated database dump and lateral admin spawn' } },
    'CVE-2020-1472': { waf: { mitigates: false, reason: 'Zerologon exploits Netlogon RPC (TCP 135/445), not covered by HTTP/WAF' }, ml: { mitigates: true, control: 'NIST AC-3 / IA-5', reason: 'Agentic SOC Mitigation flags anomalous NetrServerAuthenticate with 16 zero-bytes' } },
    'CVE-2023-36884': { waf: { mitigates: false, reason: 'Office document protocol payload bypasses perimeter application firewalls' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation halts SearchFilterHost.exe memory injection and credential dump' } },
    'CVE-2023-0669': { waf: { mitigates: false, reason: 'Encrypted deserialization payload in GoAnywhere passes perimeter proxies' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects abnormal customer storage zone file exfiltration' } },
    'CVE-2023-48788': { waf: { mitigates: false, reason: 'FortiClient EMS SQL injection occurs inside internal enterprise client RPC' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects xp_cmdshell execution and mass DB schema dumping' } },
    'CVE-2022-47966': { waf: { mitigates: false, reason: 'SAML XML body injection evades edge pattern matchers without deep cert validation' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation blocks anomalous PostgreSQL data export and child process execution' } },
    'CVE-2024-37085': { waf: { mitigates: false, reason: 'ESXi hypervisor management protocol operates outside perimeter WAF boundaries' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation alerts on rogue ESX Admins group creation attempting VMFS storage exfil' } },
    'CVE-2023-24489': { waf: { mitigates: false, reason: 'Unauthenticated file upload to Storage Zone Controller bypasses perimeter checks' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation halts unexpected high-volume S3 customer lake exfiltration' } },
    'CVE-2022-26134': { waf: { mitigates: false, reason: 'OGNL payload executed against internal application server pool' }, ml: { mitigates: true, control: 'NIST IA-5', reason: 'Agentic SOC Mitigation detects memory dumping of database connection credentials' } },
    'CVE-2024-1086': { waf: { mitigates: false, reason: 'Local Linux kernel netfilter double-free exploit is internal to host OS' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation terminates unauthorized privilege escalation targeting root vault databases' } },
    'CVE-2022-22954': { waf: { mitigates: false, reason: 'SSTI expression inside OAuth client parameters bypasses standard URI filters' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects lateral dump of embedded identity database secrets' } },
    'CVE-2018-13379': { waf: { mitigates: true, control: 'NIST SI-2 / SC-7', reason: 'Simulated virtual patch filters malicious requests to the FortiOS SSL VPN web portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2019-11510': { waf: { mitigates: true, control: 'NIST SI-2 / SC-7', reason: 'Simulated virtual patch filters malicious requests to the Pulse web portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2021-42013': { waf: { mitigates: true, control: 'NIST SI-2', reason: 'Simulated WAF rule blocks traversal requests.' }, ml: { mitigates: false, reason: 'The edge server is outside internal behavioral monitoring.' } },
    'CVE-2024-29824': { waf: { mitigates: false, reason: 'The EPM core server is on the internal network.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Simulated monitoring flags anomalous EPM database activity.' } },
    'CVE-2020-14882': { waf: { mitigates: false, reason: 'The internal WebLogic console is outside the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Simulated monitoring flags anomalous console access.' } },
    'CVE-2022-0543': { waf: { mitigates: false, reason: 'Redis protocol traffic is outside the HTTP WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Simulated monitoring flags unexpected Redis child processes.' } },
    'CVE-2020-0618': { waf: { mitigates: false, reason: 'The internal reporting service is outside the perimeter WAF.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Simulated monitoring flags unexpected reporting-service execution.' } },
    'CVE-2023-46747': { waf: { mitigates: false, reason: 'The BIG-IP management interface is assumed reachable outside the protected application path.' }, ml: { mitigates: false, reason: 'The appliance management plane is outside internal host monitoring.' } },
    'CVE-2023-32707': { waf: { mitigates: false, reason: 'The Splunk management service is internal.' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Simulated monitoring flags anomalous administrative role changes.' } }
  };

  ['CVE-2025-64446', 'CVE-2018-5412', 'CVE-2021-3827', 'CVE-2018-8340', 'CVE-2020-4888', 'CVE-2026-78597', 'CVE-2026-25769'].forEach(id => {
    KEV_MITIGATION_RULES[id] = {
      waf: { mitigates: false, reason: 'The simulated management or service path is outside the perimeter WAF.' },
      ml: { mitigates: true, control: 'NIST SI-4', reason: 'The scenario assumes independent monitoring detects the anomalous activity.' }
    };
  });

  const LAYER_CONFIG = [
    {
      name: '01 / Cloud Ingress',
      xBand: [0.08, 0.22],
      clusters: [
        {
          name: 'AWS Cloud Perimeter',
          targets: [
            { id: 'public-s3', icon: 'data.png', interfaces: ['storage-s3', 'https'], attackTechnique: 'T1530', attackDescription: 'Data from Cloud Storage', publicExposure: 'Simulated S3 bucket permits anonymous public read; the contents are not assumed to contain credentials.', variants: ['Amazon S3 · Bucket'] },
            { id: 'ivanti-connect', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2023-46805'], variants: ['Ivanti Connect Secure VPN'] },
            { id: 'f5-gateway', icon: 'network.png', interfaces: ['https'], kevByVariant: ['CVE-2022-1388'], variants: ['F5 BIG-IP Management Interface'] },
            { id: 'forti-vpn', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2018-13379'], variants: ['FortiOS SSL VPN'] }
          ]
        },
        {
          name: 'Azure Enterprise',
          targets: [
            { id: 'public-blob', icon: 'data.png', interfaces: ['storage-s3', 'https'], attackTechnique: 'T1530', attackDescription: 'Data from Cloud Storage', publicExposure: 'Simulated Azure Blob container permits anonymous public read; the contents are not assumed to contain credentials.', variants: ['Azure Blob Storage · Container'] },
            { id: 'pan-globalprotect', icon: 'network.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2024-3400'], variants: ['PAN-OS GlobalProtect Gateway'] },
            { id: 'pulse-vpn', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2019-11510'], variants: ['Pulse Connect Secure VPN'] }
          ]
        },
        {
          name: 'GCP & Partners',
          targets: [
            { id: 'public-gitlab', icon: 'code.png', interfaces: ['repo-http', 'https'], attackTechnique: 'T1593.003', attackDescription: 'Search public code repositories', publicExposure: 'Simulated GitLab project is publicly readable contrary to its intended access policy.', variants: ['GitLab · Project'] },
            { id: 'public-bitbucket', icon: 'code.png', interfaces: ['repo-http', 'https'], attackTechnique: 'T1593.003', attackDescription: 'Search public code repositories', publicExposure: 'Simulated Bitbucket repository is publicly readable contrary to its intended access policy.', variants: ['Bitbucket · Repository'] },
            { id: 'citrix-adc', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-3519'], variants: ['Citrix NetScaler ADC Gateway'] },
            { id: 'apache-edge', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2021-42013'], variants: ['Apache HTTP Server 2.4.50 Edge'] }
          ]
        }
      ]
    },
    {
      name: '02 / Gateways & Auth',
      xBand: [0.32, 0.46],
      clusters: [
        {
          name: 'API Gateways',
          targets: [
            { id: 'cust-api', icon: 'api.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-29464', 'CVE-2022-29464', 'CVE-2022-29464'], variants: ['WSO2 Customer API GW #01', 'WSO2 Customer API GW #02', 'WSO2 Customer API GW #03'] },
            { id: 'partner-api', icon: 'api.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-29464', 'CVE-2022-29464', 'CVE-2022-29464'], variants: ['WSO2 Partner API Gateway', 'WSO2 B2B Webhook Gateway', 'WSO2 Partner Sync Gateway'] },
            { id: 'waf-proxy', icon: 'server-infrastructure.png', interfaces: ['https'], isSecurity: true, productPool: true, vulnerabilityChance: 0.25, kevByVariant: ['CVE-2023-46747', 'CVE-2025-64446', 'CVE-2023-3519', 'CVE-2018-5412'], variants: ['F5 BIG-IP Advanced WAF', 'Fortinet FortiWeb WAF', 'Citrix NetScaler WAF + Gateway', 'Imperva SecureSphere WAF'] },
            { id: 'wso2-api', icon: 'api.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-29464'], variants: ['WSO2 API Manager'] },
            { id: 'exchange', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2021-26855'], variants: ['Microsoft Exchange Server'] }
          ]
        },
        {
          name: 'Identity & Access',
          targets: [
            { id: 'iam-idp', icon: 'identity.png', interfaces: ['https'], supportsSpray: true, productPool: true, vulnerabilityChance: 0.25, kevByVariant: ['CVE-2022-22954', 'CVE-2018-8340', 'CVE-2021-3827', null], variants: ['VMware Workspace ONE Access IdP', 'Microsoft AD FS IdP', 'Red Hat Keycloak IdP', 'Okta Identity Cloud'] },
            { id: 'vault-creds', icon: 'configuration.png', interfaces: ['https', 'api-https'], isSecurity: true, variants: ['HashiCorp Vault Secrets Server'] },
            { id: 'sentry-auth', icon: 'endpoint.png', interfaces: ['https'], supportsSpray: true, kevByVariant: ['CVE-2023-38035', 'CVE-2023-38035'], variants: ['Ivanti Sentry GW 01', 'Ivanti Sentry GW 02'] },
            { id: 'ad-identity', icon: 'identity.png', interfaces: ['ad-rpc', 'https'], supportsSpray: true, kevByVariant: ['CVE-2022-26923'], variants: ['Active Directory Domain Controller'] },
            { id: 'ivanti-epm', icon: 'endpoint.png', interfaces: ['https'], kevByVariant: ['CVE-2024-29824'], variants: ['Ivanti Endpoint Manager Core'] }
          ]
        },
        {
          name: 'Boundary Controls',
          targets: [
            { id: 'threat-det', icon: 'threat-detection.png', interfaces: ['https'], isSecurity: true, productPool: true, vulnerabilityChance: 0.25, kevByVariant: ['CVE-2023-32707', 'CVE-2020-4888', 'CVE-2026-78597', 'CVE-2026-25769'], variants: ['Splunk Enterprise', 'IBM QRadar SIEM', 'Elastic Security / Kibana', 'Wazuh Server'] }
          ]
        }
      ]
    },
    {
      name: '03 / Services Mesh',
      xBand: [0.54, 0.70],
      clusters: [
        {
          name: 'Core Applications',
          targets: [
            { id: 'app-engine', icon: 'application.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-22965', 'CVE-2022-22965', 'CVE-2022-22965'], variants: ['Spring MVC WAR / Tomcat / JDK 9+ (Core)', 'Spring MVC WAR / Tomcat / JDK 9+ (Billing)', 'Spring MVC WAR / Tomcat / JDK 9+ (Checkout)'] },
            { id: 'comp-registry', icon: 'components.png', interfaces: ['api-https', 'https'], variants: ['Container Registry'] },
            { id: 'cicd-runner', icon: 'cicd.png', interfaces: ['https'], kevByVariant: ['CVE-2023-42793'], variants: ['JetBrains TeamCity Build Server'] },
            { id: 'activemq', icon: 'components.png', interfaces: ['amqp'], kevByVariant: ['CVE-2023-46604'], variants: ['Apache ActiveMQ Message Broker'] },
            { id: 'moveit-sftp', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-34362', 'CVE-2023-0669'], variants: ['MOVEit Transfer (B2B EDI Integration)', 'GoAnywhere MFT (FinOps Data Exchange)'] }
          ]
        },
        {
          name: 'Internal Microservices',
          targets: [
            { id: 'log4j-svc', icon: 'server-infrastructure.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2021-44228', 'CVE-2021-44228'], variants: ['Service using Log4j 2 #01', 'Service using Log4j 2 #02'] },
            { id: 'spring-svc', icon: 'application.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2022-22965', 'CVE-2022-22965'], variants: ['Spring MVC WAR (Tomcat / JDK 9+) A', 'Spring MVC WAR (Tomcat / JDK 9+) B'] },
            { id: 'confluence-node', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-22527'], variants: ['Internal Confluence Data Center'] },
            { id: 'confluence-admin', icon: 'application.png', interfaces: ['https'], kevByVariant: ['CVE-2023-22515'], variants: ['Confluence Server 8.5.1'] },
            { id: 'weblogic', icon: 'application.png', interfaces: ['https'], kevByVariant: ['CVE-2020-14882'], variants: ['Oracle WebLogic Admin Console'] },
            { id: 'sql-reporting', icon: 'application.png', interfaces: ['https'], kevByVariant: ['CVE-2020-0618'], variants: ['SQL Server Reporting Services'] },
            { id: 'forti-ems', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-48788'], variants: ['FortiClient EMS Server'] }
          ]
        },
        {
          name: 'AI & Operations',
          targets: [
            { id: 'ai-core', icon: 'ai.png', interfaces: ['api-https'], kevByVariant: ['CVE-2026-42271'], variants: ['LiteLLM Proxy 1.83.6'] },
            { id: 'iot-hub', icon: 'iot.png', interfaces: ['api-https', 'https'], kevByVariant: ['CVE-2021-44228'], variants: ['IoT Ingestion using Log4j 2'] },
            { id: 'vuln-scan', icon: 'vulnerability-management.png', interfaces: ['https'], isSecurity: true, productPool: true, maxInstances: 1, includeChance: 0.9, kevByVariant: ['CVE-2022-46169', 'CVE-2022-29712', 'CVE-2021-35225', null, null, null], variants: ['Cacti Network Monitoring Server', 'LibreNMS 22.3.0', 'SolarWinds NPM 2020.2.6', 'Zabbix Network Monitor', 'PRTG Network Monitor', 'ManageEngine OpManager'] }
          ]
        }
      ]
    },
    {
      name: '04 / Data Stores & Secrets',
      xBand: [0.78, 0.92],
      clusters: [
        {
          name: 'Data Stores: Customer Records & Orders',
          targets: [
            { id: 'lake-cust', icon: 'data.png', interfaces: ['storage-s3', 'https'], isLake: true, variants: ['Customer Lake S3 (Parquet · Data Platform)', 'Customer Lake S3 (Curated · BI Team)', 'Customer Lake S3 (Cold Archive · Compliance)'] },
            { id: 'db-rds', icon: 'server-infrastructure.png', interfaces: ['db-pg'], isDb: true, variants: ['Customer Postgres RDS (Primary · Core DBA)', 'Customer Postgres RDS (Replica 1 · Read Ops)', 'Customer MySQL RDS (Orders · Merchant Team)'] }
          ]
        },
        {
          name: 'Data Stores: Analytics, Document & Secrets',
          targets: [
            { id: 'lake-ops', icon: 'data.png', interfaces: ['storage-s3', 'https'], variants: ['Snowflake Warehouse (SnowSQL · Enterprise BI)', 'ClickHouse Telemetry Lake (SecOps Team)', 'BigQuery Analytics Lake (Marketing Data)'] },
            { id: 'nosql-doc', icon: 'server-infrastructure.png', interfaces: ['db-pg', 'https'], isDb: true, variants: ['MongoDB Cluster (DocStore · Mobile App Team)', 'Redis Cache Cluster (In-Memory · Session Ops)', 'Cassandra DB (Streaming · Event Team)'] },
            { id: 'litellm-db', icon: 'server-infrastructure.png', interfaces: ['db-pg'], isDb: true, variants: ['LiteLLM PostgreSQL Database'] },
            { id: 'mssql-db', icon: 'server-infrastructure.png', interfaces: ['db-mssql'], isDb: true, variants: ['Microsoft SQL Server Database'] },
            { id: 'redis-debian', icon: 'server-infrastructure.png', interfaces: ['redis'], isDb: true, kevByVariant: ['CVE-2022-0543'], variants: ['Debian Redis Session Cache'] }
          ]
        }
      ]
    }
  ];

  const ALLOWED_CONNECTIONS = {
    'public-gitlab': ['iam-idp'],
    'ivanti-connect': ['cust-api', 'iam-idp'],
    'f5-gateway': ['cust-api', 'partner-api', 'waf-proxy', 'wso2-api'],
    'forti-vpn': ['sentry-auth', 'ivanti-epm', 'iam-idp', 'ad-identity', 'vault-creds', 'threat-det'],
    'pulse-vpn': ['sentry-auth', 'ivanti-epm'],
    'apache-edge': ['cust-api', 'exchange'],
    'pan-globalprotect': ['cust-api', 'iam-idp'],
    'citrix-adc': ['wso2-api'],
    'cust-api': ['app-engine', 'spring-svc', 'iot-hub', 'ai-core', 'log4j-svc', 'activemq'],
    'partner-api': ['app-engine', 'iot-hub', 'moveit-sftp'],
    'waf-proxy': ['app-engine', 'spring-svc', 'confluence-node'],
    'iam-idp': ['app-engine', 'spring-svc', 'cicd-runner', 'comp-registry'],
    'wso2-api': ['app-engine', 'spring-svc', 'moveit-sftp', 'ai-core'],
    'sentry-auth': ['app-engine', 'spring-svc', 'forti-ems', 'sql-reporting'],
    'exchange': ['confluence-admin'],
    'ivanti-epm': ['forti-ems', 'weblogic', 'vuln-scan'],
    'app-engine': ['lake-cust', 'db-rds', 'nosql-doc', 'redis-debian'],
    'moveit-sftp': ['lake-cust'],
    'confluence-node': ['mssql-db'],
    'confluence-admin': ['mssql-db'],
    'spring-svc': ['db-rds', 'nosql-doc'],
    'iot-hub': ['lake-ops', 'nosql-doc'],
    'ai-core': ['litellm-db'],
    'activemq': ['nosql-doc', 'redis-debian'],
    'cicd-runner': ['db-rds'],
    'sql-reporting': ['mssql-db'],
    'forti-ems': ['mssql-db'],
    'weblogic': ['db-rds']
  };

  const EXTERNAL_ENTRY_GROUPS = new Set([
    'ivanti-connect', 'pan-globalprotect', 'citrix-adc', 'f5-gateway',
    'forti-vpn', 'pulse-vpn', 'apache-edge', 'public-s3', 'public-blob',
    'public-gitlab', 'public-bitbucket'
  ]);

  const DEFENSE_SCENARIOS = {
    baseline: { tag: '01 / BASELINE', name: 'Baseline (Unmitigated)' },
    patch: { tag: '02 / VIRTUAL PATCH', name: 'Virtual Patch (WAF)' },
    defender: { tag: '03 / AGENTIC SOAR', name: 'Agentic SOAR' },
    combined: { tag: '04 / DEFENSE-IN-DEPTH', name: 'Combined Defense-in-Depth' }
  };

  function createRng(seed) {
    let a = (seed >>> 0) || 1;
    return function () {
      a |= 0;
      a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function hashNode(seed, id, salt) {
    let hash = ((salt >>> 0) ^ (seed >>> 0)) >>> 0;
    for (let i = 0; i < id.length; i++) {
      hash = Math.imul(hash ^ id.charCodeAt(i), 16777619);
    }
    hash ^= hash >>> 16; hash = Math.imul(hash, 0x7feb352d);
    hash ^= hash >>> 15; hash = Math.imul(hash, 0x846ca68b);
    hash ^= hash >>> 16;
    return (hash >>> 0) / 4294967296;
  }

  function soarDetects(assetId, seed) {
    return hashNode(seed, assetId, 2166136261) < SOAR_DETECTION_RATE;
  }

  function wafPortalCovered(assetId, seed) {
    return hashNode(seed, assetId, 0x9e3779b9) < WAF_PORTAL_COVERAGE;
  }

  function getTargetDef(groupId) {
    for (let l = 0; l < LAYER_CONFIG.length; l++) {
      for (const cluster of LAYER_CONFIG[l].clusters) {
        for (const t of cluster.targets) {
          if (t.id === groupId) return { def: t, layerIdx: l, clusterName: cluster.name };
        }
      }
    }
    return null;
  }

  function findKev(layerIdx, cveId) {
    if (!cveId) return null;
    return (LAYER_KEVS[layerIdx] || []).find(k => k.id === cveId) || null;
  }

  function inferConnectionProtocol(sourceAsset, targetAsset) {
    const tIfaces = targetAsset.interfaces || ['https'];
    if (tIfaces.includes('db-pg')) return 'db-pg';
    if (tIfaces.includes('db-mssql')) return 'db-mssql';
    if (tIfaces.includes('redis')) return 'redis';
    if (tIfaces.includes('amqp')) return 'amqp';
    if (tIfaces.includes('ad-rpc')) return 'ad-rpc';
    if (tIfaces.includes('storage-s3')) return 'storage-s3';
    if (tIfaces.includes('api-https')) return 'api-https';
    return 'https';
  }

  function inferTrustBoundary(sourceLayer, targetLayer) {
    if (sourceLayer === 0 && targetLayer === 1) return 'dmz-to-edge';
    if (sourceLayer === 1 && targetLayer === 2) return 'edge-to-mesh';
    if (sourceLayer === 2 && targetLayer === 3) return 'mesh-to-data';
    return 'same-zone';
  }

  function validateEstate(estate) {
    const errors = [];
    if (!estate || typeof estate !== 'object') {
      return { valid: false, errors: ['Estate must be an object'] };
    }
    if (estate.schemaVersion !== SCHEMA_VERSION) {
      errors.push(`Expected schemaVersion ${SCHEMA_VERSION}, got ${estate.schemaVersion}`);
    }
    if (!['mixed', 'demo', 'logs'].includes(estate.preset)) {
      errors.push(`Invalid preset: ${estate.preset}`);
    }
    if (!Array.isArray(estate.assets)) errors.push('assets must be an array');
    if (!Array.isArray(estate.findings)) errors.push('findings must be an array');
    if (!Array.isArray(estate.credentials)) errors.push('credentials must be an array');
    if (!Array.isArray(estate.relationships)) errors.push('relationships must be an array');
    if (errors.length) return { valid: false, errors };

    const assetIds = new Set();
    for (const a of estate.assets) {
      if (!a.id || assetIds.has(a.id)) errors.push(`Duplicate or missing asset id: ${a.id}`);
      assetIds.add(a.id);
      if (typeof a.layerIdx !== 'number' || a.layerIdx < 0 || a.layerIdx > 3) {
        errors.push(`Invalid layerIdx on asset ${a.id}`);
      }
      if (!Array.isArray(a.interfaces) || a.interfaces.length === 0) {
        errors.push(`Asset ${a.id} must declare interfaces`);
      }
    }

    const findingIds = new Set();
    for (const f of estate.findings) {
      if (!f.id || findingIds.has(f.id)) errors.push(`Duplicate or missing finding id: ${f.id}`);
      findingIds.add(f.id);
      if (!assetIds.has(f.assetId)) errors.push(`Finding ${f.id} references unknown asset ${f.assetId}`);
    }

    const credIds = new Set();
    for (const c of estate.credentials) {
      if (!c.id || credIds.has(c.id)) errors.push(`Duplicate or missing credential id: ${c.id}`);
      credIds.add(c.id);
      if (!assetIds.has(c.sourceAssetId)) errors.push(`Credential ${c.id} references unknown sourceAssetId ${c.sourceAssetId}`);
    }

    const relIds = new Set();
    for (const r of estate.relationships) {
      if (!r.id || relIds.has(r.id)) errors.push(`Duplicate or missing relationship id: ${r.id}`);
      relIds.add(r.id);
      if (!assetIds.has(r.sourceId)) errors.push(`Relationship ${r.id} references unknown sourceId ${r.sourceId}`);
      if (!assetIds.has(r.targetId)) errors.push(`Relationship ${r.id} references unknown targetId ${r.targetId}`);
      if (r.sourceId === r.targetId) errors.push(`Relationship ${r.id} is a self-loop`);
      if (r.direction !== 'outbound') errors.push(`Relationship ${r.id} has invalid direction ${r.direction}`);
    }

    return { valid: errors.length === 0, errors };
  }

  function cveTooltip(kev) {
    if (!kev) return '';
    return `${kev.id} · ${CVE_ATTACK_DESCRIPTIONS[kev.id] || kev.title}`;
  }

  /**
   * Evaluate all distinct eligible actions an attacker in `state` can perform on `targetAsset`
   * via `relationship` (or external entry). Never grants access without explicit reachability + prerequisites.
   */
  function evaluateDistinctActions(state, sourceAsset, targetAsset, relationship, estate, options = {}) {
    const targetFindings = estate.findings.filter(f => f.assetId === targetAsset.id);
    const actions = [];
    let lastReason = null;

    // 1. Reachability check
    let reachability = '';
    if (!sourceAsset) {
      if (!targetAsset.isExternalEntry) {
        return [{ eligible: false, reason: `${targetAsset.label} is not externally reachable.` }];
      }
      reachability = 'External internet ingress';
    } else {
      if (!relationship) {
        return [{ eligible: false, reason: `No directed relationship from ${sourceAsset.label} to ${targetAsset.label}.` }];
      }
      if (relationship.direction !== 'outbound') {
        return [{ eligible: false, reason: `Relationship direction (${relationship.direction}) does not permit access.` }];
      }
      if (relationship.sourceId !== sourceAsset.id || relationship.targetId !== targetAsset.id) {
        return [{ eligible: false, reason: 'Relationship endpoints do not match this action.' }];
      }
      const sourceState = state.reachedAssets.get(sourceAsset.id);
      if (!relationship.requiredSourceCapability || !sourceState?.capabilities.has(relationship.requiredSourceCapability)) {
        return [{ eligible: false, reason: 'Required source capability for this relationship is not established.' }];
      }
      if (!targetAsset.interfaces.includes(relationship.protocol)) {
        return [{ eligible: false, reason: `Protocol mismatch: route uses ${relationship.protocol}, target exposes [${targetAsset.interfaces.join(', ')}].` }];
      }
      reachability = `${sourceAsset.label} -> ${targetAsset.label} (${relationship.protocol})`;
    }

    // 2. Check findings on targetAsset independently
    for (const f of targetFindings) {
      if (f.kind === 'anonymous_access') {
        const action = {
          eligible: true,
          actionKind: 'anonymous_access',
          finding: f,
          credentialUsed: null,
          technique: f.technique || 'T1530',
          requiredAccess: 'Unauthenticated (anonymous access enabled)',
          reachability,
          yieldsCapability: f.yieldsCapability || 'data_read',
          exposesCredentialId: f.exposesCredentialId || null,
          reason: f.description || 'Anonymous access misconfiguration permits unauthenticated read.'
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }

      if (f.kind === 'cve') {
        // Product / version / interface / auth prerequisite checks
        if (!f.requiredProduct || !f.affectedVersions?.includes(targetAsset.assumedVersion) || !f.sourceUrl || !f.requiredConditions || !Object.entries(f.requiredConditions).every(([key, value]) => targetAsset.conditions?.[key] === value)) {
          lastReason = `Applicability or configuration for ${f.cveId} is not established.`;
          continue;
        }
        if (f.requiredProduct && f.requiredProduct !== targetAsset.product) {
          continue;
        }
        if (f.requiredInterface && !targetAsset.interfaces.includes(f.requiredInterface)) {
          continue;
        }
        if (relationship && f.requiredInterface !== relationship.protocol) continue;
        if (f.requiresAuth) {
          const matchingCred = diagnoseCredentialForTarget(state, targetAsset, f.requiredPermission || 'authenticate').credential;
          if (!matchingCred) {
            lastReason = `${f.cveId} requires an authorized credential for ${targetAsset.label}.`;
            continue;
          }
          const action = {
            eligible: true,
            actionKind: 'cve_authenticated',
            finding: f,
            credentialUsed: matchingCred,
            technique: f.technique || 'T1059',
            requiredAccess: `Authenticated (${matchingCred.label})`,
            reachability,
            yieldsCapability: f.yieldsCapability || 'app_exec',
            exposesCredentialId: f.exposesCredentialId || null,
            reason: `${f.cveId} exploited using acquired credential ${matchingCred.label}.`
          };
          if (options.firstOnly) return [action];
          actions.push(action);
          continue;
        }
        const action = {
          eligible: true,
          actionKind: 'cve',
          finding: f,
          credentialUsed: null,
          technique: f.technique || 'T1190',
          requiredAccess: 'Unauthenticated interface reachability',
          reachability,
          yieldsCapability: f.yieldsCapability || 'app_exec',
          exposesCredentialId: f.exposesCredentialId || null,
          reason: `${f.cveId} applicable to ${targetAsset.product} ${targetAsset.assumedVersion} over ${f.requiredInterface}.`
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }

      if (f.kind === 'password_spray') {
        if (f.syntheticAccountUsesSprayedPassword !== true) {
          lastReason = 'No matching synthetic account password is established.';
          continue;
        }
        if (f.mfaProtected) {
          lastReason = `Password spray on ${targetAsset.label} blocked by MFA enforcement.`;
          continue;
        }
        if (f.rateLimited) {
          lastReason = `Password spray on ${targetAsset.label} blocked by account lockout / rate limiting.`;
          continue;
        }
        const action = {
          eligible: true,
          actionKind: 'password_spray',
          finding: f,
          credentialUsed: null,
          technique: 'T1110.003',
          requiredAccess: 'Reachable authentication endpoint without MFA or lockout',
          reachability,
          yieldsCapability: 'account_session',
          exposesCredentialId: f.exposesCredentialId || null,
          reason: `Modeled password spray succeeded against synthetic account on ${targetAsset.label} (no MFA/lockout).`
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }
    }

    // 3. Check if attacker holds a valid, non-revoked, in-scope credential
    const credCheck = diagnoseCredentialForTarget(state, targetAsset, targetAsset.layerIdx === 3 ? 'read' : 'authenticate');
    if (credCheck.usable) {
      const action = {
        eligible: true,
        actionKind: 'valid_credential',
        finding: null,
        credentialUsed: credCheck.credential,
        technique: 'T1078',
        requiredAccess: `Acquired credential: ${credCheck.credential.label} (scope: ${credCheck.credential.scope})`,
        reachability,
        yieldsCapability: targetAsset.layerIdx === 3 ? 'data_read' : 'account_session',
        exposesCredentialId: null,
        reason: `Authenticated to ${targetAsset.label} using ${credCheck.credential.label} (no CVE needed).`
      };
      if (options.firstOnly) return [action];
      actions.push(action);
    }

    if (actions.length > 0) {
      return actions;
    }

    if (credCheck.reason) {
      return [{ eligible: false, reason: credCheck.reason }];
    }

    if (targetFindings.length > 0) {
      return [{
        eligible: false,
        finding: targetFindings[0],
        reason: lastReason || `Finding on ${targetAsset.label} did not match product/version/interface prerequisites.`
      }];
    }

    return [{
      eligible: false,
      reason: `No modeled access established for ${targetAsset.label}.`
    }];
  }

  /**
   * Evaluate whether an attacker in `state` can act on `targetAsset` via `relationship` (or external entry).
   * Never grants access without explicit reachability + satisfied prerequisites.
   */
  function evaluateAction(state, sourceAsset, targetAsset, relationship, estate) {
    return evaluateDistinctActions(state, sourceAsset, targetAsset, relationship, estate, { firstOnly: true })[0];
  }

  function diagnoseCredentialForTarget(state, targetAsset, permission = 'authenticate') {
    let rejectedReason = null;
    for (const cred of state.acquiredCredentials.values()) {
      const groupMatch = Array.isArray(cred.targetGroupIds) && cred.targetGroupIds.includes(targetAsset.groupId);
      const assetMatch = Array.isArray(cred.targetAssetIds) && cred.targetAssetIds.includes(targetAsset.id);
      if (Array.isArray(cred.targetAssetIds) && cred.targetAssetIds.length ? !assetMatch : !groupMatch) continue;
      if (state.revokedCredentials.has(cred.id) || cred.revoked) {
        rejectedReason = `Credential ${cred.label} for ${targetAsset.label} is revoked.`;
        continue;
      }
      if (cred.mfaRequired) {
        rejectedReason = `Credential ${cred.label} for ${targetAsset.label} requires MFA.`;
        continue;
      }
      if (cred.expired || (cred.audience && cred.audience !== targetAsset.id)) {
        rejectedReason = `Credential ${cred.label} is expired or has the wrong audience.`;
        continue;
      }
      const permissions = cred.permissions || (cred.scope ? [cred.scope] : []);
      if (!permissions.includes(permission)) {
        rejectedReason = `Credential ${cred.label} lacks ${permission} permission.`;
        continue;
      }
      return { usable: true, credential: cred };
    }
    return { usable: false, reason: rejectedReason };
  }

  function evaluateDefense(targetAsset, action, mode, seed, isCanary) {
    if (isCanary && mode === 'combined') {
      return {
        addressed: true,
        badge: 'BLOCKED · CANARY TRIGGER',
        control: 'NIST SI-4',
        reason: 'Access to the decoy generated an alert; the simulated SOAR playbook contained the attacker session.'
      };
    }
    if (mode === 'baseline') {
      return { addressed: false, badge: 'EXPLOITED', reason: 'Baseline scenario unmitigated: zero active defenses applied.' };
    }

    const isHttpSurface = (targetAsset.interfaces || []).some(i => ['https', 'api-https', 'repo-http', 'storage-s3'].includes(i));
    const nonHttpGroups = new Set(['aws-vpn', 'az-net', 'az-branch', 'partner-gw']);
    const isNonHttpProtocol = nonHttpGroups.has(targetAsset.groupId) || !isHttpSurface;
    const portalIds = new Set(['forti-vpn', 'pulse-vpn', 'pan-globalprotect']);
    const portalCovered = !portalIds.has(targetAsset.groupId) || wafPortalCovered(targetAsset.id, seed);

    if (action.actionKind === 'anonymous_access') {
      if ((mode === 'defender' || mode === 'combined') && soarDetects(targetAsset.id, seed)) {
        return { addressed: true, badge: 'CONTAINED · AGENTIC SOAR', control: 'NIST AC-3 / SI-4', reason: 'Simulation assumption: SOAR detects and closes the public exposure.' };
      }
      return { addressed: false, badge: 'PUBLIC EXPOSURE', reason: action.reason };
    }

    if (action.actionKind === 'valid_credential' || action.actionKind === 'password_spray') {
      if ((mode === 'defender' || mode === 'combined') && soarDetects(targetAsset.id, seed)) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOAR',
          control: 'NIST SI-4 / AC-3',
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: action.actionKind === 'password_spray'
            ? 'Simulation assumption: SOAR detects password-spray anomaly and locks the target account.'
            : 'Simulation assumption: SOAR detects anomalous credential use and revokes the token.'
        };
      }
      return {
        addressed: false,
        badge: action.actionKind === 'password_spray' ? 'T1110.003 · SPRAY' : 'T1078 · VALID ACCOUNTS',
        reason: action.reason
      };
    }

    // CVE action
    const cveId = action.finding && action.finding.cveId;
    const rule = KEV_MITIGATION_RULES[cveId] || {
      waf: { mitigates: false, reason: 'No specific virtual patch is modeled for this vulnerability.' },
      ml: { mitigates: false, reason: 'No specific detection and response is modeled for this vulnerability.' }
    };
    const wafMitigates = !isNonHttpProtocol && portalCovered && !!rule.waf?.mitigates;
    const soarMitigates = !!rule.ml?.mitigates && soarDetects(targetAsset.id, seed);

    if (mode === 'patch') {
      if (isNonHttpProtocol) {
        return { addressed: false, badge: 'WAF BLIND', reason: 'WAF operates at L7 HTTP; blind to non-HTTP protocols.' };
      }
      if (wafMitigates) {
        return { addressed: true, badge: 'SHIELDED · WAF VIRTUAL PATCH', control: rule.waf.control, reason: rule.waf.reason };
      }
      return {
        addressed: false,
        badge: 'WAF BYPASS',
        reason: !portalCovered ? 'Simulated public portal is not behind the inline WAF.' : (rule.waf?.reason || 'Vulnerability unaddressed by perimeter WAF.')
      };
    }

    if (mode === 'defender') {
      if (soarMitigates) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOAR',
          control: rule.ml.control,
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: rule.ml.reason
        };
      }
      return {
        addressed: false,
        badge: 'ML MISSED',
        reason: rule.ml?.mitigates ? 'Simulated SOAR detection missed this attack.' : (rule.ml?.reason || 'Activity does not trigger the simulated detection rule.')
      };
    }

    if (mode === 'combined') {
      if (wafMitigates) {
        return { addressed: true, badge: 'SHIELDED · WAF VIRTUAL PATCH', control: rule.waf.control, reason: rule.waf.reason };
      }
      if (soarMitigates) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOAR',
          control: rule.ml.control,
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: rule.ml.reason
        };
      }
      return { addressed: false, badge: 'UNADDRESSED', reason: 'The attack bypassed the simulated WAF rule and SOAR detection.' };
    }

    return { addressed: false, badge: 'EXPLOITED', reason: 'Unmitigated.' };
  }

  /**
   * Pure, deterministic, bounded graph traversal and action evaluator.
   */
  function simulateEstate(estate, mode = 'baseline') {
    const validation = validateEstate(estate);
    if (!validation.valid) {
      throw new Error(`Invalid estate: ${validation.errors.join('; ')}`);
    }

    const assetById = new Map(estate.assets.map(a => [a.id, a]));
    const orderRank = new Map((estate.actionOrder || []).map((id, idx) => [id, idx]));
    const rankOf = id => (orderRank.has(id) ? orderRank.get(id) : 999999);

    const canaryAsset = mode === 'combined'
      ? estate.assets
          .filter(a => a.layerIdx === 3 && estate.relationships.some(r => r.targetId === a.id))
          .sort((a, b) => a.id.localeCompare(b.id))[0] || null
      : null;

    const state = {
      reachedAssets: new Map(),
      acquiredCredentials: new Map(),
      revokedCredentials: new Set()
    };

    const visitedTransitions = new Set();
    const succeededPairs = new Set();
    const layerSuccessCount = [0, 0, 0, 0];
    const onwardSuccessCount = new Map();
    const events = [];

    let eligibleTransitions = 0;
    let attemptedTransitions = 0;
    let succeededTransitions = 0;
    let blockedTransitions = 0;
    let ineligibleTransitions = 0;
    let truncated = false;
    let dataReached = false;

    function processTransition(sourceAsset, targetAsset, relationship) {
      const transitionKey = `${sourceAsset ? sourceAsset.id : 'EXTERNAL'}->${targetAsset.id}:${relationship ? relationship.id : 'EXT'}`;
      if (visitedTransitions.has(transitionKey)) return;
      visitedTransitions.add(transitionKey);

      attemptedTransitions++;

      const isCanary = canaryAsset && canaryAsset.id === targetAsset.id;
      const candidates = evaluateDistinctActions(state, sourceAsset, targetAsset, relationship, estate);

      if (!candidates[0].eligible) {
        ineligibleTransitions++;
        events.push({
          sourceId: sourceAsset ? sourceAsset.id : null,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          finding: candidates[0].finding || null,
          outcome: 'ineligible',
          reason: candidates[0].reason
        });
        return;
      }

      const existingReach = state.reachedAssets.get(targetAsset.id);
      const distinctActions = existingReach
        ? candidates.filter(c => !existingReach.capabilities.has(c.yieldsCapability))
        : candidates;

      if (existingReach && distinctActions.length === 0) {
        events.push({
          sourceId: sourceAsset ? sourceAsset.id : null,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          outcome: 'revisit',
          reason: `${targetAsset.label} already reached with the same capability via an earlier path.`
        });
        return;
      }

      for (const action of distinctActions) {
        const currentReach = state.reachedAssets.get(targetAsset.id);
        if (currentReach && currentReach.capabilities.has(action.yieldsCapability)) {
          continue;
        }

        eligibleTransitions++;
        const mitigation = evaluateDefense(targetAsset, action, mode, estate.seed, isCanary);

        if (mitigation.addressed) {
          blockedTransitions++;
          if (mitigation.revokeCredentialId) {
            state.revokedCredentials.add(mitigation.revokeCredentialId);
          }
          events.push({
            sourceId: sourceAsset ? sourceAsset.id : null,
            targetId: targetAsset.id,
            relationshipId: relationship ? relationship.id : null,
            finding: action.finding,
            credentialUsed: action.credentialUsed,
            technique: action.technique,
            requiredAccess: action.requiredAccess,
            reachability: action.reachability,
            grantedCapability: null,
            acquiredCredentials: [],
            mitigation,
            outcome: 'blocked',
            reason: mitigation.reason
          });
          continue;
        }

        // Check demo-design budgets: count each source-target pair once and each reached asset once per layer
        const sourceId = sourceAsset ? sourceAsset.id : null;
        const alreadyReached = !!currentReach;
        const pairBudgetKey = `${sourceId || 'EXTERNAL'}->${targetAsset.id}`;
        const pairAlreadyCounted = succeededPairs.has(pairBudgetKey);
        const srcCount = sourceId ? (onwardSuccessCount.get(sourceId) || 0) : 0;
        const dataCap = mode === 'baseline' ? MAX_SUCCESS_PER_LAYER : 1;
        const layerCap = targetAsset.layerIdx === 3 ? dataCap : MAX_SUCCESS_PER_LAYER;

        if ((!pairAlreadyCounted && sourceId && srcCount >= MAX_ONWARD_PER_SOURCE) ||
            (!alreadyReached && layerSuccessCount[targetAsset.layerIdx] >= layerCap)) {
          truncated = true;
          events.push({
            sourceId,
            targetId: targetAsset.id,
            relationshipId: relationship ? relationship.id : null,
            finding: action.finding,
            credentialUsed: action.credentialUsed,
            technique: action.technique,
            requiredAccess: action.requiredAccess,
            reachability: action.reachability,
            grantedCapability: null,
            acquiredCredentials: [],
            mitigation,
            outcome: 'truncated',
            reason: `Demo display budget reached (max ${MAX_ONWARD_PER_SOURCE} onward/source, max ${layerCap} in layer ${targetAsset.layerIdx + 1}).`
          });
          continue;
        }

        // Grant capability and update state
        succeededTransitions++;
        if (!alreadyReached) layerSuccessCount[targetAsset.layerIdx]++;
        if (sourceId && !pairAlreadyCounted) onwardSuccessCount.set(sourceId, srcCount + 1);
        succeededPairs.add(pairBudgetKey);
        if (action.yieldsCapability === 'data_read') dataReached = true;

        let caps;
        if (currentReach) {
          currentReach.capabilities.add(action.yieldsCapability);
          caps = currentReach.capabilities;
        } else {
          caps = new Set([action.yieldsCapability]);
          state.reachedAssets.set(targetAsset.id, {
            layerIdx: targetAsset.layerIdx,
            sourceId,
            capabilities: caps,
            viaFindingId: action.finding ? action.finding.id : null,
            viaCredentialId: action.credentialUsed ? action.credentialUsed.id : null
          });
        }

        // Collect any synthetic credentials stored on targetAsset that are now accessible
        const newlyAcquired = [];
        for (const cred of estate.credentials) {
          if (cred.sourceAssetId !== targetAsset.id) continue;
          if (state.revokedCredentials.has(cred.id) || cred.revoked) continue;
          const capOk = !!cred.requiredSourceCapability && caps.has(cred.requiredSourceCapability);
          if (capOk && !state.acquiredCredentials.has(cred.id)) {
            state.acquiredCredentials.set(cred.id, cred);
            newlyAcquired.push(cred);
          }
        }

        events.push({
          sourceId,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          finding: action.finding,
          credentialUsed: action.credentialUsed,
          technique: action.technique,
          requiredAccess: action.requiredAccess,
          reachability: action.reachability,
          grantedCapability: action.yieldsCapability,
          acquiredCredentials: newlyAcquired,
          mitigation,
          outcome: 'succeeded',
          reason: action.reason
        });
      }
    }

    // Layer 0 external entries
    const entryAssets = estate.assets
      .filter(a => a.layerIdx === 0 && a.isExternalEntry)
      .sort((a, b) => rankOf(a.id) - rankOf(b.id));
    for (const entry of entryAssets) {
      processTransition(null, entry, null);
    }

    // Layer 1..3 progression from reached assets
    for (let layer = 0; layer < 3; layer++) {
      const reachedInLayer = [...state.reachedAssets.entries()]
        .filter(([, info]) => info.layerIdx === layer)
        .map(([id]) => assetById.get(id))
        .sort((a, b) => rankOf(a.id) - rankOf(b.id));

      for (const src of reachedInLayer) {
        const outRels = estate.relationships
          .filter(r => r.sourceId === src.id)
          .sort((a, b) => rankOf(a.targetId) - rankOf(b.targetId));
        for (const rel of outRels) {
          const tgt = assetById.get(rel.targetId);
          if (tgt) processTransition(src, tgt, rel);
        }
      }
    }

    const completeFourLayerPath = [...state.reachedAssets.entries()].some(([id, entry]) => {
      if (entry.layerIdx !== 3) return false;
      const layers = new Set();
      while (id && state.reachedAssets.has(id)) {
        const step = state.reachedAssets.get(id);
        layers.add(step.layerIdx);
        id = step.sourceId;
      }
      return [0, 1, 2, 3].every(layer => layers.has(layer));
    });

    return {
      mode,
      canaryAssetId: canaryAsset ? canaryAsset.id : null,
      events,
      summary: {
        layerSuccessCounts: layerSuccessCount,
        eligibleTransitions,
        attemptedTransitions,
        succeededTransitions,
        blockedTransitions,
        ineligibleTransitions,
        truncated,
        dataReached,
        completeFourLayerPath,
        preset: estate.preset,
        intentionalPathNote: estate.intentionalPathNote || null
      }
    };
  }

  function shuffleWithRng(arr, rng) {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }

  /**
   * Generates a versioned v3 estate.
   * - preset === 'mixed' (default): uses demo-design budgets per layer, allows 0 complete paths without resampling.
   * - preset === 'demo': intentionally constructs a verified 4-layer CVE path (plus an optional stopped branch) and labels it.
   * - preset === 'logs': intentionally constructs a 4-layer credential-in-logs path (plus a stopped expired/sibling branch) and labels it.
   */
  function generateEstate(options = {}) {
    const seed = Number.isInteger(options.seed) ? (options.seed >>> 0) : Math.floor(Math.random() * 4294967296);
    const preset = options.preset === 'demo'
      ? 'demo'
      : (options.preset === 'logs' || options.preset === 'credential-in-logs')
        ? 'logs'
        : 'mixed';
    const rng = createRng(seed);
    const rand = (min, max) => rng() * (max - min) + min;
    const randInt = (min, max) => Math.floor(rand(min, max + 1));

    const assets = [];
    LAYER_CONFIG.forEach((layer, layerIdx) => {
      const numClusters = layer.clusters.length;
      layer.clusters.forEach((cluster, clusterIdx) => {
        const numTargets = cluster.targets.length;
        cluster.targets.forEach((targetDef, targetIdx) => {
          if (targetDef.includeChance != null && rng() >= targetDef.includeChance) return;
          const maxVariants = targetDef.variants.length;
          const instanceCount = maxVariants > 1 ? randInt(1, Math.min(targetDef.maxInstances ?? 3, maxVariants)) : 1;
          const variants = targetDef.productPool
            ? shuffleWithRng(Array.from({ length: maxVariants }, (_, idx) => idx), rng).slice(0, instanceCount)
            : Array.from({ length: instanceCount }, (_, idx) => idx);

          for (let slot = 0; slot < instanceCount; slot++) {
            const vIdx = variants[slot];
            const label = targetDef.variants[vIdx];
            const familyAngle = (targetIdx / numTargets) * Math.PI * 2 - Math.PI / 2 + rand(-0.08, 0.08);
            const clusterCenterX = (layer.xBand[0] + (layer.xBand[1] - layer.xBand[0]) * 0.5) + rand(-0.02, 0.02);
            const clusterCenterY = (clusterIdx + 0.5) / numClusters + rand(-0.025, 0.025);
            const ox = instanceCount === 2 ? (slot === 0 ? -0.015 : 0.015) : instanceCount === 3 ? Math.cos((slot / 3) * Math.PI * 2) * 0.018 : 0;
            const oy = instanceCount === 2 ? (slot === 0 ? -0.02 : 0.02) : instanceCount === 3 ? Math.sin((slot / 3) * Math.PI * 2) * 0.022 : 0;
            const x = Math.max(0.04, Math.min(0.95, clusterCenterX + Math.cos(familyAngle) * 0.045 + ox));
            const y = Math.max(0.05, Math.min(0.95, clusterCenterY + Math.sin(familyAngle) * 0.065 + oy));

            assets.push({
              id: `${targetDef.id}-${vIdx + 1}`,
              groupId: targetDef.id,
              label,
              product: REVIEWED_EXAMPLES[targetDef.id]?.product || label,
              assumedVersion: REVIEWED_EXAMPLES[targetDef.id]?.version || null,
              conditions: { ...(REVIEWED_EXAMPLES[targetDef.id]?.conditions || {}) },
              layerIdx,
              trustZone: TRUST_ZONES[layerIdx],
              interfaces: [...(targetDef.interfaces || ['https'])],
              auth: targetDef.publicExposure ? 'none' : 'token',
              isExternalEntry: EXTERNAL_ENTRY_GROUPS.has(targetDef.id),
              isSecurity: !!targetDef.isSecurity,
              isLake: !!targetDef.isLake,
              isDb: !!targetDef.isDb,
              icon: targetDef.icon,
              clusterName: cluster.name,
              variantIdx: vIdx,
              x,
              y
            });
          }
        });
      });
    });

    // Wire directed relationships using ALLOWED_CONNECTIONS
    const relationships = [];
    const relKeys = new Set();
    const addRel = (src, tgt) => {
      const key = `${src.id}->${tgt.id}`;
      if (relKeys.has(key)) return;
      relKeys.add(key);
      relationships.push({
        id: `rel-${src.id}->${tgt.id}`,
        sourceId: src.id,
        targetId: tgt.id,
        protocol: inferConnectionProtocol(src, tgt),
        direction: 'outbound',
        requiredSourceCapability: src.groupId === 'public-gitlab' ? 'code_read' : 'app_exec',
        trustBoundary: inferTrustBoundary(src.layerIdx, tgt.layerIdx),
        purpose: `${src.groupId} to ${tgt.groupId} service flow`
      });
    };

    assets.forEach(source => {
      (ALLOWED_CONNECTIONS[source.groupId] || []).forEach(targetGroup => {
        const candidates = assets.filter(n => n.groupId === targetGroup && n.layerIdx === source.layerIdx + 1);
        if (!candidates.length) return;
        const target = candidates.reduce((a, b) => Math.abs(a.y - source.y) < Math.abs(b.y - source.y) ? a : b);
        addRel(source, target);
      });
    });

    assets.forEach(target => {
      if (relationships.some(r => r.targetId === target.id)) return;
      const candidates = assets.filter(n => n.layerIdx === target.layerIdx - 1 &&
        (ALLOWED_CONNECTIONS[n.groupId] || []).includes(target.groupId));
      if (!candidates.length) return;
      const source = candidates.reduce((a, b) => Math.abs(a.y - target.y) < Math.abs(b.y - target.y) ? a : b);
      addRel(source, target);
    });

    if (preset === 'demo') {
      const edge = assets.find(a => a.groupId === 'f5-gateway');
      const gateway = assets.find(a => a.groupId === 'cust-api');
      const app = assets.find(a => a.groupId === 'app-engine');
      const postgres = assets.find(a => a.groupId === 'db-rds' && a.label.includes('Postgres'));
      if (edge && gateway) addRel(edge, gateway);
      if (gateway && app) addRel(gateway, app);
      if (app && postgres) addRel(app, postgres);
    } else if (preset === 'logs') {
      const logBucket = assets.find(a => a.groupId === 'public-s3');
      const gateway = assets.find(a => a.groupId === 'cust-api');
      const siblingGw = assets.find(a => a.groupId === 'cust-api' && a.id !== gateway?.id);
      const app = assets.find(a => a.groupId === 'app-engine');
      const postgres = assets.find(a => a.groupId === 'db-rds' && a.label.includes('Postgres'));
      if (logBucket && gateway) {
        addRel(logBucket, gateway);
        const rel01 = relationships.find(r => r.sourceId === logBucket.id && r.targetId === gateway.id);
        if (rel01) {
          rel01.protocol = 'https';
          rel01.requiredSourceCapability = 'file_read';
          rel01.purpose = 'Assumed internet access to API gateway using synthetic service token recovered from exposed application logs';
        }
      }
      if (logBucket && siblingGw) {
        addRel(logBucket, siblingGw);
        const relSib = relationships.find(r => r.sourceId === logBucket.id && r.targetId === siblingGw.id);
        if (relSib) {
          relSib.protocol = 'https';
          relSib.requiredSourceCapability = 'file_read';
          relSib.purpose = 'Attempted reuse of log-exposed token against sibling API gateway';
        }
      }
      if (gateway && app) {
        addRel(gateway, app);
        const rel12 = relationships.find(r => r.sourceId === gateway.id && r.targetId === app.id);
        if (rel12) {
          rel12.requiredSourceCapability = 'account_session';
          rel12.purpose = 'Authenticated API gateway session calling internal application service';
        }
      }
      if (app && postgres) {
        addRel(app, postgres);
        const rel23 = relationships.find(r => r.sourceId === app.id && r.targetId === postgres.id);
        if (rel23) {
          rel23.requiredSourceCapability = 'account_session';
          rel23.purpose = 'Application service connection to customer database using scoped read credential';
        }
      }
    }

    // Retain only externally reachable assets
    const reachable = new Set(assets.filter(a => a.isExternalEntry).map(a => a.id));
    for (let l = 0; l < 4; l++) {
      relationships.forEach(r => { if (reachable.has(r.sourceId)) reachable.add(r.targetId); });
    }
    const keptAssets = assets.filter(a => reachable.has(a.id));
    const keptRels = relationships.filter(r => reachable.has(r.sourceId) && reachable.has(r.targetId));

    const findings = [];
    const credentials = [];

    const addCveFindingForAsset = (asset) => {
      const info = getTargetDef(asset.groupId);
      const reviewed = REVIEWED_EXAMPLES[asset.groupId];
      if (!reviewed) return false;
      const cveId = info && info.def.kevByVariant ? info.def.kevByVariant[asset.variantIdx] : null;
      if (!cveId || cveId !== reviewed.cve) return false;
      const kev = findKev(asset.layerIdx, cveId);
      if (!kev) return false;
      findings.push({
        id: `finding-${asset.id}-${cveId}`,
        assetId: asset.id,
        kind: 'cve',
        cveId,
        inKev: !!kev.inKev,
        provenance: 'synthetic_deployment_assumption',
        requiredProduct: reviewed.product,
        affectedVersions: [reviewed.version],
        requiredConditions: { ...reviewed.conditions },
        sourceUrl: reviewed.source,
        sourceReviewed: '2026-11-15',
        requiredInterface: kev.reqInterface || asset.interfaces[0],
        requiresAuth: !!kev.requiresAuth,
        technique: kev.tech || 'T1190',
        title: kev.title,
        description: CVE_ATTACK_DESCRIPTIONS[cveId] || kev.title,
        yieldsCapability: kev.yields || (asset.layerIdx === 3 ? 'data_read' : 'app_exec')
      });
      return true;
    };

    const addPublicFindingForAsset = (asset) => {
      const info = getTargetDef(asset.groupId);
      if (!info || !info.def.publicExposure) return false;
      findings.push({
        id: `finding-${asset.id}-public`,
        assetId: asset.id,
        kind: 'anonymous_access',
        inKev: false,
        provenance: 'synthetic_assumption',
        technique: info.def.attackTechnique || 'T1530',
        title: info.def.attackDescription || 'Anonymous public access',
        description: info.def.publicExposure,
        yieldsCapability: asset.groupId.includes('gitlab') || asset.groupId.includes('bitbucket') ? 'code_read' : 'data_read'
      });
      return true;
    };

    const assignCredentialOnSource = (srcAsset, targetAsset, scope = 'read') => {
      const credId = `cred-${srcAsset.id}-to-${targetAsset.id}`;
      if (credentials.some(c => c.id === credId)) return;
      credentials.push({
        id: credId,
        kind: targetAsset.layerIdx === 3 ? 'db_credential' : 'service_account',
        label: `Synthetic ${scope} credential for ${targetAsset.groupId}`,
        scope,
        targetGroupIds: [],
        targetAssetIds: [targetAsset.id],
        revoked: false,
        mfaRequired: false,
        sourceAssetId: srcAsset.id,
        requiredSourceCapability: 'app_exec'
      });
    };

    if (preset === 'demo') {
      // Intentionally construct one verified 4-layer path + an optional stopped branch
      const l0Candidates = keptAssets.filter(a => a.groupId === 'f5-gateway');
      let chosenChain = null;
      for (const a0 of l0Candidates) {
        const r01 = keptRels.filter(r => r.sourceId === a0.id);
        for (const rel1 of r01) {
          const a1 = keptAssets.find(a => a.id === rel1.targetId);
          if (!a1 || a1.groupId !== 'cust-api') continue;
          const r12 = keptRels.filter(r => r.sourceId === a1.id);
          for (const rel2 of r12) {
            const a2 = keptAssets.find(a => a.id === rel2.targetId);
            if (!a2 || a2.groupId !== 'app-engine') continue;
            const r23 = keptRels.filter(r => {
              const target = keptAssets.find(a => a.id === r.targetId);
              return r.sourceId === a2.id && target?.groupId === 'db-rds' && target.label.includes('Postgres');
            });
            if (r23.length) {
              const a3 = keptAssets.find(a => a.id === r23[0].targetId);
              if (a3) {
                chosenChain = [a0, a1, a2, a3];
                break;
              }
            }
          }
          if (chosenChain) break;
        }
        if (chosenChain) break;
      }

      if (!chosenChain) throw new Error('Unable to construct the reviewed demo topology.');
      if (chosenChain) {
        const [a0, a1, a2, a3] = chosenChain;
        if (!addCveFindingForAsset(a0)) addPublicFindingForAsset(a0);
        if (!addCveFindingForAsset(a1)) assignCredentialOnSource(a0, a1, 'exec');
        if (!addCveFindingForAsset(a2)) assignCredentialOnSource(a1, a2, 'exec');
        // Layer 3: either CVE or scoped credential from L2 (prefer credential to show realistic progression)
        assignCredentialOnSource(a2, a3, 'read');

        // Add one secondary branch that is blocked by MFA/healthy asset for contrast
        const sprayCandidate = keptAssets.find(a => a.layerIdx === 1 && a.id !== a1.id && getTargetDef(a.groupId)?.def.supportsSpray);
        if (sprayCandidate) {
          findings.push({
            id: `finding-${sprayCandidate.id}-spray-mfa`,
            assetId: sprayCandidate.id,
            kind: 'password_spray',
            inKev: false,
            provenance: 'synthetic_assumption',
            mfaProtected: true,
            syntheticAccountUsesSprayedPassword: true,
            rateLimited: false,
            technique: 'T1110.003',
            title: 'Password spray attempt (MFA enforced)',
            description: 'Modeled spray attempt against synthetic account; blocked by MFA.',
            yieldsCapability: 'account_session'
          });
        }
      }
    } else if (preset === 'logs') {
      // Dedicated credential-in-logs scenario: readable application logs -> synthetic service token ->
      // authenticated service access (no CVE needed) -> scoped DB credential -> data read.
      const a0 = keptAssets.find(a => a.groupId === 'public-s3');
      const a1 = keptAssets.find(a => a.groupId === 'cust-api');
      const a2 = keptAssets.find(a => a.groupId === 'app-engine');
      const a3 = keptAssets.find(a => a.groupId === 'db-rds' && a.label.includes('Postgres'));
      if (!a0 || !a1 || !a2 || !a3) {
        throw new Error('Unable to construct the credential-in-logs topology.');
      }

      findings.push({
        id: `finding-${a0.id}-logs`,
        assetId: a0.id,
        kind: 'anonymous_access',
        inKev: false,
        provenance: 'synthetic_assumption',
        technique: 'T1552.001',
        title: 'Readable application logs expose service token',
        description: 'Simulated log bucket is publicly readable and contains a synthetic unrevoked service token (no real secret).',
        yieldsCapability: 'file_read'
      });

      credentials.push({
        id: `cred-logs-${a0.id}-to-${a1.id}`,
        kind: 'api_token',
        label: 'Synthetic service token in application logs',
        scope: 'authenticate',
        permissions: ['authenticate'],
        targetGroupIds: [],
        targetAssetIds: [a1.id],
        audience: a1.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: a0.id,
        requiredSourceCapability: 'file_read'
      });

      // Expired sibling token in logs for contrast (must not authorize sibling gateway)
      const siblingGw = keptAssets.find(a => a.groupId === 'cust-api' && a.id !== a1.id);
      if (siblingGw) {
        credentials.push({
          id: `cred-logs-${a0.id}-to-${siblingGw.id}-expired`,
          kind: 'api_token',
          label: 'Synthetic expired token in application logs',
          scope: 'authenticate',
          permissions: ['authenticate'],
          targetGroupIds: [],
          targetAssetIds: [siblingGw.id],
          audience: siblingGw.id,
          revoked: false,
          expired: true,
          mfaRequired: false,
          sourceAssetId: a0.id,
          requiredSourceCapability: 'file_read'
        });
      }

      credentials.push({
        id: `cred-logs-${a1.id}-to-${a2.id}`,
        kind: 'service_account',
        label: 'Synthetic downstream service credential on API gateway',
        scope: 'authenticate',
        permissions: ['authenticate'],
        targetGroupIds: [],
        targetAssetIds: [a2.id],
        audience: a2.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: a1.id,
        requiredSourceCapability: 'account_session'
      });

      credentials.push({
        id: `cred-logs-${a2.id}-to-${a3.id}`,
        kind: 'db_credential',
        label: 'Synthetic read-only DB credential',
        scope: 'read',
        permissions: ['read'],
        targetGroupIds: [],
        targetAssetIds: [a3.id],
        audience: a3.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: a2.id,
        requiredSourceCapability: 'account_session'
      });
    } else {
      // Mixed-Estate (default): apply small demo-design budgets per layer, allow 0 complete paths
      for (let layerIdx = 0; layerIdx < 4; layerIdx++) {
        const budget = LAYER_FINDING_BUDGETS[layerIdx];
        const targetCount = randInt(budget.min, budget.max);
        const candidates = shuffleWithRng(keptAssets.filter(a => a.layerIdx === layerIdx), rng);
        let assigned = 0;

        for (const asset of candidates) {
          if (assigned >= targetCount) break;
          const info = getTargetDef(asset.groupId);
          if (info?.def.publicExposure) {
            if (addPublicFindingForAsset(asset)) assigned++;
          } else if (layerIdx === 1 && info?.def.supportsSpray && rng() < 0.35) {
            findings.push({
              id: `finding-${asset.id}-spray`,
              assetId: asset.id,
              kind: 'password_spray',
              inKev: false,
              provenance: 'synthetic_assumption',
              mfaProtected: rng() < 0.5,
              syntheticAccountUsesSprayedPassword: true,
              rateLimited: false,
              technique: 'T1110.003',
              title: 'Password spray exposure check',
              description: 'Synthetic authentication endpoint evaluated for password spray.',
              yieldsCapability: 'account_session'
            });
            assigned++;
          } else if (addCveFindingForAsset(asset)) {
            assigned++;
          } else if (layerIdx === 3) {
            // Healthy data store may have a scoped credential stored on an upstream L2 service
            const incoming = keptRels.filter(r => r.targetId === asset.id);
            if (incoming.length > 0 && rng() < 0.5) {
              const src = keptAssets.find(a => a.id === incoming[0].sourceId);
              if (src) {
                assignCredentialOnSource(src, asset, 'read');
                assigned++;
              }
            }
          }
        }
      }
      // Illustrative leak: a public repository contains one synthetic credential
      // for an assumed internet-reachable identity endpoint. No real secret exists.
      const repo = keptAssets.find(a => a.groupId === 'public-gitlab');
      const identityLink = repo && keptRels.find(r => r.sourceId === repo.id);
      const identity = identityLink && keptAssets.find(a => a.id === identityLink.targetId);
      if (repo && identity && rng() < 0.35) {
        if (!findings.some(f => f.assetId === repo.id)) addPublicFindingForAsset(repo);
        credentials.push({
          id: `cred-${repo.id}-to-${identity.id}`, kind: 'service_account',
          label: 'Synthetic repository-exposed identity credential', scope: 'authenticate',
          targetAssetIds: [identity.id], targetGroupIds: [], audience: identity.id,
          revoked: false, mfaRequired: false, sourceAssetId: repo.id, requiredSourceCapability: 'code_read'
        });
        identityLink.purpose = 'Assumed internet access to identity endpoint using credential exposed in public repository';
      }
    }

    const actionOrder = shuffleWithRng(keptAssets.map(a => a.id), rng);
    const estate = {
      schemaVersion: SCHEMA_VERSION,
      seed,
      preset,
      intentionalPathNote: preset === 'demo'
        ? 'DEMO-READY · INTENTIONAL 4-LAYER PATH'
        : preset === 'logs'
          ? 'CREDENTIAL-IN-LOGS · INTENTIONAL 4-LAYER PATH'
          : null,
      assets: keptAssets,
      findings,
      credentials,
      relationships: keptRels,
      actionOrder
    };

    const validation = validateEstate(estate);
    if (!validation.valid) {
      throw new Error(`Generated invalid estate: ${validation.errors.join('; ')}`);
    }
    return estate;
  }

  function migrateSnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== 'object') {
      return { ok: false, reason: 'No snapshot provided.' };
    }
    if (snapshot.schemaVersion === SCHEMA_VERSION) {
      const validation = validateEstate(snapshot);
      return validation.valid ? { ok: true, estate: snapshot } : { ok: false, reason: validation.errors.join('; ') };
    }
    return {
      ok: false,
      legacy: true,
      reason: 'Incompatible infrastructure snapshot replaced with a new synthetic estate.'
    };
  }

  return {
    SCHEMA_VERSION,
    MAX_ONWARD_PER_SOURCE,
    MAX_SUCCESS_PER_LAYER,
    LAYER_FINDING_BUDGETS,
    CVE_ATTACK_DESCRIPTIONS,
    LAYER_KEVS,
    KEV_MITIGATION_RULES,
    LAYER_CONFIG,
    ALLOWED_CONNECTIONS,
    EXTERNAL_ENTRY_GROUPS,
    DEFENSE_SCENARIOS,
    createRng,
    cveTooltip,
    validateEstate,
    evaluateAction,
    evaluateDistinctActions,
    evaluateDefense,
    simulateEstate,
    generateEstate,
    migrateSnapshot
  };
}));
