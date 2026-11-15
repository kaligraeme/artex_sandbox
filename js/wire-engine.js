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

  // Equal demo coverage across seeds; public incident reports do not establish rates for these categories.
  const MIXED_DIAGNOSTIC_OPENINGS = [
    {
      openingType: 'low_exposure',
      title: 'Low exposure',
      requiredCondition: 'unredactedSupportCapture',
      description: 'An approved support capture retains a synthetic staging status credential visible to the signed-in diagnostics viewer.'
    },
    {
      openingType: 'misconfiguration',
      title: 'Misconfiguration',
      requiredCondition: 'overbroadDiagnosticsSharing',
      description: 'An overly broad sharing policy lets the signed-in diagnostics viewer see a restricted staging build log containing a synthetic status credential.'
    },
    {
      openingType: 'low_vulnerability',
      title: 'Low vulnerability',
      requiredCondition: 'limitedDiagnosticReadDefect',
      description: 'A modeled, read-only defect exposes a synthetic staging status credential to the signed-in diagnostics viewer.'
    }
  ];

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
            { id: 'apache-edge', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2021-42013'], variants: ['Apache HTTP Server 2.4.50 Edge'] },
            { id: 'support-diagnostics', preset: 'mixed', icon: 'configuration.png', interfaces: ['https'], variants: ['Support Diagnostics Portal'] }
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
            { id: 'exchange', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2021-26855'], variants: ['Microsoft Exchange Server'] },
            { id: 'staging-status', preset: 'mixed', icon: 'api.png', interfaces: ['api-https'], variants: ['Staging Status API'] }
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
    'support-diagnostics': ['staging-status'],
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
    'public-gitlab', 'public-bitbucket', 'support-diagnostics'
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
    if (!['mixed', 'demo', 'logs', 'comparison'].includes(estate.preset)) {
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
      if (f.kind === 'diagnostic_access') {
        const diagnosticLogin = diagnoseCredentialForTarget(state, targetAsset, 'read_diagnostics');
        if (!diagnosticLogin.usable) {
          return [{ eligible: false, finding: f, reason: 'Reading diagnostics requires an authorized diagnostics viewer.' }];
        }
        if (targetAsset.conditions?.[f.requiredCondition] !== true) {
          return [{ eligible: false, finding: f, reason: 'The modeled diagnostic exposure is absent.' }];
        }
        const action = {
          eligible: true,
          actionKind: 'diagnostic_access',
          finding: f,
          credentialUsed: diagnosticLogin.credential,
          requiredAccess: 'Signed-in diagnostics viewer',
          reachability,
          yieldsCapability: 'diagnostic_read',
          reason: f.description
        };
        if (options.firstOnly) return [action];
        actions.push(action);
        continue;
      }
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
        reason: targetAsset.groupId === 'staging-status'
          ? 'Staging status access established. Production access requires a separate authorization.'
          : `Authenticated to ${targetAsset.label} using ${credCheck.credential.label} (no CVE needed).`
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
    if (action.actionKind === 'diagnostic_access') {
      return { addressed: false, badge: 'SCOPED CREDENTIAL EXPOSED', reason: action.reason };
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
      acquiredCredentials: new Map(estate.credentials.filter(cred => cred.startingAccess).map(cred => [cred.id, cred])),
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
        const targets = cluster.targets.filter(target => !target.preset || target.preset === preset);
        const numTargets = targets.length;
        targets.forEach((targetDef, targetIdx) => {
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

    const diagnostics = assets.find(a => a.groupId === 'support-diagnostics');
    const statusApi = assets.find(a => a.groupId === 'staging-status');
    if (diagnostics) {
      const statusRoute = relationships.find(r => r.sourceId === diagnostics.id);
      statusRoute.requiredSourceCapability = 'diagnostic_read';
      statusRoute.purpose = 'Staging status access with a viewer credential';
    }

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
      const opening = MIXED_DIAGNOSTIC_OPENINGS[seed % MIXED_DIAGNOSTIC_OPENINGS.length];
      diagnostics.conditions[opening.requiredCondition] = true;
      findings.push({
        id: `finding-${diagnostics.id}`,
        assetId: diagnostics.id,
        kind: 'diagnostic_access',
        inKev: false,
        provenance: 'synthetic_assumption',
        ...opening
      });
      credentials.push({
        id: 'mixed-diagnostics-viewer',
        kind: 'service_account',
        label: 'Synthetic diagnostics viewer',
        scope: 'read diagnostics',
        permissions: ['read_diagnostics'],
        targetAssetIds: [diagnostics.id],
        audience: diagnostics.id,
        sourceAssetId: diagnostics.id,
        startingAccess: true
      }, {
        id: 'mixed-staging-status',
        kind: 'api_token',
        label: 'Synthetic staging status credential',
        scope: 'staging status only',
        permissions: ['authenticate'],
        targetAssetIds: [statusApi.id],
        audience: statusApi.id,
        sourceAssetId: diagnostics.id,
        requiredSourceCapability: 'diagnostic_read'
      });

      // The diagnostic finding consumes one of the mixed estate's ingress slots.
      for (let layerIdx = 0; layerIdx < 4; layerIdx++) {
        const budget = LAYER_FINDING_BUDGETS[layerIdx];
        const targetCount = randInt(budget.min, budget.max);
        const candidates = shuffleWithRng(keptAssets.filter(a => a.layerIdx === layerIdx), rng);
        let assigned = layerIdx === 0 ? 1 : 0;

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
    }

    const actionOrder = shuffleWithRng(keptAssets.map(a => a.id), rng);
    if (diagnostics) {
      actionOrder.splice(actionOrder.indexOf(diagnostics.id), 1);
      actionOrder.unshift(diagnostics.id);
    }
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
      if (!validation.valid) return { ok: false, reason: validation.errors.join('; ') };
      if (snapshot.preset === 'mixed' && Number.isInteger(snapshot.seed) &&
          !snapshot.findings.some(finding => finding.kind === 'diagnostic_access' && finding.openingType)) {
        return { ok: true, estate: generateEstate({ seed: snapshot.seed, preset: 'mixed' }) };
      }
      return { ok: true, estate: snapshot };
    }
    return {
      ok: false,
      legacy: true,
      reason: 'Incompatible infrastructure snapshot replaced with a new synthetic estate.'
    };
  }

  // ---------------------------------------------------------------------------
  // Fixed Comparison Mode: Pre-2023 Human-Led vs ARTEX & Friends
  // ---------------------------------------------------------------------------
  const COMPARISON_PROFILES = {
    pre2023: {
      id: 'pre2023',
      label: 'Pre-2023 human-led',
      shortLabel: 'PRE-2023',
      description: 'Human-led operations using scripts, automation, valid credentials, and operator handoffs.'
    },
    artex: {
      id: 'artex',
      label: 'ARTEX & Friends',
      shortLabel: 'ARTEX',
      description: 'Agentic operations with faster pace, concurrent opportunity review, and context-dependent continuation.'
    }
  };

  const COMPARISON_DEFENSES = {
    baseline: { id: 'baseline', label: 'Baseline', shortLabel: 'BASELINE' },
    patch: { id: 'patch', label: 'Virtual Patching', shortLabel: 'VIRTUAL PATCH' },
    soc: { id: 'soc', label: 'Agentic SOC', shortLabel: 'AGENTIC SOC' },
    canaries: { id: 'canaries', label: 'Canaries', shortLabel: 'CANARIES' },
    combined: { id: 'combined', label: 'Combined (SOC + Canary)', shortLabel: 'COMBINED' }
  };

  function createComparisonEstate() {
    const estate = {
      schemaVersion: SCHEMA_VERSION,
      seed: 20261115,
      preset: 'comparison',
      intentionalPathNote: 'FIXED COMPARISON ESTATE: identical four-layer estate, exposures, access rules, and protected record across all comparison runs.',
      assets: [
        {
          id: 'cmp-edge',
          groupId: 'f5-gateway',
          label: 'Ingress Gateway',
          product: 'F5 BIG-IP',
          assumedVersion: '16.1.0',
          layerIdx: 0,
          trustZone: 'internet-dmz',
          interfaces: ['https'],
          auth: 'token',
          isExternalEntry: true,
          x: 0.14,
          y: 0.48
        },
        {
          id: 'cmp-api',
          groupId: 'cust-api',
          label: 'API Boundary',
          product: 'WSO2 API Manager',
          assumedVersion: '3.2.0',
          layerIdx: 1,
          trustZone: 'identity-edge',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.38,
          y: 0.34
        },
        {
          id: 'cmp-gw2',
          groupId: 'wso2-api',
          label: 'Service Gateway',
          product: 'WSO2 Gateway',
          assumedVersion: '3.2.0',
          layerIdx: 1,
          trustZone: 'identity-edge',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.38,
          y: 0.68
        },
        {
          id: 'cmp-app',
          groupId: 'app-engine',
          label: 'Core App Service',
          product: 'Spring Framework',
          assumedVersion: '5.3.17',
          layerIdx: 2,
          trustZone: 'internal-mesh',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.63,
          y: 0.34
        },
        {
          id: 'cmp-svc',
          groupId: 'spring-svc',
          label: 'Workflow Service',
          product: 'Order Workflow',
          assumedVersion: '5.3.17',
          layerIdx: 2,
          trustZone: 'internal-mesh',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          x: 0.63,
          y: 0.68
        },
        {
          id: 'cmp-data',
          groupId: 'db-rds',
          label: 'Sensitive Record Store',
          product: 'PostgreSQL RDS',
          assumedVersion: '14.9',
          layerIdx: 3,
          trustZone: 'data-tier',
          interfaces: ['db-pg'],
          auth: 'db_credential',
          isExternalEntry: false,
          isProtectedRecord: true,
          x: 0.86,
          y: 0.34
        },
        {
          id: 'cmp-decoy',
          groupId: 'nosql-doc',
          label: 'Canary Decoy Asset',
          product: 'Decoy Document Store',
          assumedVersion: '1.0',
          layerIdx: 3,
          trustZone: 'data-tier',
          interfaces: ['api-https', 'https'],
          auth: 'token',
          isExternalEntry: false,
          isDecoyAsset: true,
          x: 0.86,
          y: 0.68
        }
      ],
      findings: [
        {
          id: 'cmp-f-edge',
          assetId: 'cmp-edge',
          kind: 'cve',
          cveId: 'CVE-2022-1388',
          requiredProduct: 'F5 BIG-IP',
          affectedVersions: ['16.1.0'],
          requiredConditions: { managementReachable: true },
          sourceUrl: 'https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf',
          sourceReviewed: true,
          requiredInterface: 'https',
          yieldsCapability: 'app_exec'
        },
        {
          id: 'cmp-f-api',
          assetId: 'cmp-api',
          kind: 'cve',
          cveId: 'CVE-2022-29464',
          requiredProduct: 'WSO2 API Manager',
          affectedVersions: ['3.2.0'],
          requiredConditions: { uploadEndpointReachable: true, executableUpload: true },
          sourceUrl: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf',
          sourceReviewed: true,
          requiredInterface: 'api-https',
          yieldsCapability: 'app_exec'
        },
        {
          id: 'cmp-f-app',
          assetId: 'cmp-app',
          kind: 'cve',
          cveId: 'CVE-2022-22965',
          requiredProduct: 'Spring Framework',
          affectedVersions: ['5.3.17'],
          requiredConditions: { jdk9Plus: true, tomcatVulnerable: true, warDeployment: true, mvcDataBinding: true },
          sourceUrl: 'https://spring.io/security/cve-2022-22965/',
          sourceReviewed: true,
          requiredInterface: 'api-https',
          yieldsCapability: 'app_exec'
        }
      ],
      credentials: [
        {
          id: 'cmp-cred-db',
          kind: 'db_credential',
          label: 'app-db-read',
          scope: 'read',
          targetGroupIds: ['db-rds'],
          targetAssetIds: ['cmp-data'],
          revoked: false,
          expired: false,
          mfaRequired: false,
          sourceAssetId: 'cmp-app',
          requiredSourceCapability: 'app_exec'
        }
      ],
      relationships: [
        { id: 'cmp-r-edge-api', sourceId: 'cmp-edge', targetId: 'cmp-api', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
        { id: 'cmp-r-edge-gw2', sourceId: 'cmp-edge', targetId: 'cmp-gw2', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
        { id: 'cmp-r-api-app', sourceId: 'cmp-api', targetId: 'cmp-app', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
        { id: 'cmp-r-api-svc', sourceId: 'cmp-api', targetId: 'cmp-svc', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
        { id: 'cmp-r-app-data', sourceId: 'cmp-app', targetId: 'cmp-data', protocol: 'db-pg', direction: 'outbound', requiredSourceCapability: 'app_exec' },
        { id: 'cmp-r-svc-decoy', sourceId: 'cmp-svc', targetId: 'cmp-decoy', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' }
      ],
      actionOrder: ['cmp-edge', 'cmp-api', 'cmp-gw2', 'cmp-app', 'cmp-svc', 'cmp-data', 'cmp-decoy']
    };
    estate.assets.forEach(a => {
      const td = getTargetDef(a.groupId);
      a.icon = td?.def?.icon || 'application.png';
    });
    return estate;
  }

  function formatDurationSeconds(totalSeconds) {
    if (totalSeconds === null || totalSeconds === undefined || Number.isNaN(totalSeconds)) return 'N/A';
    const secs = Math.max(0, Math.round(totalSeconds));
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }

  function formatSignedDelta(deltaSeconds) {
    if (deltaSeconds === null || deltaSeconds === undefined || Number.isNaN(deltaSeconds)) return 'Unavailable';
    const sign = deltaSeconds > 0 ? '+' : deltaSeconds < 0 ? '−' : '';
    const abs = Math.abs(Math.round(deltaSeconds));
    if (abs >= 60 && abs % 60 === 0) {
      return `${sign}${abs / 60} min`;
    }
    if (abs >= 120) {
      const mins = Math.floor(abs / 60);
      const rem = abs % 60;
      return rem === 0 ? `${sign}${mins} min` : `${sign}${mins}m ${rem}s`;
    }
    return `${sign}${abs} s`;
  }

  function buildSpeedEvents({
    ingressTime = 0,
    decoyTime = 600,
    boundaryTime = 5400,
    lateralTime = 6300,
    protectedReadTime = 7200,
    patchCovered = false,
    socDetectable = true,
    includeDecoy = true,
    decoyPlacement = 'early',
    includeSecondaryBranch = false
  }) {
    const events = [
      {
        id: 'ev-ingress',
        timeSec: ingressTime,
        layerIdx: 0,
        assetId: 'cmp-edge',
        relationshipId: null,
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'ingress',
        title: 'Ingress edge request',
        detail: patchCovered
          ? 'Edge request matches active virtual patch rule VP-EDGE-01.'
          : 'Edge request uses an unpatched path outside virtual patch rule coverage.',
        ruleCoverage: patchCovered
          ? { covered: true, ruleId: 'VP-EDGE-01', label: 'Active ingress virtual patch' }
          : { covered: false, label: 'Outside virtual patch rule coverage' },
        telemetry: { detectable: false },
        isDecoy: false,
        decoyPlacement: null,
        isBoundaryCrossing: false,
        isProtectedRead: false
      }
    ];

    if (includeDecoy && decoyPlacement === 'early') {
      events.push({
        id: 'ev-decoy',
        timeSec: decoyTime,
        layerIdx: 3,
        assetId: 'cmp-decoy',
        relationshipId: 'cmp-r-svc-decoy',
        prerequisiteIds: ['ev-ingress'],
        identityId: 'sess-primary',
        kind: 'decoy',
        title: 'Early canary decoy interaction',
        detail: 'Session touches instrumented canary decoy, identifying sess-primary.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Canary decoy signal (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: true,
        decoyPlacement: 'early',
        isBoundaryCrossing: false,
        isProtectedRead: false
      });
    }

    events.push({
      id: 'ev-boundary',
      timeSec: boundaryTime,
      layerIdx: 1,
      assetId: 'cmp-api',
      relationshipId: 'cmp-r-edge-api',
      prerequisiteIds: ['ev-ingress'],
      identityId: 'sess-primary',
      kind: 'boundary',
      title: 'First boundary crossing',
      detail: 'Cross-boundary session reaches internal API tier.',
      ruleCoverage: { covered: false },
      telemetry: socDetectable
        ? { detectable: true, signalLabel: 'Boundary crossing telemetry (sess-primary)', containableIdentity: 'sess-primary' }
        : { detectable: false, signalLabel: 'No matching SOC telemetry' },
      isDecoy: false,
      decoyPlacement: null,
      isBoundaryCrossing: true,
      isProtectedRead: false
    });

    events.push({
      id: 'ev-lateral',
      timeSec: lateralTime,
      layerIdx: 2,
      assetId: 'cmp-app',
      relationshipId: 'cmp-r-api-app',
      prerequisiteIds: ['ev-boundary'],
      identityId: 'sess-primary',
      kind: 'lateral',
      title: 'Internal service pivot',
      detail: 'Workflow pivots into core application service.',
      ruleCoverage: { covered: false },
      telemetry: { detectable: false },
      isDecoy: false,
      decoyPlacement: null,
      isBoundaryCrossing: false,
      isProtectedRead: false
    });

    events.push({
      id: 'ev-protected-read',
      timeSec: protectedReadTime,
      layerIdx: 3,
      assetId: 'cmp-data',
      relationshipId: 'cmp-r-app-data',
      prerequisiteIds: ['ev-lateral'],
      identityId: 'sess-primary',
      kind: 'protected_read',
      title: 'Protected record read',
      detail: 'First unauthorized read of the designated sensitive record.',
      ruleCoverage: { covered: false },
      telemetry: { detectable: false },
      isDecoy: false,
      decoyPlacement: null,
      isBoundaryCrossing: false,
      isProtectedRead: true
    });

    if (includeDecoy && decoyPlacement === 'late') {
      events.push({
        id: 'ev-decoy',
        timeSec: decoyTime,
        layerIdx: 3,
        assetId: 'cmp-decoy',
        relationshipId: 'cmp-r-svc-decoy',
        prerequisiteIds: ['ev-boundary'],
        identityId: 'sess-primary',
        kind: 'decoy',
        title: 'Late canary decoy interaction',
        detail: 'Session touches backend decoy after sensitive record access.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Late canary decoy signal (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: true,
        decoyPlacement: 'late',
        isBoundaryCrossing: false,
        isProtectedRead: false
      });
    }

    if (includeSecondaryBranch) {
      events.push({
        id: 'ev-unrelated',
        timeSec: lateralTime + 15,
        layerIdx: 2,
        assetId: 'cmp-svc',
        relationshipId: 'cmp-r-api-svc',
        prerequisiteIds: [],
        identityId: 'sess-secondary',
        kind: 'lateral',
        title: 'Independent secondary session activity',
        detail: 'Unrelated identity sess-secondary continues outside sess-primary containment scope.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        decoyPlacement: null,
        isBoundaryCrossing: false,
        isProtectedRead: false
      });
    }

    events.sort((a, b) => a.timeSec - b.timeSec);
    return events;
  }

  function buildCapabilityEvents(profileId, accessDenied) {
    if (profileId === 'pre2023') {
      return [
        {
          id: 'cap-opp-1',
          timeSec: 15,
          layerIdx: 1,
          assetId: 'cmp-api',
          relationshipId: 'cmp-r-edge-api',
          prerequisiteIds: [],
          identityId: 'sess-primary',
          kind: 'opportunity_review',
          opportunityId: 'opp-1',
          concurrentGroup: null,
          requiresHumanReview: true,
          handoffDurationSec: 45,
          title: 'Opportunity 1 reviewed (scripted check)',
          detail: 'Operator runs scripted check on Opportunity 1 (15 s) and hits context-dependent decision point.',
          ruleCoverage: { covered: false },
          telemetry: { detectable: true, signalLabel: 'Scripted check telemetry (sess-primary)', containableIdentity: 'sess-primary' },
          isDecoy: false,
          isBoundaryCrossing: true,
          isProtectedRead: false
        },
        {
          id: 'cap-handoff-1',
          timeSec: 60,
          layerIdx: 2,
          assetId: 'cmp-app',
          relationshipId: 'cmp-r-api-app',
          prerequisiteIds: ['cap-opp-1'],
          identityId: 'sess-primary',
          kind: 'human_handoff',
          opportunityId: 'opp-1',
          concurrentGroup: null,
          requiresHumanReview: true,
          handoffDurationSec: 45,
          title: 'Human operator handoff (45 s)',
          detail: 'Awaits human review for context-dependent decision (15 s -> 60 s, exceeds 45 s cutoff).',
          ruleCoverage: { covered: false },
          telemetry: { detectable: false },
          isDecoy: false,
          isBoundaryCrossing: false,
          isProtectedRead: false
        },
        {
          id: 'cap-opp-2',
          timeSec: 75,
          layerIdx: 2,
          assetId: 'cmp-svc',
          relationshipId: 'cmp-r-api-svc',
          prerequisiteIds: ['cap-handoff-1'],
          identityId: 'sess-primary',
          kind: 'opportunity_review',
          opportunityId: 'opp-2',
          concurrentGroup: null,
          requiresHumanReview: false,
          handoffDurationSec: null,
          title: 'Opportunity 2 reviewed',
          detail: 'Available only after first human handoff completes.',
          ruleCoverage: { covered: false },
          telemetry: { detectable: false },
          isDecoy: false,
          isBoundaryCrossing: false,
          isProtectedRead: false
        },
        {
          id: 'cap-read',
          timeSec: 75,
          layerIdx: 3,
          assetId: 'cmp-data',
          relationshipId: 'cmp-r-app-data',
          prerequisiteIds: ['cap-opp-2'],
          identityId: 'sess-primary',
          kind: 'protected_read',
          opportunityId: 'opp-2',
          concurrentGroup: null,
          requiresHumanReview: false,
          handoffDurationSec: null,
          accessDenied,
          title: accessDenied ? 'Protected record access denied' : 'Protected record read',
          detail: accessDenied ? 'Shared access rules deny read of sensitive record.' : 'Protected read on Opportunity 2.',
          ruleCoverage: { covered: false },
          telemetry: { detectable: false },
          isDecoy: false,
          isBoundaryCrossing: false,
          isProtectedRead: true
        }
      ];
    }

    // ARTEX agentic capability trace
    return [
      {
        id: 'cap-opp-1',
        timeSec: 15,
        layerIdx: 1,
        assetId: 'cmp-api',
        relationshipId: 'cmp-r-edge-api',
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'opportunity_review',
        opportunityId: 'opp-1',
        concurrentGroup: 'batch-0',
        requiresHumanReview: true,
        handoffDurationSec: 45,
        title: 'Opportunity 1 reviewed concurrently',
        detail: 'Reviewed in parallel (0-15 s); requires 45 s human review before continuing.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        isBoundaryCrossing: false,
        isProtectedRead: false
      },
      {
        id: 'cap-opp-2',
        timeSec: 15,
        layerIdx: 1,
        assetId: 'cmp-gw2',
        relationshipId: 'cmp-r-edge-gw2',
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'opportunity_review',
        opportunityId: 'opp-2',
        concurrentGroup: 'batch-0',
        requiresHumanReview: false,
        handoffDurationSec: null,
        title: 'Opportunity 2 reviewed concurrently',
        detail: 'Context-dependent continuation proceeds without human gate (0-15 s).',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Concurrent opportunity telemetry (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: false,
        isBoundaryCrossing: true,
        isProtectedRead: false
      },
      {
        id: 'cap-opp-3',
        timeSec: 15,
        layerIdx: 2,
        assetId: 'cmp-svc',
        relationshipId: 'cmp-r-api-svc',
        prerequisiteIds: [],
        identityId: 'sess-primary',
        kind: 'opportunity_review',
        opportunityId: 'opp-3',
        concurrentGroup: 'batch-0',
        requiresHumanReview: false,
        handoffDurationSec: null,
        title: 'Opportunity 3 reviewed concurrently (decoy-adjacent)',
        detail: 'Reviewed in parallel (0-15 s); touches instrumented decoy marker.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: true, signalLabel: 'Canary decoy signal (sess-primary)', containableIdentity: 'sess-primary' },
        isDecoy: true,
        decoyPlacement: 'early',
        isBoundaryCrossing: false,
        isProtectedRead: false
      },
      {
        id: 'cap-read',
        timeSec: 30,
        layerIdx: 3,
        assetId: 'cmp-data',
        relationshipId: 'cmp-r-app-data',
        prerequisiteIds: ['cap-opp-2'],
        identityId: 'sess-primary',
        kind: 'protected_read',
        opportunityId: 'opp-2',
        concurrentGroup: null,
        requiresHumanReview: false,
        handoffDurationSec: null,
        accessDenied,
        title: accessDenied ? 'Protected record access denied' : 'Protected record read (30 s)',
        detail: accessDenied
          ? 'Shared access rules deny read of designated sensitive record at 30 s.'
          : 'Context-dependent continuation on Opportunity 2 completes protected read at 30 s.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        isBoundaryCrossing: false,
        isProtectedRead: true
      },
      {
        id: 'cap-handoff-1',
        timeSec: 60,
        layerIdx: 2,
        assetId: 'cmp-app',
        relationshipId: 'cmp-r-api-app',
        prerequisiteIds: ['cap-opp-1'],
        identityId: 'sess-primary',
        kind: 'human_handoff',
        opportunityId: 'opp-1',
        concurrentGroup: null,
        requiresHumanReview: true,
        handoffDurationSec: 45,
        title: 'Human review on Opportunity 1 completes (60 s)',
        detail: 'Still awaiting human review at the 45 s cutoff.',
        ruleCoverage: { covered: false },
        telemetry: { detectable: false },
        isDecoy: false,
        isBoundaryCrossing: false,
        isProtectedRead: false
      }
    ];
  }

  const COMPARISON_FIXTURES = {
    'speed-race': {
      id: 'speed-race',
      kind: 'speed',
      title: 'Speed: Timing Race (Out-of-Scope Patch)',
      subtitle: 'Identical ordered attacker activity retimestamped at Pre-2023 vs ARTEX pace. Same 60 s SOC containment wins at Pre-2023 pace and loses at ARTEX pace.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: [
        'Virtual patch has no matching rule for the ingress path (OUTSIDE RULE COVERAGE).',
        'Regular SOC signal occurs at the first boundary crossing; containment takes 60 modeled seconds.',
        'Early decoy identifies the same containable identity (sess-primary) as the regular SOC signal.',
        'Same response policy, action scope, and 60 s latency across both attacker paces.'
      ],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, patchCovered: false }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, patchCovered: false })
      }
    },
    'speed-covered-patch': {
      id: 'speed-covered-patch',
      kind: 'speed',
      title: 'Speed: Covered Virtual Patch',
      subtitle: 'Active ingress virtual patch rule matches the same milestone at both Pre-2023 and ARTEX paces.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: [
        'Active virtual patch rule VP-EDGE-01 covers the ingress event at both paces.',
        'Blocking at ingress suppresses all dependent downstream milestones.'
      ],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, patchCovered: true }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, patchCovered: true })
      }
    },
    'capability-45s': {
      id: 'capability-45s',
      kind: 'capability',
      title: 'Capability: 45s Review Window',
      subtitle: 'Common pace and 45 s budget across 3 service opportunities (15 s/review, 45 s human handoff).',
      cutoffSec: 45,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: [
        'Three abstract service opportunities available to both profiles under identical access rules.',
        '15 s per opportunity review; 45 s duration for any required human handoff.',
        'Human-led trace reviews sequentially and waits at Opportunity 1 handoff; ARTEX reviews all 3 concurrently.'
      ],
      traces: {
        pre2023: buildCapabilityEvents('pre2023', false),
        artex: buildCapabilityEvents('artex', false)
      }
    },
    'capability-denied': {
      id: 'capability-denied',
      kind: 'capability',
      title: 'Capability: Access Denied (45s)',
      subtitle: 'Same 45 s window and workflow traces, with access to the designated sensitive record denied.',
      cutoffSec: 45,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: true,
      assumptions: [
        'Shared access rules deny read access to the designated sensitive record.',
        'Both profiles end without a protected read while still differing in opportunities reviewed.'
      ],
      traces: {
        pre2023: buildCapabilityEvents('pre2023', true),
        artex: buildCapabilityEvents('artex', true)
      }
    },
    'speed-no-signal': {
      id: 'speed-no-signal',
      kind: 'speed',
      title: 'Edge Case: No Matching SOC Signal',
      subtitle: 'Observable telemetry is absent, so Agentic SOC never triggers.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['No matching SOC telemetry is emitted during the trace.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, socDetectable: false, includeDecoy: false }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, socDetectable: false, includeDecoy: false })
      }
    },
    'speed-at-objective': {
      id: 'speed-at-objective',
      kind: 'speed',
      title: 'Edge Case: Same-Timestamp Enforcement Tie',
      subtitle: 'SOC enforcement becomes effective at the exact timestamp of the protected read.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['When enforcement and protected read share a timestamp, objective takes precedence unless enforcementPrecedesOnTie is set.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 7140, lateralTime: 7170, protectedReadTime: 7200 }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 20, lateralTime: 50, protectedReadTime: 80 })
      }
    },
    'speed-late-decoy': {
      id: 'speed-late-decoy',
      kind: 'speed',
      title: 'Edge Case: Late Decoy Placement',
      subtitle: 'Decoy interaction occurs after the protected read.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['Decoy is placed behind the protected record so alert arrives after data access.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 7500, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, decoyPlacement: 'late' }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 100, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, decoyPlacement: 'late' })
      }
    },
    'speed-untouched-decoy': {
      id: 'speed-untouched-decoy',
      kind: 'speed',
      title: 'Edge Case: Untouched Decoy',
      subtitle: 'Attacker trace never interacts with the instrumented decoy.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['An untouched decoy produces no alert.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, includeDecoy: false }),
        artex: buildSpeedEvents({ ingressTime: 0, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, includeDecoy: false })
      }
    },
    'speed-scope-mismatch': {
      id: 'speed-scope-mismatch',
      kind: 'speed',
      title: 'Edge Case: Containment Scope Mismatch',
      subtitle: 'Containment of sess-primary leaves independent sess-secondary activity in progress.',
      cutoffSec: null,
      socLatencySec: 60,
      decisionDelaySec: 15,
      accessDenied: false,
      assumptions: ['Containment is scoped to sess-primary; unrelated sess-secondary events continue.'],
      traces: {
        pre2023: buildSpeedEvents({ ingressTime: 0, decoyTime: 600, boundaryTime: 5400, lateralTime: 6300, protectedReadTime: 7200, includeSecondaryBranch: true }),
        artex: buildSpeedEvents({ ingressTime: 0, decoyTime: 5, boundaryTime: 30, lateralTime: 55, protectedReadTime: 80, includeSecondaryBranch: true })
      }
    }
  };

  function evaluateComparisonRun(fixtureId, profileId, defenseId, options = {}) {
    const fixture = COMPARISON_FIXTURES[fixtureId];
    if (!fixture) throw new Error(`Unknown comparison fixture: ${fixtureId}`);
    const profile = COMPARISON_PROFILES[profileId];
    if (!profile) throw new Error(`Unknown comparison profile: ${profileId}`);
    const defense = COMPARISON_DEFENSES[defenseId];
    if (!defense) throw new Error(`Unknown comparison defense: ${defenseId}`);

    const rawEvents = fixture.traces[profileId] || [];
    const cutoffSec = fixture.cutoffSec;
    const useVirtualPatch = defenseId === 'patch';
    const useSoc = defenseId === 'soc' || defenseId === 'combined';
    const useCanaries = defenseId === 'canaries' || (defenseId === 'combined' && options.useDecoySignal !== false);
    const enforcementPrecedesOnTie = !!options.enforcementPrecedesOnTie;

    const blockedEventIds = new Set();
    const containedIdentities = new Set();
    const trace = [];
    const alerts = [];

    let telemetryTimeSec = null;
    let decisionTimeSec = null;
    let enforcementTimeSec = null;
    let signalSource = null;
    let edgeBlockedTimeSec = null;
    let patchMissed = false;
    let decoyTriggeredTimeSec = null;
    let protectedReadReached = false;
    let protectedReadTimeSec = null;
    let accessDeniedObserved = false;

    const reviewedOpportunities = new Set();
    const concurrentBatchSet = new Set();
    let manualHandoffs = 0;

    let pendingContainment = null;

    function enforceContainment() {
      const { timeSec, identityId, source } = pendingContainment;
      enforcementTimeSec = timeSec;
      containedIdentities.add(identityId);
      trace.push({
        id: `soc-enforce-${identityId}`,
        timeSec,
        layerIdx: 1,
        assetId: 'cmp-api',
        relationshipId: null,
        identityId,
        kind: 'containment',
        outcome: 'enforced',
        title: 'Agentic SOC containment effective',
        detail: `Containment enforced for ${identityId} (signal: ${source}).`,
        reason: protectedReadReached
          ? 'CONTAINMENT EFFECTIVE AFTER DATA ACCESS'
          : 'CONTAINMENT EFFECTIVE'
      });
    }

    for (const ev of rawEvents) {
      if (cutoffSec !== null && ev.timeSec > cutoffSec) {
        continue;
      }

      if (pendingContainment && enforcementTimeSec === null) {
        const arrivesBefore = enforcementPrecedesOnTie
          ? pendingContainment.timeSec <= ev.timeSec
          : pendingContainment.timeSec < ev.timeSec;
        if (arrivesBefore) enforceContainment();
      }

      const prereqBlocked = (ev.prerequisiteIds || []).some(pid => blockedEventIds.has(pid));
      if (prereqBlocked) {
        blockedEventIds.add(ev.id);
        trace.push({
          ...ev,
          outcome: 'suppressed',
          reason: 'PREREQUISITE BLOCKED'
        });
        continue;
      }

      // Check if this event's identity is already contained
      if (containedIdentities.has(ev.identityId)) {
        blockedEventIds.add(ev.id);
        trace.push({
          ...ev,
          outcome: 'suppressed',
          reason: 'CONTAINMENT ACTIVE'
        });
        continue;
      }

      // Track capability review metrics for unblocked events within cutoff
      if (ev.kind === 'opportunity_review' && ev.opportunityId) {
        reviewedOpportunities.add(ev.opportunityId);
        if (ev.concurrentGroup) concurrentBatchSet.add(ev.opportunityId);
        if (ev.requiresHumanReview) manualHandoffs += 1;
      }

      // Virtual Patching check
      if (useVirtualPatch && ev.kind === 'ingress') {
        if (ev.ruleCoverage && ev.ruleCoverage.covered) {
          blockedEventIds.add(ev.id);
          edgeBlockedTimeSec = ev.timeSec;
          alerts.push({ timeSec: ev.timeSec, source: 'virtual_patch', label: ev.ruleCoverage.ruleId || 'RULE MATCH' });
          trace.push({
            ...ev,
            outcome: 'blocked',
            reason: 'RULE MATCH · BLOCKED AT EDGE'
          });
          continue;
        } else {
          patchMissed = true;
        }
      }

      // Canaries check
      if (ev.isDecoy) {
        if (useCanaries) {
          decoyTriggeredTimeSec = decoyTriggeredTimeSec === null ? ev.timeSec : Math.min(decoyTriggeredTimeSec, ev.timeSec);
          alerts.push({ timeSec: ev.timeSec, source: 'canary', label: 'DECOY TRIGGERED' });
        } else if (defenseId === 'canaries') {
          // shouldn't happen since useCanaries is true for canaries
        }
      }

      // Agentic SOC telemetry check (decoy signal only counts if useCanaries is true)
      if (useSoc && ev.telemetry && ev.telemetry.detectable) {
        const isDecoyOnly = ev.isDecoy && !useCanaries;
        if (!isDecoyOnly && !pendingContainment) {
          const sigTime = ev.timeSec;
          const decTime = sigTime + fixture.decisionDelaySec;
          const enfTime = sigTime + fixture.socLatencySec;
          telemetryTimeSec = sigTime;
          decisionTimeSec = decTime;
          signalSource = ev.isDecoy ? 'canary' : 'regular';
          alerts.push({ timeSec: sigTime, source: signalSource, label: ev.telemetry.signalLabel });
          pendingContainment = {
            timeSec: enfTime,
            identityId: ev.telemetry.containableIdentity || ev.identityId,
            source: signalSource
          };
        }
      }

      // Protected read check
      if (ev.isProtectedRead) {
        if (ev.accessDenied) {
          accessDeniedObserved = true;
          trace.push({
            ...ev,
            outcome: 'denied',
            reason: 'ACCESS DENIED'
          });
        } else {
          protectedReadReached = true;
          protectedReadTimeSec = ev.timeSec;
          trace.push({
            ...ev,
            outcome: 'succeeded',
            reason: 'PROTECTED RECORD READ'
          });
        }
        continue;
      }

      trace.push({
        ...ev,
        outcome: ev.isDecoy && useCanaries ? 'alert' : 'succeeded',
        reason: ev.isDecoy && useCanaries
          ? (defenseId === 'canaries' ? 'DECOY TRIGGERED · ALERT ONLY' : 'DECOY TRIGGERED · SIGNAL TO SOC')
          : (useVirtualPatch && ev.kind === 'ingress' ? 'OUTSIDE RULE COVERAGE' : 'OBSERVED')
      });
    }

    if (pendingContainment && enforcementTimeSec === null &&
        (cutoffSec === null || pendingContainment.timeSec <= cutoffSec)) {
      enforceContainment();
    }

    trace.sort((a, b) => a.timeSec - b.timeSec);

    // Determine baseline reference protected read time for margin / lead time calculations
    let baselineProtectedReadSec = null;
    if (defenseId === 'baseline') {
      baselineProtectedReadSec = protectedReadTimeSec;
    } else {
      const baseRun = evaluateComparisonRun(fixtureId, profileId, 'baseline');
      baselineProtectedReadSec = baseRun.protectedReadTimeSec;
    }

    alerts.sort((a, b) => a.timeSec - b.timeSec);
    const firstAlert = alerts.length > 0 ? alerts[0] : null;
    const firstAlertTimeSec = firstAlert ? firstAlert.timeSec : null;
    const firstAlertSource = firstAlert ? firstAlert.source : null;

    // Determine effective control time & reason
    let effectiveControlTimeSec = null;
    let controlReason = 'NO ACTIVE DEFENSES';

    if (defenseId === 'baseline') {
      controlReason = accessDeniedObserved ? 'ACCESS DENIED' : (protectedReadReached ? 'UNMITIGATED · PROTECTED READ' : 'NO PROTECTED READ BY CUTOFF');
    } else if (defenseId === 'patch') {
      if (edgeBlockedTimeSec !== null) {
        effectiveControlTimeSec = edgeBlockedTimeSec;
        controlReason = 'RULE MATCH · BLOCKED AT EDGE';
      } else {
        controlReason = 'OUTSIDE RULE COVERAGE';
      }
    } else if (defenseId === 'canaries') {
      if (decoyTriggeredTimeSec !== null) {
        controlReason = 'DECOY TRIGGERED · ALERT ONLY';
      } else {
        controlReason = 'DECOY UNTOUCHED · NO ALERT';
      }
    } else if (defenseId === 'soc' || defenseId === 'combined') {
      if (!pendingContainment) {
        controlReason = 'NO MATCHING SIGNAL';
      } else if (enforcementTimeSec === null) {
        controlReason = 'CONTAINMENT PENDING AT CUTOFF';
      } else {
        effectiveControlTimeSec = enforcementTimeSec;
        if (protectedReadReached) {
          controlReason = 'CONTAINMENT EFFECTIVE AFTER DATA ACCESS';
        } else {
          controlReason = 'CONTAINED BEFORE DATA ACCESS';
        }
      }
    }

    const responseMarginSec = (baselineProtectedReadSec !== null && effectiveControlTimeSec !== null)
      ? baselineProtectedReadSec - effectiveControlTimeSec
      : null;

    const detectionLeadTimeSec = (baselineProtectedReadSec !== null && firstAlertTimeSec !== null)
      ? baselineProtectedReadSec - firstAlertTimeSec
      : null;

    return {
      fixtureId,
      fixtureKind: fixture.kind,
      fixtureTitle: fixture.title,
      profileId,
      profileLabel: profile.label,
      defenseId,
      defenseLabel: defense.label,
      cutoffSec,
      protectedReadReached,
      protectedReadTimeSec,
      accessDeniedObserved,
      baselineProtectedReadSec,
      firstAlertTimeSec,
      firstAlertSource,
      telemetryTimeSec,
      decisionTimeSec,
      enforcementTimeSec,
      scheduledEnforcementTimeSec: pendingContainment?.timeSec ?? null,
      effectiveControlTimeSec,
      signalSource,
      controlReason,
      responseMarginSec,
      detectionLeadTimeSec,
      patchMissed,
      opportunitiesReviewed: reviewedOpportunities.size,
      concurrentReviews: concurrentBatchSet.size,
      manualHandoffs,
      assumptions: fixture.assumptions,
      trace
    };
  }

  function evaluateComparisonMatrix(fixtureId, options = {}) {
    const profiles = ['pre2023', 'artex'];
    const defenses = ['baseline', 'patch', 'soc', 'canaries', 'combined'];
    const cells = {};
    for (const p of profiles) {
      cells[p] = {};
      for (const d of defenses) {
        cells[p][d] = evaluateComparisonRun(fixtureId, p, d, options);
      }
    }
    return {
      fixture: COMPARISON_FIXTURES[fixtureId],
      estate: createComparisonEstate(),
      cells
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
    COMPARISON_PROFILES,
    COMPARISON_DEFENSES,
    COMPARISON_FIXTURES,
    createComparisonEstate,
    formatDurationSeconds,
    formatSignedDelta,
    evaluateComparisonRun,
    evaluateComparisonMatrix,
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
