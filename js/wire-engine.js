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
    { min: 2, max: 3 },
    { min: 2, max: 3 },
    { min: 2, max: 3 },
    { min: 1, max: 2 }
  ];

  // Historical analogues for an isolated Layer 1 event in the browser.
  const EDGE_MISCONFIGURATIONS = [
    { id: 'default-admin', asset: 'External Device Admin Portal', title: 'Default admin credentials', icon: 'iot.png', interfaces: ['device-management'], assumedAccount: true, reference: 'Unitronics device intrusions', source: 'https://www.cisa.gov/sites/default/files/2024-12/aa23-335a-irgc-affiliated-cyber-actors-exploit-plcs-in-multiple-sectors.pdf' },
    { id: 'rdp-exposed', asset: 'Internet-Facing Remote Desktop', title: 'Remote Desktop exposed directly', icon: 'remote-access.png', interfaces: ['rdp'], assumedAccount: true, reference: 'SamSam ransomware incidents', source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa18-337a' },
    { id: 'legacy-vpn', asset: 'Legacy VPN Portal', title: 'Legacy VPN account still enabled without MFA', icon: 'remote-access.png', interfaces: ['vpn'], assumedAccount: true, reference: 'Colonial Pipeline breach', source: 'https://www.govinfo.gov/content/pkg/CHRG-117hhrg45085/html/CHRG-117hhrg45085.htm' },
    { id: 'test-tenant', asset: 'Nonproduction Cloud Tenant', title: 'Test tenant account excluded from MFA', icon: 'identity.png', interfaces: ['https'], assumedAccount: true, reference: 'Microsoft Midnight Blizzard incident', source: 'https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/' },
    { id: 'data-allowlist', asset: 'Public Cloud Data Warehouse Login', title: 'Cloud warehouse reachable without trusted-network restrictions', icon: 'data.png', interfaces: ['https'], assumedAccount: true, reference: 'UNC5537 Snowflake customer compromises', source: 'https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion' },
    { id: 'public-storage', asset: 'Public Document Storage', title: 'Sensitive storage allows anonymous read', icon: 'data.png', interfaces: ['storage-s3', 'https'], reference: 'Ascension mortgage document breach', source: 'https://search.ftc.gov/system/files/documents/cases/1923126ascensioncomplaint.pdf' },
    { id: 'public-kubernetes', asset: 'Public Kubernetes Console', title: 'Kubernetes dashboard with no authentication', icon: 'cloud-infrastructure.png', interfaces: ['https'], reference: 'RedLock investigation of Tesla cryptojacking', source: 'https://www.ten-inc.com/documents/RedLock_Whitepaper_2018.pdf' },
    { id: 'public-docker', asset: 'Public Container Management Interface', title: 'Docker management API with no authentication', icon: 'components.png', interfaces: ['http'], reference: 'Unit 42 investigation of compromised Docker hosts', source: 'https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed/' },
    { id: 'waf-forwarding', asset: 'Public Cloud Application Gateway', title: 'WAF permits unintended backend access', icon: 'network.png', interfaces: ['https'], reference: 'Capital One cloud data breach', source: 'https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson' },
    { id: 'public-web-config', asset: 'Public Application Configuration', title: 'Web server publishes deployment configuration', icon: 'configuration.png', interfaces: ['https'], reference: 'Unit 42 cloud extortion investigation', source: 'https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/' },
    { id: 'datadog-proxy', asset: 'Customer-Managed Datadog Proxy', title: 'Unauthenticated proxy exposes logs', icon: 'threat-detection.png', interfaces: ['https'], illustration: 'git-to-idp', reference: 'User-supplied scenario. Datadog documentation provides product context.', source: 'https://docs.datadoghq.com/data_security/agent/' }
  ];

  // Advisory-backed appliance families. Affected builds and configurations are
  // assigned only when that family receives a modeled finding in an estate.
  const EDGE_APPLIANCES = {
    'f5-gateway': { cve: 'CVE-2022-1388', product: 'F5 BIG-IP', version: '16.1.0', conditions: { managementReachable: true }, source: 'https://www.cisa.gov/sites/default/files/publications/AA22-138A-Threat_Actors_Exploiting_F5_BIG-IP_CVE-2022-1388_F5.pdf' },
    'ivanti-connect': { cve: 'CVE-2023-46805', product: 'Ivanti Connect Secure', version: '22.4R2', conditions: { gatewayWebEnabled: true }, source: 'https://www.ivanti.com/blog/security-update-for-ivanti-connect-secure-and-ivanti-policy-secure-gateways' },
    'forti-vpn': { cve: 'CVE-2018-13379', product: 'Fortinet FortiGate', version: '6.0.4', conditions: { sslVpnEnabled: true }, source: 'https://www.fortinet.com/blog/psirt-blogs/fortios-ssl-vulnerability' },
    'pan-globalprotect': { cve: 'CVE-2024-3400', product: 'Palo Alto Networks PAN-OS Firewall', version: '10.2.8', conditions: { globalProtectEnabled: true }, source: 'https://security.paloaltonetworks.com/CVE-2024-3400' },
    'citrix-adc': { cve: 'CVE-2023-3519', product: 'Citrix NetScaler ADC', version: '13.1-48.47', conditions: { gatewayMode: true }, source: 'https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf' },
    'cisco-asa': { cve: 'CVE-2020-3452', product: 'Cisco ASA Firewall', version: '9.12.3', conditions: { webVpnEnabled: true }, source: 'https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-asaftd-ro-path-KJuQhB86.html' },
    'sonicwall-sma': { cve: 'CVE-2021-20016', product: 'SonicWall SMA 100', version: '10.2.0.6', conditions: { sslVpnEnabled: true }, source: 'https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2021-005/' },
    'sophos-firewall': { cve: 'CVE-2022-1040', product: 'Sophos Firewall', version: '18.5 MR2 before hotfix', conditions: { userPortalEnabled: true }, source: 'https://www.sophos.com/en-us/security-advisories/sophos-sa-20220325-sfos-rce' },
    'zyxel-atp': { cve: 'CVE-2023-28771', product: 'Zyxel ATP Firewall', version: '5.35', conditions: { ipsecEnabled: true }, source: 'https://www.zyxel.com/global/en/support/security-advisories/zyxels-guidance-for-the-recent-attacks-on-the-zywall-devices' },
    'checkpoint-quantum': { cve: 'CVE-2024-24919', product: 'Check Point Quantum Security Gateway', version: 'R81.20 before hotfix', conditions: { remoteAccessVpnEnabled: true }, source: 'https://advisories.checkpoint.com/defense/advisories/public/2024/cpai-2024-0353.html/' }
  };

  const REVIEWED_EXAMPLES = {
    ...EDGE_APPLIANCES,
    'cust-api': { cve: 'CVE-2022-29464', product: 'WSO2 API Manager', version: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, source: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf' },
    'partner-api': { cve: 'CVE-2022-29464', product: 'WSO2 API Manager', version: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, source: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf' },
    'wso2-api': { cve: 'CVE-2022-29464', product: 'WSO2 API Manager', version: '3.2.0', conditions: { uploadEndpointReachable: true, executableUpload: true }, source: 'https://www.cisa.gov/sites/default/files/2023-08/aa23-215a_joint_csa_2022_top_routinely_exploited_vulnerabilities.pdf' },
    'sentry-auth': { cve: 'CVE-2023-38035', product: 'Ivanti Sentry', version: '9.18.0', conditions: { adminPort8443Reachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-38035' },
    'ad-identity': { cve: 'CVE-2022-26923', product: 'Active Directory Domain Services', version: 'Windows Server 2022', conditions: { adcsEnrollmentEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2022-26923' },
    'ivanti-epm': { cve: 'CVE-2024-29824', product: 'Ivanti EPM', version: '2022 SU5', conditions: { coreServerReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2024-29824' },
    'exchange': { cve: 'CVE-2021-26855', product: 'Microsoft Exchange Server', version: '2019 CU8', conditions: { ewsExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-26855' },
    'app-engine': { cve: 'CVE-2022-22965', product: 'Spring Framework', version: '5.3.17', conditions: { jdk9Plus: true, tomcatVulnerable: true, warDeployment: true, mvcDataBinding: true }, source: 'https://spring.io/security/cve-2022-22965/' },
    'spring-svc': { cve: 'CVE-2022-22965', product: 'Spring Framework', version: '5.3.17', conditions: { jdk9Plus: true, tomcatVulnerable: true, warDeployment: true, mvcDataBinding: true }, source: 'https://spring.io/security/cve-2022-22965/' },
    'log4j-svc': { cve: 'CVE-2021-44228', product: 'Apache Log4j 2', version: '2.14.1', conditions: { jndiLookupsEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
    'iot-hub': { cve: 'CVE-2021-44228', product: 'Apache Log4j 2', version: '2.14.1', conditions: { jndiLookupsEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
    'confluence-node': { cve: 'CVE-2023-22527', product: 'Atlassian Confluence Data Center', version: '8.5.3', conditions: { templateEndpointExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-22527' },
    'confluence-admin': { cve: 'CVE-2023-22515', product: 'Atlassian Confluence Server', version: '8.5.1', conditions: { setupEndpointExposed: true }, source: 'https://support.atlassian.com/atlassian-knowledge-base/kb/faq-for-cve-2023-22515/' },
    'weblogic': { cve: 'CVE-2020-14882', product: 'Oracle WebLogic Server', version: '12.2.1.4.0', conditions: { adminConsoleReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2020-14882' },
    'sql-reporting': { cve: 'CVE-2020-0618', product: 'SQL Server Reporting Services', version: '2016', conditions: { reportViewerExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2020-0618' },
    'forti-ems': { cve: 'CVE-2023-48788', product: 'Fortinet FortiClient EMS', version: '7.2.2', conditions: { fcmDaemonReachable: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-48788' },
    'cicd-runner': { cve: 'CVE-2023-42793', product: 'JetBrains TeamCity', version: '2023.05.3', conditions: { restAuthBypass: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-42793' },
    'activemq': { cve: 'CVE-2023-46604', product: 'Apache ActiveMQ', version: '5.18.2', conditions: { openWirePortExposed: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-46604' },
    'moveit-sftp': { cve: 'CVE-2023-34362', product: 'Progress MOVEit Transfer', version: '2023.0.0', conditions: { webTransferEnabled: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2023-34362' },
    'ai-core': { cve: 'CVE-2026-42271', product: 'LiteLLM Proxy', version: '1.83.6', conditions: { mcpTestEndpointsEnabled: true }, source: 'https://github.com/BerriAI/litellm/security/advisories/GHSA-v4p8-mg3p-g94g' },
    'redis-debian': { cve: 'CVE-2022-0543', product: 'Debian Redis', version: '5:6.0.16-1', conditions: { luaSandboxUnpatched: true }, source: 'https://nvd.nist.gov/vuln/detail/CVE-2022-0543' }
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
      { id: 'CVE-2023-46805', title: 'Ivanti Connect Secure Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2024-3400', title: 'PAN-OS Command Injection RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-3519', title: 'Citrix NetScaler ADC Unauth RCE', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-20198', title: 'Cisco IOS XE Priv Escalation', tech: 'T1068', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2024-21887', title: 'Ivanti Connect Policy Injection', tech: 'T1059', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-1388', title: 'F5 BIG-IP iControl REST Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2022-42475', title: 'FortiOS SSL-VPN Heap Buffer Overflow', tech: 'T1190', inKev: true, reqInterface: 'vpn', yields: 'app_exec' },
      { id: 'CVE-2018-13379', title: 'FortiOS SSL-VPN Path Traversal', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2020-3452', title: 'Cisco ASA VPN File Disclosure', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2021-20016', title: 'SonicWall SMA SQL Injection', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
      { id: 'CVE-2022-1040', title: 'Sophos Firewall Auth Bypass', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'app_exec' },
      { id: 'CVE-2023-28771', title: 'Zyxel ATP Command Injection', tech: 'T1190', inKev: true, reqInterface: 'vpn', yields: 'app_exec' },
      { id: 'CVE-2024-24919', title: 'Check Point VPN Information Disclosure', tech: 'T1190', inKev: true, reqInterface: 'https', yields: 'file_read' },
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
    'CVE-2024-4577': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2 / SC-7', reason: 'WAF query regex drops %ad PHP CGI argument injection' }, ml: { mitigates: false, reason: 'Edge CGI exploit bypasses internal behavioral telemetry' } },
    'CVE-2023-46805': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'WAF virtual patch restricts unauthenticated /api/v1/cav/client endpoints' }, ml: { mitigates: false, reason: 'Perimeter auth bypass occurs before internal ML baseline can flag session' } },
    'CVE-2024-3400': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SI-2 / SC-7', reason: 'Simulated targeted virtual patch filters malicious HTTP requests to the GlobalProtect portal when covered.' }, ml: { mitigates: false, reason: 'Edge firewall OS injection executes at edge appliance firmware layer' } },
    'CVE-2023-3519': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'WAF protocol validator drops malformed HTTP Host header buffer overflow' }, ml: { mitigates: false, reason: 'Edge ADC stack overflow executes pre-auth before user identity creation' } },
    'CVE-2023-20198': { waf: { mitigates: false, reason: 'Direct REST management endpoint bypasses edge reverse proxy' }, ml: { mitigates: false, reason: 'Direct network boundary exploitation circumvents internal host ML agents' } },
    'CVE-2024-21887': { waf: { mitigates: false, reason: 'In-line edge gateway exploit triggers prior to internal microservice logs' }, ml: { mitigates: false, reason: 'In-line edge gateway exploit triggers prior to internal microservice logs' } },
    'CVE-2022-1388': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'WAF drops hop-by-hop Connection header smuggling to /mgmt/shared/authn' }, ml: { mitigates: false, reason: 'Edge appliance admin bypass executes outside host mesh' } },
    'CVE-2022-42475': { waf: { mitigates: false, reason: 'VPN binary protocol heap overflow bypasses L7 HTTP reverse proxy' }, ml: { mitigates: false, reason: 'Edge VPN daemon heap overwrite occurs before telemetry ingestion' } },
    'CVE-2023-22515': { waf: { mitigates: false, reason: 'Legitimate HTTP requests to /setup endpoints pass perimeter WAF inspection' }, ml: { mitigates: true, control: 'NIST SI-4 / AC-3', reason: 'Agentic SOC Mitigation flags setup wizard execution on established production instance' } },
    'CVE-2024-27198': { waf: { mitigates: false, reason: 'OAuth/Auth endpoint traversal passes standard perimeter HTTP parsers' }, ml: { mitigates: true, control: 'NIST IA-5 / AC-3', reason: 'Agentic SOC Mitigation isolates service on forged administrative token minting' } },
    'CVE-2023-38035': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SC-7', reason: 'Edge WAF blocks unauthenticated HTTP requests to MICS port 8443 interface' }, ml: { mitigates: false, reason: 'Admin API interface lacks granular internal behavioral baseline' } },
    'CVE-2023-4966': { waf: { mitigates: false, reason: 'Outbound session token memory disclosure occurs in TLS response stream' }, ml: { mitigates: true, control: 'NIST AC-3 / IA-5', reason: 'Zero-Trust ML halts stolen session token used across divergent IP/fingerprint' } },
    'CVE-2024-1709': { waf: { mitigates: false, reason: 'Setup wizard URI /SetupWizard.aspx is considered valid application traffic by WAF' }, ml: { mitigates: true, control: 'NIST AC-3', reason: 'Agentic SOC Mitigation blocks unauthorized admin account creation out-of-band' } },
    'CVE-2021-26855': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2 / SC-7', reason: 'WAF virtual patch filters X-AnonResource-Backend SSRF header' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects internal SSRF lateral probe to backend Exchange RPC' } },
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
    'CVE-2023-34362': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2', reason: 'WAF SQLi virtual patch inspects & blocks malformed X-MOVEit headers' }, ml: { mitigates: true, control: 'NIST SI-4', reason: 'Agentic SOC Mitigation detects abnormal mass query exfiltration on core SQL tables' } },
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
    'CVE-2018-13379': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SI-2 / SC-7', reason: 'Simulated virtual patch filters malicious requests to the FortiOS SSL VPN web portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2019-11510': { waf: { mitigates: true, ruleStrictness: 'strict_virtual_patch', control: 'NIST SI-2 / SC-7', reason: 'Simulated virtual patch filters malicious requests to the Pulse web portal when covered.' }, ml: { mitigates: false, reason: 'The edge appliance is outside internal behavioral monitoring.' } },
    'CVE-2021-42013': { waf: { mitigates: true, ruleStrictness: 'signature_regex', control: 'NIST SI-2', reason: 'Simulated WAF rule blocks traversal requests.' }, ml: { mitigates: false, reason: 'The edge server is outside internal behavioral monitoring.' } },
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
            { id: 'forti-vpn', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2018-13379'], variants: ['Fortinet FortiGate SSL VPN'] },
            { id: 'cisco-asa', icon: 'network.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2020-3452'], variants: ['Cisco ASA Firewall'] }
          ]
        },
        {
          name: 'Azure Enterprise',
          targets: [
            { id: 'public-blob', icon: 'data.png', interfaces: ['storage-s3', 'https'], attackTechnique: 'T1530', attackDescription: 'Data from Cloud Storage', publicExposure: 'Simulated Azure Blob container permits anonymous public read; the contents are not assumed to contain credentials.', variants: ['Azure Blob Storage · Container'] },
            { id: 'pan-globalprotect', icon: 'network.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2024-3400'], variants: ['PAN-OS GlobalProtect Gateway'] },
            { id: 'sonicwall-sma', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2021-20016'], variants: ['SonicWall SMA 100'] },
            { id: 'sophos-firewall', icon: 'network.png', interfaces: ['https'], kevByVariant: ['CVE-2022-1040'], variants: ['Sophos Firewall'] }
          ]
        },
        {
          name: 'GCP & Partners',
          targets: [
            { id: 'public-gitlab', icon: 'code.png', interfaces: ['repo-http', 'https'], attackTechnique: 'T1593.003', attackDescription: 'Search public code repositories', publicExposure: 'Simulated GitLab project is publicly readable contrary to its intended access policy.', variants: ['GitLab · Project'] },
            { id: 'public-bitbucket', icon: 'code.png', interfaces: ['repo-http', 'https'], attackTechnique: 'T1593.003', attackDescription: 'Search public code repositories', publicExposure: 'Simulated Bitbucket repository is publicly readable contrary to its intended access policy.', variants: ['Bitbucket · Repository'] },
            { id: 'citrix-adc', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2023-3519'], variants: ['Citrix NetScaler ADC Gateway'] },
            { id: 'zyxel-atp', icon: 'network.png', interfaces: ['vpn'], kevByVariant: ['CVE-2023-28771'], variants: ['Zyxel ATP Firewall'] },
            { id: 'checkpoint-quantum', icon: 'remote-access.png', interfaces: ['https', 'vpn'], kevByVariant: ['CVE-2024-24919'], variants: ['Check Point Quantum Gateway'] },
            { id: 'apache-edge', icon: 'server-infrastructure.png', interfaces: ['https'], kevByVariant: ['CVE-2021-42013'], variants: ['Apache HTTP Server 2.4.50 Edge'] },
            { id: 'support-diagnostics', preset: 'mixed', icon: 'configuration.png', interfaces: ['https'], variants: ['Support Diagnostics Portal'] },
            { id: 'external-misconfig', preset: 'mixed', icon: 'configuration.png', variants: ['External service'] }
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
    'cisco-asa': ['iam-idp', 'ad-identity'],
    'sonicwall-sma': ['sentry-auth', 'iam-idp'],
    'sophos-firewall': ['exchange', 'iam-idp'],
    'zyxel-atp': ['partner-api', 'iam-idp'],
    'checkpoint-quantum': ['iam-idp', 'ad-identity'],
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
    ...Object.keys(EDGE_APPLIANCES), 'apache-edge', 'public-s3', 'public-blob',
    'public-gitlab', 'public-bitbucket', 'support-diagnostics', 'external-misconfig'
  ]);

  const DEFENSE_SCENARIOS = {
    baseline: { tag: '01 / BASELINE', name: 'Baseline (Unmitigated)' },
    patch: { tag: '02 / VIRTUAL PATCH', name: 'Virtual Patch (WAF)' },
    canaries: { tag: '03 / CANARIES', name: 'Canaries (Alert Only)' },
    defender: { tag: '04 / AGENTIC SOAR', name: 'Agentic SOAR' },
    soc: { tag: '04 / AGENTIC SOC', name: 'Agentic SOC' },
    'soc-canary': { tag: '05 / SOC + CANARY', name: 'Agentic SOC + Canary' },
    combined: { tag: '05 / DEFENSE IN DEPTH', name: 'Defense in Depth' }
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

  function soarDetects(assetId, seed, multiplier = 1) {
    return hashNode(seed, assetId, 2166136261) < Math.min(0.95, SOAR_DETECTION_RATE * multiplier);
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
    // A tabletop step moves only its fictional session along the seeded display route.
    const exercise = targetFindings.find(f => f.kind === 'exercise' &&
      f.relationshipId === (relationship?.id ?? null));
    if (exercise && (sourceAsset
      ? relationship?.sourceId === sourceAsset.id && relationship.targetId === targetAsset.id &&
        state.reachedAssets.get(sourceAsset.id)?.capabilities.has('exercise_session')
      : targetAsset.isExternalEntry)) {
      return [{
        eligible: true,
        actionKind: 'exercise',
        finding: exercise,
        technique: exercise.technique,
        yieldsCapability: targetAsset.layerIdx === 3 ? 'data_read' : 'exercise_session',
        reason: exercise.description
      }];
    }
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
        finding: targetFindings.find(finding => finding.kind === 'assumed_edge_account') || null,
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

  function evaluateDefense(targetAsset, action, mode, seed, isCanary, options = {}) {
    const attackerProfile = options.attackerProfile || null;
    const defensePosture = options.defensePosture || null;
    const multiplier = attackerProfile?.detectionMultiplier ?? 1;
    const layerMonitored = !defensePosture?.telemetryLayers || defensePosture.telemetryLayers.includes(targetAsset.layerIdx);

    if (action.actionKind === 'exercise') {
      if (mode === 'patch' && action.finding.patchCovered) {
        return { addressed: true, badge: 'BLOCKED · VIRTUAL PATCH', reason: 'The exercise assumes a matching edge rule blocks this session.' };
      }
      return { addressed: false, reason: action.reason };
    }
    if (isCanary) {
      if (mode === 'canaries') {
        return {
          addressed: false,
          alertOnly: true,
          badge: 'CANARY TRIGGERED · ALERT ONLY',
          control: 'NIST SI-4',
          reason: 'Decoy interaction emitted a high-confidence alert without blocking or containing the session.'
        };
      }
      if (mode === 'combined' || mode === 'soc-canary') {
        return {
          addressed: true,
          badge: 'CONTAINED · CANARY TRIGGER',
          control: 'NIST SI-4',
          reason: 'Access to the decoy generated an alert; Agentic SOC immediately contained the session.'
        };
      }
    }
    if (action.actionKind === 'diagnostic_access') {
      return { addressed: false, badge: 'SCOPED CREDENTIAL EXPOSED', reason: action.reason };
    }

    if (mode === 'baseline' || mode === 'canaries') {
      return {
        addressed: false,
        badge: mode === 'canaries' ? 'UNMITIGATED · NO DECOY HIT' : 'EXPLOITED',
        reason: mode === 'canaries'
          ? 'Canaries alert on decoy contact only; non-decoy paths remain unblocked.'
          : 'Baseline scenario unmitigated: zero active defenses applied.'
      };
    }

    const isHttpSurface = (targetAsset.interfaces || []).some(i => ['https', 'api-https', 'repo-http', 'storage-s3'].includes(i));
    const nonHttpGroups = new Set(['aws-vpn', 'az-net', 'az-branch', 'partner-gw', 'zyxel-atp']);
    const isNonHttpProtocol = nonHttpGroups.has(targetAsset.groupId) || !isHttpSurface;
    const portalIds = new Set(['forti-vpn', 'pulse-vpn', 'pan-globalprotect']);
    const portalCovered = !portalIds.has(targetAsset.groupId) || wafPortalCovered(targetAsset.id, seed);
    const socEnabled = mode === 'defender' || mode === 'soc' || mode === 'soc-canary' || mode === 'combined';

    if (action.actionKind === 'anonymous_access') {
      if (socEnabled && layerMonitored && soarDetects(targetAsset.id, seed, multiplier)) {
        return { addressed: true, badge: 'CONTAINED · AGENTIC SOC', control: 'NIST AC-3 / SI-4', reason: 'Simulation assumption: Agentic SOC detects and closes the public exposure.' };
      }
      return { addressed: false, badge: 'PUBLIC EXPOSURE', reason: action.reason };
    }

    if (action.actionKind === 'valid_credential' || action.actionKind === 'password_spray') {
      if (socEnabled && layerMonitored && soarDetects(targetAsset.id, seed, multiplier)) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOC',
          control: 'NIST SI-4 / AC-3',
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: action.actionKind === 'password_spray'
            ? 'Simulation assumption: Agentic SOC detects password-spray anomaly and locks the target account.'
            : 'Simulation assumption: Agentic SOC detects anomalous credential use and revokes the token.'
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
    const wafRuleMatches = !isNonHttpProtocol && portalCovered && !!rule.waf?.mitigates;
    const wafEvadedByAdaptive = wafRuleMatches && rule.waf?.ruleStrictness === 'signature_regex' && !!attackerProfile?.adaptiveWafEvasion;
    const wafMitigates = wafRuleMatches && !wafEvadedByAdaptive;
    const soarMitigates = layerMonitored && !!rule.ml?.mitigates && soarDetects(targetAsset.id, seed, multiplier);

    if (mode === 'patch') {
      if (isNonHttpProtocol) {
        return { addressed: false, badge: 'WAF BLIND', reason: 'WAF operates at L7 HTTP; blind to non-HTTP protocols.' };
      }
      if (wafEvadedByAdaptive) {
        return { addressed: false, badge: 'WAF EVADED · ADAPTIVE', reason: 'Agentic Observer/Guard re-encoded payload around static signature WAF rule.' };
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

    if (mode === 'defender' || mode === 'soc' || mode === 'soc-canary') {
      if (!layerMonitored) {
        return { addressed: false, badge: 'TELEMETRY GAP', reason: `Infrastructure telemetry blind spot on Layer ${targetAsset.layerIdx + 1}.` };
      }
      if (soarMitigates) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOC',
          control: rule.ml.control,
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: rule.ml.reason
        };
      }
      return {
        addressed: false,
        badge: 'ML MISSED',
        reason: rule.ml?.mitigates ? 'Simulated Agentic SOC detection missed this attack.' : (rule.ml?.reason || 'Activity does not trigger the simulated detection rule.')
      };
    }

    if (mode === 'combined') {
      if (wafMitigates) {
        return { addressed: true, badge: 'SHIELDED · WAF VIRTUAL PATCH', control: rule.waf.control, reason: rule.waf.reason };
      }
      if (soarMitigates) {
        return {
          addressed: true,
          badge: 'CONTAINED · AGENTIC SOC',
          control: rule.ml.control,
          revokeCredentialId: action.credentialUsed ? action.credentialUsed.id : null,
          reason: rule.ml.reason
        };
      }
      return { addressed: false, badge: 'UNADDRESSED', reason: 'The attack bypassed the simulated WAF rule and Agentic SOC detection.' };
    }

    return { addressed: false, badge: 'EXPLOITED', reason: 'Unmitigated.' };
  }

  /**
   * Pure, deterministic, bounded graph traversal and action evaluator.
   */
  function simulateEstate(estate, mode = 'baseline', timing = null) {
    const validation = validateEstate(estate);
    if (!validation.valid) {
      throw new Error(`Invalid estate: ${validation.errors.join('; ')}`);
    }

    const assetById = new Map(estate.assets.map(a => [a.id, a]));
    const orderRank = new Map((estate.actionOrder || []).map((id, idx) => [id, idx]));
    const rankOf = id => (orderRank.has(id) ? orderRank.get(id) : 999999);

    const defensePosture = estate.defensePosture || null;
    const canaryAssets = new Set(
      defensePosture && Array.isArray(defensePosture.decoys)
        ? defensePosture.decoys.map(d => d.assetId).filter(Boolean)
        : estate.assets.filter(a => a.isDecoy).map(a => a.id)
    );
    const canaryAsset = mode === 'combined' && canaryAssets.size === 0
      ? estate.assets
          .filter(a => a.layerIdx === 3 && estate.relationships.some(r => r.targetId === a.id))
          .sort((a, b) => a.id.localeCompare(b.id))[0] || null
      : null;
    if (canaryAsset) canaryAssets.add(canaryAsset.id);

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
    const controls = [];
    const signals = new Map();
    const containedSessions = new Set();
    const sessionHops = new Map();
    const triggeredDecoys = new Set();
    const attackerProfile = timing?.attackerProfile || null;

    function scopeFor(source) {
      let entry = source.id;
      let parent = state.reachedAssets.get(entry)?.sourceId;
      while (parent) {
        entry = parent;
        parent = state.reachedAssets.get(entry)?.sourceId;
      }
      return entry;
    }

    function signal(scope, targetId, source, timeSec, contain = true) {
      if (signals.has(scope)) {
        if (source === 'canary') controls.push({ scope, targetId, source, timeSec, control: 'signal' });
        if (contain) containedSessions.add(scope);
        return;
      }
      if (!contain) {
        controls.push({ scope, targetId, source, timeSec, control: 'signal' });
        return;
      }
      const effectiveAt = timeSec + (timing?.responseDelay ?? 0);
      signals.set(scope, effectiveAt);
      containedSessions.add(scope);
      controls.push(
        { scope, targetId, source, timeSec, control: 'signal' },
        { scope, targetId, source, timeSec: timeSec + (timing?.decisionDelay ?? 0), control: 'decision' },
        { scope, targetId, source, timeSec: effectiveAt, control: 'enforced' }
      );
    }

    function recordTelemetry(source, target, action, scope, timeSec, isCanary) {
      if (!timing) return;
      if (isCanary) {
        if ((mode === 'canaries' || mode === 'soc-canary') && !triggeredDecoys.has(target.id)) {
          triggeredDecoys.add(target.id);
          signal(scope, target.id, 'canary', timeSec, mode === 'soc-canary');
        }
        return;
      }
      if (!timing.respond) return;
      const layerMonitored = !defensePosture?.telemetryLayers || defensePosture.telemetryLayers.includes(target.layerIdx);
      if (!layerMonitored || target.groupId === 'staging-status') return;
      const hops = (sessionHops.get(scope) || 0) + 1;
      sessionHops.set(scope, hops);
      // Cross-boundary sequence correlation triggers on >= 2 monitored hops
      if (hops >= 2 && target.layerIdx >= 1) {
        signal(scope, target.id, 'boundary', timeSec, true);
      }
    }

    let eligibleTransitions = 0;
    let attemptedTransitions = 0;
    let succeededTransitions = 0;
    let blockedTransitions = 0;
    let ineligibleTransitions = 0;
    let truncated = false;
    let dataReached = false;

    function processTransition(sourceAsset, targetAsset, relationship) {
      const isCanaryTarget = canaryAssets.has(targetAsset.id);
      const timeSec = (isCanaryTarget && timing?.canaryDelay != null && targetAsset.layerIdx === 1)
        ? timing.canaryDelay
        : timing?.stageTimes?.[targetAsset.layerIdx];
      const scope = timing ? (sourceAsset ? scopeFor(sourceAsset) : targetAsset.id) : null;
      const transitionKey = `${sourceAsset ? sourceAsset.id : 'EXTERNAL'}->${targetAsset.id}:${relationship ? relationship.id : 'EXT'}`;
      if (visitedTransitions.has(transitionKey)) return false;
      visitedTransitions.add(transitionKey);

      if (scope && containedSessions.has(scope) && (signals.get(scope) ?? Infinity) <= timeSec) {
        attemptedTransitions++;
        blockedTransitions++;
        events.push({
          sourceId: sourceAsset ? sourceAsset.id : null,
          targetId: targetAsset.id,
          relationshipId: relationship ? relationship.id : null,
          finding: null,
          credentialUsed: null,
          technique: null,
          requiredAccess: null,
          reachability: `${sourceAsset ? sourceAsset.label : 'External'} -> ${targetAsset.label}`,
          grantedCapability: null,
          acquiredCredentials: [],
          scope,
          mitigation: {
            addressed: true,
            badge: 'CONTAINED · AGENTIC SOC',
            control: 'NIST SI-4 / AC-3',
            reason: 'Session contained by Agentic SOC before this hop.'
          },
          outcome: 'contained',
          reason: 'Session contained by Agentic SOC before this hop.'
        });
        return false;
      }

      const isCanary = canaryAssets.has(targetAsset.id);
      if ((isCanary || targetAsset.isDecoy) && (!isCanary || (mode !== 'canaries' && mode !== 'soc-canary' && mode !== 'combined'))) {
        return false;
      }
      attemptedTransitions++;
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

      let gainedAccess = false;
      for (const action of distinctActions) {
        const currentReach = state.reachedAssets.get(targetAsset.id);
        if (currentReach && currentReach.capabilities.has(action.yieldsCapability)) {
          continue;
        }

        eligibleTransitions++;
        const mitigation = evaluateDefense(targetAsset, action, mode, estate.seed, isCanary, {
          attackerProfile,
          defensePosture
        });

        if (mitigation.addressed) {
          blockedTransitions++;
          if (mitigation.revokeCredentialId) {
            state.revokedCredentials.add(mitigation.revokeCredentialId);
          }
          if (isCanary && (mode === 'soc-canary' || mode === 'combined')) {
            recordTelemetry(sourceAsset, targetAsset, action, scope, timeSec, true);
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
            ...(scope && { scope }),
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
        const dataCap = (mode === 'baseline' || mode === 'canaries') ? MAX_SUCCESS_PER_LAYER : 1;
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
        gainedAccess = true;
        succeededTransitions++;
        if (!alreadyReached && !isCanary) layerSuccessCount[targetAsset.layerIdx]++;
        if (sourceId && !pairAlreadyCounted) onwardSuccessCount.set(sourceId, srcCount + 1);
        succeededPairs.add(pairBudgetKey);
        if (action.yieldsCapability === 'data_read' && !isCanary) dataReached = true;

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
          ...(scope && { scope }),
          mitigation,
          outcome: isCanary && mode === 'canaries' ? 'alert_only' : 'succeeded',
          reason: mitigation.alertOnly ? mitigation.reason : action.reason
        });
        recordTelemetry(sourceAsset, targetAsset, action, scope, timeSec, isCanary);
      }
      return gainedAccess;
    }

    const entryAssets = estate.assets
      .filter(a => a.layerIdx === 0 && a.isExternalEntry)
      .sort((a, b) => rankOf(a.id) - rankOf(b.id));

    if (attackerProfile?.maxConcurrentBranches) {
      const frontier = entryAssets.map(entry => ({ sourceAsset: null, targetAsset: entry, relationship: null }));
      const maxWaves = attackerProfile.maxConcurrentBranches === 1 ? 40 : 16;
      let wave = 0;
      while (frontier.length > 0 && wave < maxWaves) {
        const batch = frontier.splice(0, attackerProfile.maxConcurrentBranches);
        const discovered = [];
        for (const step of batch) {
          const ok = processTransition(step.sourceAsset, step.targetAsset, step.relationship);
          if (ok && step.targetAsset.layerIdx < 3) {
            const outRels = estate.relationships
              .filter(r => r.sourceId === step.targetAsset.id)
              .sort((a, b) => rankOf(a.targetId) - rankOf(b.targetId));
            for (const rel of outRels) {
              const tgt = assetById.get(rel.targetId);
              if (tgt) discovered.push({ sourceAsset: step.targetAsset, targetAsset: tgt, relationship: rel });
            }
          }
        }
        if (attackerProfile.maxConcurrentBranches === 1) {
          frontier.unshift(...discovered);
        } else {
          frontier.push(...discovered);
        }
        wave++;
      }
      if (frontier.length > 0 && !dataReached) truncated = true;
    } else {
      // Layer 0 external entries
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
      controls,
      summary: {
        layerSuccessCounts: layerSuccessCount,
        eligibleTransitions,
        attemptedTransitions,
        succeededTransitions,
        blockedTransitions,
        ineligibleTransitions,
        containedSessions: containedSessions.size,
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

  function seedVerifiedPath(assets, relationships, preferredIngress, rng, findings, credentials, addCveFindingForAsset, assignCredentialOnSource) {
    const byId = new Map(assets.map(asset => [asset.id, asset]));
    const bySource = new Map();
    for (const link of relationships) {
      if (!bySource.has(link.sourceId)) bySource.set(link.sourceId, []);
      bySource.get(link.sourceId).push(link);
    }

    function findRoute(asset, incoming = null) {
      const stage = { asset, link: incoming };
      if (asset.layerIdx === 3) return [stage];
      for (const link of shuffleWithRng(bySource.get(asset.id) || [], rng)) {
        const next = byId.get(link.targetId);
        if (next.layerIdx !== asset.layerIdx + 1) continue;
        const tail = findRoute(next, link);
        if (tail) return [stage, ...tail];
      }
      return null;
    }

    const startingPoints = shuffleWithRng(assets.filter(asset => asset.isExternalEntry && asset.groupId !== 'support-diagnostics'), rng);
    startingPoints.sort((a, b) => Number(b.groupId === preferredIngress) - Number(a.groupId === preferredIngress));
    let route;
    for (const start of startingPoints) {
      route = findRoute(start);
      if (route) break;
    }
    if (!route) return [];

    const [s0, s1, s2, s3] = route;
    const fromLogs = rng() < 0.25;
    let cap0 = 'app_exec';

    if (fromLogs) {
      if (!findings.some(f => f.assetId === s0.asset.id)) {
        findings.push({
          id: `finding-${s0.asset.id}-logs`,
          assetId: s0.asset.id,
          kind: 'anonymous_access',
          inKev: false,
          provenance: 'synthetic_assumption',
          technique: 'T1552.001',
          title: 'Credential exposed in sample logs',
          description: 'Exposed diagnostics/application logs contain a synthetic service token.',
          yieldsCapability: 'file_read'
        });
      }
      cap0 = findings.find(f => f.assetId === s0.asset.id)?.yieldsCapability || 'file_read';
      s1.link.requiredSourceCapability = cap0;
      credentials.push({
        id: `cred-path-${s0.asset.id}-to-${s1.asset.id}`,
        kind: 'api_token',
        label: `Synthetic token from ${s0.asset.label}`,
        scope: 'authenticate',
        permissions: ['authenticate'],
        targetGroupIds: [],
        targetAssetIds: [s1.asset.id],
        audience: s1.asset.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: s0.asset.id,
        requiredSourceCapability: cap0
      });
    } else {
      if (!findings.some(f => f.assetId === s0.asset.id)) {
        if (!addCveFindingForAsset(s0.asset)) {
          findings.push({
            id: `finding-${s0.asset.id}-edge`,
            assetId: s0.asset.id,
            kind: 'anonymous_access',
            inKev: false,
            provenance: 'synthetic_assumption',
            technique: 'T1190',
            title: 'Exposed edge service',
            description: 'External interface permits unauthenticated access.',
            yieldsCapability: 'app_exec'
          });
        }
      }
      cap0 = findings.find(f => f.assetId === s0.asset.id)?.yieldsCapability || 'app_exec';
      s1.link.requiredSourceCapability = cap0;
      if (cap0 === 'file_read' && !credentials.some(c => c.sourceAssetId === s0.asset.id && c.targetAssetIds?.includes(s1.asset.id))) {
        credentials.push({
          id: `cred-path-${s0.asset.id}-to-${s1.asset.id}`,
          kind: 'api_token',
          label: `Token disclosed via ${s0.asset.label}`,
          scope: 'authenticate',
          permissions: ['authenticate'],
          targetGroupIds: [],
          targetAssetIds: [s1.asset.id],
          audience: s1.asset.id,
          revoked: false,
          expired: false,
          mfaRequired: false,
          sourceAssetId: s0.asset.id,
          requiredSourceCapability: 'file_read'
        });
      }
    }

    // Layer 1
    let cap1 = 'account_session';
    if (cap0 === 'app_exec' && !fromLogs) {
      if (!findings.some(f => f.assetId === s1.asset.id)) {
        addCveFindingForAsset(s1.asset);
      }
      const f1 = findings.find(f => f.assetId === s1.asset.id);
      if (f1 && (!f1.requiredInterface || f1.requiredInterface === s1.link.protocol)) {
        cap1 = f1.yieldsCapability || 'app_exec';
      } else {
        assignCredentialOnSource(s0.asset, s1.asset, 'authenticate', cap0);
        cap1 = 'account_session';
      }
    } else {
      cap1 = 'account_session';
    }
    s2.link.requiredSourceCapability = cap1;

    // Layer 2
    let cap2 = 'app_exec';
    if (!findings.some(f => f.assetId === s2.asset.id)) {
      addCveFindingForAsset(s2.asset);
    }
    const f2 = findings.find(f => f.assetId === s2.asset.id);
    if (f2 && (!f2.requiredInterface || f2.requiredInterface === s2.link.protocol)) {
      cap2 = f2.yieldsCapability || 'app_exec';
    } else {
      assignCredentialOnSource(s1.asset, s2.asset, 'authenticate', cap1);
      cap2 = 'account_session';
    }
    s3.link.requiredSourceCapability = cap2;

    // Layer 3 (85% complete path to protected data, 15% stop at Layer 2)
    if (rng() < 0.85) {
      if (!findings.some(f => f.assetId === s3.asset.id) && !addCveFindingForAsset(s3.asset)) {
        assignCredentialOnSource(s2.asset, s3.asset, 'read', cap2);
      } else if (!findings.some(f => f.assetId === s3.asset.id && (!f.requiredInterface || f.requiredInterface === s3.link.protocol))) {
        assignCredentialOnSource(s2.asset, s3.asset, 'read', cap2);
      }
    }

    return route.map(stage => stage.asset.id);
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
    const edgePool = Object.keys(EDGE_APPLIANCES);
    const applianceCount = randInt(5, 7);
    const preferredIngress = options.preferredIngress;
    const pinned = preset === 'demo' ? ['f5-gateway']
      : preset === 'mixed' && edgePool.includes(preferredIngress) ? [preferredIngress] : [];
    const selectedAppliances = new Set([
      ...pinned,
      ...shuffleWithRng(edgePool.filter(id => !pinned.includes(id)), rng).slice(0, applianceCount - pinned.length)
    ]);
    const ingressBudget = LAYER_FINDING_BUDGETS[0];
    const hasAdditionalOpening = preset === 'mixed' && randInt(ingressBudget.min, ingressBudget.max) === ingressBudget.max;
    const edgeMisconfig = hasAdditionalOpening
      ? EDGE_MISCONFIGURATIONS[randInt(0, EDGE_MISCONFIGURATIONS.length - 1)]
      : null;

    const assets = [];
    LAYER_CONFIG.forEach((layer, layerIdx) => {
      const numClusters = layer.clusters.length;
      layer.clusters.forEach((cluster, clusterIdx) => {
        const targets = cluster.targets.filter(target =>
          (!target.preset || target.preset === preset) &&
          (target.id !== 'external-misconfig' || edgeMisconfig) &&
          (!EDGE_APPLIANCES[target.id] || selectedAppliances.has(target.id)));
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
            const misconfig = targetDef.id === 'external-misconfig' ? edgeMisconfig : null;
            const label = misconfig?.asset || targetDef.variants[vIdx];
            const familyAngle = (targetIdx / numTargets) * Math.PI * 2 - Math.PI / 2 + rand(-0.08, 0.08);
            const clusterCenterX = (layer.xBand[0] + (layer.xBand[1] - layer.xBand[0]) * 0.5) + rand(-0.02, 0.02);
            const clusterCenterY = (clusterIdx + 0.5) / numClusters + rand(-0.025, 0.025);
            const ox = instanceCount === 2 ? (slot === 0 ? -0.015 : 0.015) : instanceCount === 3 ? Math.cos((slot / 3) * Math.PI * 2) * 0.018 : 0;
            const oy = instanceCount === 2 ? (slot === 0 ? -0.02 : 0.02) : instanceCount === 3 ? Math.sin((slot / 3) * Math.PI * 2) * 0.022 : 0;
            const x = Math.max(0.04, Math.min(0.95, clusterCenterX + Math.cos(familyAngle) * 0.045 + ox));
            const y = Math.max(0.05, Math.min(0.95, clusterCenterY + Math.sin(familyAngle) * 0.065 + oy));
            const reviewed = REVIEWED_EXAMPLES[targetDef.id];
            const appliance = EDGE_APPLIANCES[targetDef.id];

            assets.push({
              id: `${targetDef.id}-${vIdx + 1}`,
              groupId: targetDef.id,
              label,
              product: reviewed?.product || label,
              assumedVersion: appliance ? null : reviewed?.version || null,
              conditions: appliance ? {} : { ...reviewed?.conditions },
              ...(appliance && { referenceCve: appliance.cve }),
              layerIdx,
              trustZone: TRUST_ZONES[layerIdx],
              interfaces: [...(misconfig?.interfaces || targetDef.interfaces || ['https'])],
              auth: targetDef.publicExposure || (misconfig && !misconfig.assumedAccount) ? 'none' : 'token',
              isExternalEntry: EXTERNAL_ENTRY_GROUPS.has(targetDef.id),
              isSecurity: !!targetDef.isSecurity,
              isLake: !!targetDef.isLake,
              isDb: !!targetDef.isDb,
              icon: misconfig?.icon || targetDef.icon,
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
      if (asset.referenceCve) {
        asset.assumedVersion = reviewed.version;
        Object.assign(asset.conditions, reviewed.conditions);
      }
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

    const assignCredentialOnSource = (srcAsset, targetAsset, scope = 'read', requiredSourceCapability = 'app_exec') => {
      const credId = `cred-${srcAsset.id}-to-${targetAsset.id}`;
      if (credentials.some(c => c.id === credId)) return;
      const permissions = scope === 'read' ? ['read'] : scope === 'authenticate' ? ['authenticate'] : [scope];
      credentials.push({
        id: credId,
        kind: targetAsset.layerIdx === 3 ? 'db_credential' : 'service_account',
        label: `Synthetic ${scope} credential for ${targetAsset.groupId}`,
        scope,
        permissions,
        targetGroupIds: [],
        targetAssetIds: [targetAsset.id],
        audience: targetAsset.id,
        revoked: false,
        expired: false,
        mfaRequired: false,
        sourceAssetId: srcAsset.id,
        requiredSourceCapability
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

      const edgeAppliances = shuffleWithRng(keptAssets.filter(asset => asset.referenceCve), rng);
      addCveFindingForAsset(edgeAppliances[0]);
      if (edgeMisconfig) {
        const { id } = keptAssets.find(asset => asset.groupId === 'external-misconfig');
        const logToken = edgeMisconfig.illustration === 'git-to-idp';
        findings.push({
          id: `finding-${edgeMisconfig.id}`,
          assetId: id,
          kind: edgeMisconfig.assumedAccount ? 'assumed_edge_account' : 'anonymous_access',
          category: 'external_misconfiguration',
          title: edgeMisconfig.title,
          description: logToken
            ? 'The exposed synthetic logs contain a Git token.'
            : 'The scenario records access to the exposed edge service only.',
          ...(logToken && { illustration: edgeMisconfig.illustration }),
          historicalReference: edgeMisconfig.reference,
          sourceUrl: edgeMisconfig.source,
          sourceReviewed: '2026-11-15',
          provenance: 'synthetic_assumption',
          technique: logToken ? 'T1552.001' : edgeMisconfig.assumedAccount ? 'T1078' : null,
          yieldsCapability: logToken ? 'file_read' : 'edge_access'
        });
        if (edgeMisconfig.assumedAccount) {
          credentials.push({
            id: 'mixed-external-example',
            kind: 'account',
            label: 'Synthetic edge-only account',
            scope: 'authenticate to this edge service',
            permissions: ['authenticate'],
            targetAssetIds: [id],
            audience: id,
            sourceAssetId: id,
            startingAccess: true
          });
        }
      }

      for (let layerIdx = 1; layerIdx < 4; layerIdx++) {
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
    }

    const actionOrder = shuffleWithRng(keptAssets.map(a => a.id), rng);
    if (diagnostics) {
      actionOrder.splice(actionOrder.indexOf(diagnostics.id), 1);
      actionOrder.unshift(diagnostics.id);
    }
    if (preset === 'mixed' && options.seedExercise) {
      const priority = seedVerifiedPath(keptAssets, keptRels, preferredIngress, rng, findings, credentials, addCveFindingForAsset, assignCredentialOnSource);
      actionOrder.splice(0, actionOrder.length, ...priority, ...actionOrder.filter(id => !priority.includes(id)));
    }

    // Estate-owned defensive visibility & decoy placement (invariant across attacker switches)
    const telemetryLayers = rng() < 0.75 ? [0, 1, 2, 3] : [1, 2, 3];
    const decoys = [];
    const decoyAnchor = (preset === 'demo' && keptAssets.find(a => a.layerIdx === 0 && a.groupId === 'f5-gateway')) ||
      keptAssets.find(a => a.layerIdx === 0 && a.isExternalEntry && findings.some(f => f.assetId === a.id && f.yieldsCapability)) ||
      keptAssets.find(a => a.layerIdx === 1 && a.groupId !== 'staging-status');
    if ((preset === 'mixed' || preset === 'demo') && decoyAnchor) {
      const decoyLayer = decoyAnchor.layerIdx + 1;
      const decoyId = 'canary-decoy-1';
      keptAssets.push({
        id: decoyId,
        groupId: decoyLayer === 3 ? 'lake-cust' : 'comp-registry',
        label: 'Canary Decoy Vault',
        product: 'Instrumented Decoy',
        assumedVersion: '1.0',
        conditions: {},
        layerIdx: decoyLayer,
        trustZone: TRUST_ZONES[decoyLayer],
        interfaces: ['api-https', 'https'],
        auth: 'token',
        isExternalEntry: false,
        isSecurity: true,
        isDecoy: true,
        icon: 'threat-detection.png',
        clusterName: 'Deception Decoys',
        variantIdx: 0,
        x: decoyLayer === 1 ? 0.34 : decoyLayer === 3 ? 0.84 : 0.62,
        y: 0.90
      });
      const anchorCap = findings.find(f => f.assetId === decoyAnchor.id)?.yieldsCapability || 'app_exec';
      const relCap = anchorCap === 'file_read' ? 'account_session' : anchorCap;
      keptRels.push({
        id: `rel-${decoyAnchor.id}->${decoyId}`,
        sourceId: decoyAnchor.id,
        targetId: decoyId,
        protocol: 'api-https',
        direction: 'outbound',
        requiredSourceCapability: relCap,
        trustBoundary: inferTrustBoundary(decoyAnchor.layerIdx, decoyLayer),
        purpose: 'Instrumented canary decoy endpoint'
      });
      findings.push({
        id: `finding-${decoyId}`,
        assetId: decoyId,
        kind: 'anonymous_access',
        inKev: false,
        provenance: 'synthetic_decoy',
        technique: 'T1552',
        title: 'Canary decoy interaction',
        description: 'Instrumented decoy triggers high-confidence deception alert on access.',
        yieldsCapability: 'decoy_alert'
      });
      decoys.push({
        id: decoyId,
        kind: 'decoy_asset',
        assetId: decoyId,
        credentialId: null,
        placement: decoyLayer <= 2 ? 'early' : 'late'
      });
      actionOrder.unshift(decoyId);
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
      defensePosture: {
        telemetryLayers,
        socCoverageSeed: seed,
        decoys
      },
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

  // Resolve one predeclared service flow for display. Findings and the runner
  // do not use this reference context.
  function referenceServiceFlow(estate, groups) {
    const assets = [];
    const relationships = [];
    const byId = new Map(estate.assets.map(asset => [asset.id, asset]));
    let asset = estate.assets.find(node => node.layerIdx === 0 && node.groupId === groups[0]);
    for (const group of groups.slice(1)) {
      if (!asset) return null;
      assets.push(asset.id);
      const relationship = estate.relationships.find(link => link.sourceId === asset.id &&
        byId.get(link.targetId)?.groupId === group);
      if (!relationship) return null;
      relationships.push(relationship.id);
      asset = byId.get(relationship.targetId);
    }
    if (!asset) return null;
    assets.push(asset.id);
    return { assets, relationships };
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
    combined: { id: 'combined', label: 'Defense in Depth', shortLabel: 'DEFENSE IN DEPTH' }
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

  // Fixed timestamps for the authored comparison fixtures below.
  const TIMING_RACE = {
    pre2023: { decoyTime: 10 * 60, boundaryTime: 75 * 60, lateralTime: 90 * 60, protectedReadTime: 105 * 60 },
    artex: { decoyTime: 2 * 60, boundaryTime: 14 * 60 + 45, lateralTime: 15 * 60, protectedReadTime: 15 * 60 + 35 }
  };

  const ATTACKER_PROFILES = {
    pre2023: {
      id: 'pre2023',
      maxConcurrentBranches: 1,
      adaptiveWafEvasion: false,
      detectionMultiplier: 1.0
    },
    artex: {
      id: 'artex',
      maxConcurrentBranches: 3,
      adaptiveWafEvasion: true,
      detectionMultiplier: 0.72
    }
  };

  // Names identify scenario examples. Pace selects the capability profile;
  // boundary telemetry and decoy placement come from estate.defensePosture.
  const WIRE_ATTACKERS = {
    lockbit: { pace: 'pre2023' },
    conti: { pace: 'pre2023' },
    blackcat: { pace: 'pre2023' },
    hive: { pace: 'pre2023' },
    revil: { pace: 'pre2023' },
    artex: { pace: 'artex' }
  };

  const WIRE_READ_MINUTES = {
    pre2023: { min: 80, max: 270 },
    artex: { min: 45, max: 75 }
  };

  function wireTiming(seed, pace) {
    const { min, max } = WIRE_READ_MINUTES[pace];
    const draw = hashNode(seed, `wire-timing:${pace}`, 0x9e3779b9);
    const readTime = (min + Math.floor(draw * (max - min + 1))) * 60;

    if (pace === 'artex') {
      // Vary the time before the final burst and keep its short gaps for the SOAR exercise.
      return { stageTimes: [0, readTime - 50, readTime - 35, readTime], earlyCanaryDelay: 120 };
    }

    // Preserve the proportions of the original 10/75/90/105-minute milestones.
    return {
      stageTimes: [0, Math.round(readTime * 75 / 105), Math.round(readTime * 90 / 105), readTime],
      earlyCanaryDelay: Math.round(readTime * 10 / 105)
    };
  }

  function simulateWireRun(estate, mode, attackerId) {
    const attacker = WIRE_ATTACKERS[attackerId];
    if (!attacker) throw new Error(`Unknown Wire attacker: ${attackerId}`);
    const attackerProfile = ATTACKER_PROFILES[attacker.pace] || ATTACKER_PROFILES.pre2023;
    const posture = estate.defensePosture || { telemetryLayers: [0, 1, 2], decoys: [] };
    const { stageTimes, earlyCanaryDelay } = wireTiming(estate.seed, attacker.pace);
    const result = simulateEstate(estate, mode, {
      stageTimes,
      respond: mode === 'soc' || mode === 'soc-canary',
      boundarySignal: posture.telemetryLayers.length >= 3 ? 'all' : (posture.telemetryLayers.length ? 'first' : 'none'),
      canary: (mode === 'canaries' || mode === 'soc-canary') ? (posture.decoys && posture.decoys.length ? 'early' : 'untouched') : null,
      canaryDelay: earlyCanaryDelay,
      decisionDelay: 15,
      responseDelay: 60,
      attackerProfile
    });
    const layerById = new Map(estate.assets.map(asset => [asset.id, asset.layerIdx]));
    const decoyIds = new Set(estate.assets.filter(a => a.isDecoy).map(a => a.id));
    const events = result.events.map(event => {
      const layer = layerById.get(event.targetId);
      const timeSec = (decoyIds.has(event.targetId) && layer === 1)
        ? earlyCanaryDelay
        : stageTimes[layer];
      return { ...event, timeSec };
    });
    return { ...result, events, lanes: attackerProfile.maxConcurrentBranches, attackerProfile };
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
        pre2023: buildSpeedEvents(TIMING_RACE.pre2023),
        artex: buildSpeedEvents(TIMING_RACE.artex)
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
        pre2023: buildSpeedEvents({ ...TIMING_RACE.pre2023, patchCovered: true }),
        artex: buildSpeedEvents({ ...TIMING_RACE.artex, patchCovered: true })
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
    const useVirtualPatch = defenseId === 'patch' || (defenseId === 'combined' && options.combineVirtualPatch);
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
    } else if (edgeBlockedTimeSec !== null) {
      effectiveControlTimeSec = edgeBlockedTimeSec;
      controlReason = 'RULE MATCH · BLOCKED AT EDGE';
    } else if (defenseId === 'patch') {
      controlReason = 'OUTSIDE RULE COVERAGE';
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
    ATTACKER_PROFILES,
    WIRE_ATTACKERS,
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
    simulateWireRun,
    generateEstate,
    referenceServiceFlow,
    migrateSnapshot
  };
}));
