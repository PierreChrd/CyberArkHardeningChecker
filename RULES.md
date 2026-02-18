# CyberArk Hardening Rules Reference

Ce document liste l’ensemble des règles de durcissement disponibles dans le projet, organisées par composant.

Chaque règle est définie selon le format commun :
- **id** : identifiant unique
- **title** : nom court de la règle
- **description** : description fonctionnelle
- **type** : service / registry / command / iisBinding / iisAppPool / port
- **severity** : criticité
- **tags** : classification utile pour filtrage


---

# 🟦 WINDOWS Rules

| ID | Title | Description | Type | Severity | Tags |
|----|--------|-------------|-------|----------|-------|
| WIN-001 | ImportingINFConfiguration | Importing an INF File to the Local Machine | command | medium | cross,inf |
| WIN-002 | ValidateServerRoles | Checks for unnecessary roles | command | medium | cross,roles |
| WIN-003 | EnableScreenSaver | Checks if the screen saver is disabled | command | low | cross,ux |
| WIN-004 | AdvancedAuditPolicyConfiguration | Advanced Audit Policy Configuration | command | high | cross,audit |
| WIN-005 | RemoteDesktopServices | Check Remote Desktop Services settings | command | high | cross,rdp |
| WIN-006 | EventLogSizeAndRetention | Check Event Log and Retention settings | command | medium | cross,eventlog |
| WIN-007 | RegistryAudits | Check Registry Audits access control | command | medium | cross,registry,audit |
| WIN-008 | RegistryPermissions | Check Registry permissions | command | medium | cross,registry,acl |
| WIN-009 | FileSystemPermissions | Validate ACLs on SYSTEM32\Config | command | high | cross,filesystem,acl |
| WIN-010 | FileSystemAudit | Validate audit rules on SYSTEM32\Config | command | medium | cross,filesystem,audit |
| WIN-011 → WIN-017 | DisableService_* | Ensure Windows services are disabled | service | high | cross,services |
| WIN-018 | TLS_1-2_Enabled | Ensure TLS 1.2 is enabled | registry | high | tls,schannel |
| WIN-019 | TLS_1-0_Disabled | Disable TLS 1.0 | registry | high | tls,schannel |
| WIN-020 | PowerShell >= 5 | Minimum PSVersion 5 | command | medium | runtime |
| WIN-021 | Windows Firewall Enabled | Domain firewall profile enabled | command | low | firewall |
| WIN-022 | RDP_Requires_NLA | NLA must be enabled | registry | high | rdp,nla |
| WIN-023 | RDP Encryption Level >=3 | Strong RDP encryption | registry | high | rdp |
| WIN-024 | SMBv1 Disabled | Disable SMBv1 | registry | high | smb |
| WIN-025 | UAC Enabled | UAC must be enabled | registry | medium | uac |
| WIN-026 | Disable_Local_Administrator | Local admin disabled | command | high | windows,account |
| WIN-027 | Disable_NetBIOS | NetBIOS disabled | command | medium | network |
| WIN-028 | LSA_Protection | RunAsPPL must be enabled | registry | high | lsa,security |
| WIN-029 | Disable_TLS1-1 | TLS 1.1 disabled | registry | high | tls,schannel |
| WIN-030 | Disable_RC4_Ciphers | RC4 cipher suites disabled | command | high | tls,cipher |


---

# 🟩 PVWA Rules

| ID | Title | Description | Type | Severity | Tags |
|----|--------|-------------|-------|----------|-------|
| PVWA-001 | PVWA_ScheduledTasks_Running | Scheduled Tasks service running | service | high | pvwa,service |
| PVWA-002 | PVWA_WAS_Running | WAS must be running | service | critical | pvwa,iis |
| PVWA-003 | PVWA_W3SVC_Running | WWW Publishing Service running | service | critical | pvwa,iis |
| PVWA-004 | PVWA_IIS_MimeTypes | Validate MIME types | command | low | pvwa,iis,mime |
| PVWA-005 | PVWA_AnonymousAuthentication | Anonymous Auth disabled | command | high | pvwa,iis,auth |
| PVWA-006 | PVWA_DirectoryBrowsing | Directory browsing disabled | command | high | pvwa,iis |
| PVWA-007 | PVWA_IIS_SSL_TLS_Settings | SSL/TLS binding check | command | critical | pvwa,iis,tls |
| PVWA-008 | PVWA_IIS_Cypher_Suites | Weak cipher suites disabled | command | critical | pvwa,cipher |
| PVWA-009 | PVWA_Scheduled_Task_Service_LocalUser | Maintenance task exists | command | medium | pvwa,task |
| PVWA-010 | PVWA_NonSystemDrive | PVWA not on system drive | command | medium | pvwa,filesystem |
| PVWA-011 | PVWA_IIS_Hardening | IIS requestFiltering check | command | medium | pvwa,iis,hardening |
| PVWA-012 | PVWA_AdditionalAppPool | AppPool state validation | command | high | pvwa,iis,apppool |
| PVWA-013 | PVWA_CredFileHardening | Web.config ACL must be strict | command | high | pvwa,file |
| PVWA-014 | PVWA_IIS_Registry_Shares | Disable admin shares | command | medium | pvwa,shares |
| PVWA-015 | PVWA_IIS_WebDAV | WebDAV must be disabled | command | high | pvwa,iis,webdav |
| PVWA-016 | PVWA_Cryptography_Settings | Cryptography mode settings | command | high | pvwa,tls |
| PVWA-017 | PVWA_AppPool_Running | PVWAAppPool must be running | iisAppPool | high | pvwa,iis |
| PVWA-018 | PVWA_HTTPS_Binding_Present | HTTPS binding must exist | iisBinding | critical | pvwa,iis,tls |
| PVWA-019 | IIS_Role_Installed | IIS Web-Server must be present | command | high | pvwa,iis |
| PVWA-020 | PVWA_HTTPS_Port_Open_Locally | 443 must be open | port | medium | pvwa,port |
| PVWA-021 | No_HTTP_Binding | No HTTP binding allowed | command | critical | pvwa,iis,tls |
| PVWA-022 | AppPool_NoManagedCode | AppPool runs in No Managed Code | command | high | pvwa,iis |
| PVWA-023 | AppPool_IdleTimeout_Disabled | IdleTimeout = 0 | command | medium | pvwa,iis |
| PVWA-024 | Disable_DynamicCompression | Disable dynamic compression | command | medium | pvwa,iis,compression |


---

# 🟧 CPM Rules

| ID | Title | Description | Type | Severity | Tags |
|----|--------|-------------|-------|----------|-------|
| CPM-001 | CPM_Scanner_Running | CPM Scanner must be running | service | critical | cpm,service |
| CPM-002 | CPM_PasswordManager_Running | Password Manager running | service | critical | cpm,service |
| CPM-003 | CPM_PasswordManager_Start_Type_Automatic | Password Manager start type | service | high | cpm |
| CPM-004 | CPM_CredFileHardening | Credential file hardening | command | high | cpm,file |
| CPM-005 | CPM_EnableFIPSCryptography | FIPS enablement | registry | high | cpm,fips |
| CPM-006 | CPM_DisableDEPForExecutables | Disable DEP | command | medium | cpm,dep |
| CPM-007 | PasswordManagerUser_NoExpiration | PasswordManagerUser account must not expire | command | high | cpm,account |
| CPM-008 | Logs_Directory_Hardened | Logs folder ACL strict | command | high | cpm,filesystem |
| CPM-009 | CPMScanner_AutomaticStartup | Scanner must start automatically | command | high | cpm,service |


---

# 🟨 PSM Rules

| ID | Title | Description | Type | Severity | Tags |
|----|--------|-------------|-------|----------|-------|
| PSM-001 | PSM_PrivilegedSessionManager_Running | PSM service running | service | critical | psm,service |
| PSM-002 | PSM_RemoteDesktopConfiguration_Running | RDC running | service | high | psm,rdp |
| PSM-003 | PSM_RemoteDesktopManagement_Running | RDM running | service | high | psm,rdp |
| PSM-004 | PSM_RemoteDesktopServices_Running | RDS running | service | critical | psm,rdp |
| PSM-005 | PSM_RemoteAppConnectionManagement_Running | RemoteApp mgmt running | service | medium | psm,rdp |
| PSM-006 | RunApplocker | AppLocker policy exists | command | high | psm,applocker |
| PSM-007 | ConfigureOutOfDomainPSMServer | Out-of-domain config | command | medium | psm,domain |
| PSM-008 | DisableTheScreenSaverForThePSMLocalUsers | Disable screensaver | command | low | psm,ux |
| PSM-009 | HidePSMDrives | Hide drives | command | medium | psm,policy |
| PSM-010 | BlockIETools | Block IE tools | command | medium | psm,browser |
| PSM-011 | HardenRDS | Harden RDS | command | high | psm,rdp |
| PSM-012 | HardenPSMUsersAccess | Harden user access | command | high | psm,acl |
| PSM-013 | HardenSMBServices | Disable SMB1 | command | high | psm,smb |
| PSM-014 | PSM_CredFileHardening | Credfile ACL strict | command | high | psm,file |
| PSM-015 | Disable RDP clipboard redirection | Clipboard disabled | registry | high | psm,rdp |
| PSM-016 | ConfigureUsersForPSMSessions | Config PSM users | command | medium | psm,users |
| PSM-017 | PSMForWebApplications | Support for web apps | command | low | psm,web |
| PSM-018 | EnableUsersToPrintPSMSessions | Printing setting | command | low | psm,policy |
| PSM-019 | SupportWebApplications | Support for web components | command | low | psm,web |
| PSM-020 | ClearRemoteDesktopUsers | Clear RDP Users group | command | high | psm,rdp |
| PSM-021 | PSMConnect_User_Exists | PSMConnect user exists | command | high | psm,account |
| PSM-022 | DFSS_Disabled | DFSS disabled | registry | medium | psm,performance |
| PSM-023 | PSMAdminConnect_Exists | PSMAdminConnect exists | command | high | psm,account |
| PSM-024 | DisconnectedSessionTime_1min | RDP timeout 1 min | registry | medium | psm,rdp |
| PSM-025 | ReconnectionPolicy_OriginOnly | RDP reconnection policy | registry | medium | psm,rdp |
| PSM-026 | AppLocker_Strict | Strict AppLocker policy | command | high | psm,applocker |


---

# 🟪 VAULT Rules

| ID | Title | Description | Type | Severity | Tags |
|----|--------|-------------|-------|----------|-------|
| VAULT-001 | Vault_EventNotificationEngine_Running | ENE running | service | high | vault,service |
| VAULT-002 | Vault_StaticIP | Static IP required | command | critical | vault,network |
| VAULT-003 | Vault_WindowsFirewall | Firewall enabled | command | critical | vault,firewall |
| VAULT-004 | Vault_DomainJoined | Vault must not be domain-joined | command | critical | vault,isolation |
| VAULT-005 | Vault_LogicContainerServiceLocalUser | LogicContainer exists | command | high | vault,account |
| VAULT-006 | Vault_FirewallNonStandardRules | Firewall rules valid | command | medium | vault,firewall |
| VAULT-007 | Vault_ServerCertificate | Certificate present | command | high | vault,cert |
| VAULT-008 | Vault_NICHardening | NIC hardening | command | high | vault,network |
| VAULT-009 | Vault_PARAgent_ConfigExists | PARAgent.ini present | command | medium | vault,config |
| VAULT-010 | Vault_DBKey_Permissions | DBKey ACL strict | command | critical | vault,file |
| VAULT-011 | Vault_No_RDP_Sessions | No RDP sessions | command | critical | vault,rdp |

---
