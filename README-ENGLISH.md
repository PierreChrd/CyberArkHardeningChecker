

<div align="center">

# 🔐 CyberArk Hardening Checker (English)
### *An extensible hardening validation engine for CyberArk servers*

![cyberark](https://img.shields.io/badge/CyberArk-Hardening%20Toolkit-0a74da?logo=cyberark&logoColor=white)
![powershell](https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell)
![license](https://img.shields.io/badge/License-MIT-green)
![MadeInFrance](https://img.shields.io/badge/Made_in-🟦⬜🟥-ffffff)

</div>

---

## 📖 About

**CyberArk Hardening Checker** is a modular engine that automatically verifies compliance and hardening of various CyberArk components:

- 🟦 **Windows / System Baseline**  
- 🟩 **PVWA**  
- 🟧 **CPM**  
- 🟨 **PSM**  
- 🟪 **Vault**

It automates checks based on:
- CyberArk hardening scripts  
- Windows Server best practices  
- SCHANNEL, IIS, RDP, and AppLocker cryptographic recommendations  

All rules are **versionable JSON files**, easy to maintain and extend.

---

## 📚 Rule Documentation

➡️ **See the complete rule documentation: RULES.md**

Each rule is a simple self-contained file like this:

```json
{
  "id": "CPM-001",
  "title": "CPM service running",
  "description": "Central Policy Manager service running",
  "type": "service",
  "appliesTo": ["CPM"],
  "severity": "critical",
  "serviceName": "CyberArk Central Policy Manager",
  "expectedStatus": "Running",
  "tags": ["cpm"]
}
```

---

## 📂 Project Structure

```
CyberArkHardeningChecker/
├── src/
│   ├── HardeningChecker.ps1     # Main script
│   └── RuleEngine.psm1          # Rule engine
├── rules/
│   ├── WINDOWS/
│   ├── PVWA/
│   ├── CPM/
│   ├── PSM/
│   └── VAULT/
├── LICENSE
├── RULES.md
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the project
```powershell
git clone https://github.com/PierreChrd/CyberArkHardeningChecker.git
cd CyberArkHardeningChecker/src
```

### 2. Unblock files (Windows ADS)
```powershell
Get-ChildItem -Recurse | Unblock-File
```

### 3. If your machine blocks script execution
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\HardeningChecker.ps1
```

---

## ▶️ Usage

### 🔹 Check server hardening
```powershell
./HardeningChecker.ps1 -Output Html,Json
```

### 🔹 List all rules
```powershell
./HardeningChecker.ps1 -ListRules
```

### 🔹 Export rule list to CSV
```powershell
./HardeningChecker.ps1 -ListRulesCsv "./rules.csv"
```

### 🔹 Check a specific component
```powershell
./HardeningChecker.ps1 -ComponentProfile PSM
```

### 🔹 Filter by tags
```powershell
./HardeningChecker.ps1 -IncludeTags tls,rdp
```

---

## 🧩 Supported Rule Types

| Type | Description |
|------|-------------|
| `service` | Checks the status of a Windows service (Running/Stopped) |
| `registry` | Checks a registry value (SCHANNEL, RDP, LSA…) |
| `command` | Executes a PowerShell expression returning True/False |
| `iisBinding` | Validates presence of an IIS binding (HTTPS) |
| `iisAppPool` | Checks status of an AppPool |
| `port` | Verifies that a local port is open |

---

## 📊 Example HTML Report

```
[ GLOBAL SCORE : 89% ]
- 8 critical rules OK
- 2 critical rules FAIL
- 12 medium rules OK
- 4 rules skipped (not applicable)
```

---

## 🤝 Contribution

Contributions are welcome:  
✔️ new rules  
✔️ engine optimizations  
✔️ documentation  

Please follow the structure:
- one rule = one JSON file  
- unique ID (CPM-XXX / PVWA-XXX, etc.)  
- relevant tags  
- consistent severity  

---

## 📝 License
Project under the **MIT** license.

---

✨ Created by Pierre Chaussard — to automate CyberArk hardening.