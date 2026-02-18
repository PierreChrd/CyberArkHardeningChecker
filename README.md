
<div align="center">

# 🔐 CyberArk Hardening Checker  
### *Un moteur extensible de vérification de durcissement pour les serveurs CyberArk*

![cyberark](https://img.shields.io/badge/CyberArk-Hardening%20Toolkit-0a74da?logo=cyberark&logoColor=white)
![powershell](https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell)
![license](https://img.shields.io/badge/License-MIT-green)
![MadeInFrance](https://img.shields.io/badge/Made_in-🟦⬜🟥-ffffff)

</div>

---

####  *🇺🇸 🇬🇧 English Version [README-ENGLISH.md](./README-ENGLISH.md)*

---

## 📖 À propos

**CyberArk Hardening Checker** est un moteur modulaire permettant de vérifier automatiquement la conformité et le durcissement des différents composants CyberArk :

- 🟦 **Windows / Baseline Systèmes**  
- 🟩 **PVWA**  
- 🟧 **CPM**  
- 🟨 **PSM**  
- 🟪 **Vault**

Il permet d’automatiser les vérifications issues :
- des scripts de hardening CyberArk,  
- des bonnes pratiques Windows Server,  
- des recommandations cryptographiques SCHANNEL, IIS, RDP, AppLocker.

Toutes les règles sont sous forme **JSON versionnables**, faciles à maintenir et à enrichir.

---

## 📚 Documentation des règles

➡️ **Voir la documentation complète des règles : [RULES.md](./RULES.md)**

Chaque règle est un fichier simple et autonome comme :

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

## 📂 Architecture du projet

```
CyberArkHardeningChecker/
├── src/
│   ├── HardeningChecker.ps1     # Script principal
│   └── RuleEngine.psm1          # Moteur de règles
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

### 1. Cloner le projet
```powershell
git clone https://github.com/PierreChrd/CyberArkHardeningChecker.git
cd CyberArkHardeningChecker/src
```

### 2. Débloquer les fichiers (Windows ADS)
```powershell
Get-ChildItem -Recurse | Unblock-File
```

### 3. Si ton poste bloque les scripts
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\HardeningChecker.ps1
```

---

## ▶️ Utilisation

### 🔹 Vérifier le durcissement du serveur
```powershell
./HardeningChecker.ps1 -Output Html,Json
```

### 🔹 Lister toutes les règles
```powershell
./HardeningChecker.ps1 -ListRules
```

### 🔹 Exporter la liste des règles en CSV
```powershell
./HardeningChecker.ps1 -ListRulesCsv "./rules.csv"
```

### 🔹 Vérifier un composant spécifique
```powershell
./HardeningChecker.ps1 -ComponentProfile PSM
```

### 🔹 Filtrer par tags
```powershell
./HardeningChecker.ps1 -IncludeTags tls,rdp
```

---

## 🧩 Types de règles supportés

| Type | Description |
|------|-------------|
| `service` | Vérifie état d’un service Windows (Running/Stopped) |
| `registry` | Vérifie une valeur de registre (SCHANNEL, RDP, LSA…) |
| `command` | Exécute une expression PowerShell retournant True/False |
| `iisBinding` | Vérifie présence d’un binding IIS (HTTPS) |
| `iisAppPool` | Vérifie l’état d’un AppPool |
| `port` | Vérifie qu’un port est ouvert localement |

---

## 📊 Exemple de rapport HTML

*(Section en travaux)*

```
[ SCORE GLOBAL : 89% ]
- 8 règles critiques OK
- 2 règles critiques FAIL
- 12 règles medium OK
- 4 règles skipped (non applicables)
```

---

## 🤝 Contribution

Les contributions sont les bienvenues :  
✔️ nouvelles rules  
✔️ optimisations du moteur  
✔️ documentation  

Merci de respecter la structure :
- une règle = un fichier JSON  
- ID unique (CPM-XXX / PVWA-XXX, etc.)  
- tags pertinents  
- severité cohérente  

---

## 📝 Licence
Projet sous licence **MIT**.

---

✨ Créé par Pierre Chaussard — pour automatiser le durcissement CyberArk.
