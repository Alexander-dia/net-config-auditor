# Network Configuration & Security Compliance Auditor

Ett nätverks- och automationsverktyg i Python utvecklat för att auditera, validera och poängsätta nätverkskonfigurationer (t.ex. Cisco IOS/IOS-XE) mot etablerade säkerhetsstandarder (CIS Benchmarks, NIST).

Verktyget analyserar switch- och routerkonfigurationer efter sårbarheter som okrypterad fjärradministration (Telnet, HTTP), svaga lösenords-hashes, saknade VTY-åtkomstlistor (ACL) och osäkra standardinställningar.

---

## 🚀 Funktioner

- **Regelbaserad säkerhetsmotor:** Dynamisk JSON-regeluppsättning (`rules/compliance_rules.json`) med regex-mönstermatchning för obligatoriska och förbjudna konfigurationsrader.
- **Risk- och allvarlighetsbedömning:** Kategoriserar sårbarheter efter allvarlighetsgrad (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Åtgärdsförslag (Remediation):** Tillhandahåller exakta Cisco CLI-kommandon för varje identifierad brist.
- **Interaktivt CLI & Rapportering:** Färgkodad realtidssummering via `rich` samt automatisk export till Markdown-rapporter (`reports/`).

---

## 🏛️ Arkitektur & Flöde

```text
+-----------------------------------+
| Network Config (*.cfg / *.txt)    |
+-----------------+-----------------+
                  |
                  v
+-----------------+-----------------+       +-----------------------------+
|    ConfigAuditor (Python Engine)  |<======| Hardening Rules (JSON)      |
+-----------------+-----------------+       +-----------------------------+
                  |
         +--------+--------+
         |                 |
         v                 v
+-----------------+   +-------------------------+
| Rich CLI Table  |   | Markdown Report (*.md)  |
|  (Pass / Fail)  |   | (Compliance Score & Fix)|
+-----------------+   +-------------------------+
```

---

## 📋 Standardregelverk

| Regel-ID | Allvarlighetsgrad | Titel | Beskrivning |
| :--- | :--- | :--- | :--- |
| `SEC-001` | **MEDIUM** | Enable Password Encryption | Säkerställer att lösenordskryptering (`service password-encryption`) är aktiv. |
| `SEC-002` | **HIGH** | Disable Unencrypted HTTP | Förbjuder okrypterat webbgränssnitt (`no ip http server`). |
| `SEC-003` | **HIGH** | Enforce SSH Version 2 | Tvingar användning av SSHv2 (`ip ssh version 2`). |
| `SEC-004` | **CRITICAL** | Enforce SSH on VTY Lines | Blockerar Telnet och kräver `transport input ssh` på VTY-linjer. |
| `SEC-005` | **HIGH** | Restricted Access-Class on VTY | Kräver ACL-begränsning (`access-class`) mot management-subnät. |
| `SEC-006` | **LOW** | Configure Login Banner (MOTD) | Säkerställer varningsbanner (`banner motd`) för obehörig åtkomst. |

---

## 🛠️ Installation & Användning

### 1. Klona repot och sätt upp miljön
```bash
git clone [https://github.com/Alexander-dia/net-config-auditor.git](https://github.com/Alexander-dia/net-config-auditor.git)
cd net-config-auditor
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Kör auditering

**Granska en osäker switch-konfiguration:**
```bash
python src/main.py sample_configs/cisco_switch_insecure.cfg --output reports/insecure_audit.md
```

**Granska en härdad switch-konfiguration:**
```bash
python src/main.py sample_configs/cisco_switch_hardened.cfg --output reports/hardened_audit.md
```

---

## 📂 Projektstruktur

```text
net-config-auditor/
├── rules/
│   └── compliance_rules.json       # Regeldefinitioner i JSON
├── sample_configs/
│   ├── cisco_switch_hardened.cfg   # Härdad Cisco-testkonfiguration (100% Pass)
│   └── cisco_switch_insecure.cfg   # Sårbar Cisco-testkonfiguration (0% Pass)
├── src/
│   ├── __init__.py
│   ├── auditor.py                  # Kärnlogik för regex-analys & poängberäkning
│   └── main.py                     # CLI-interface och rapportgenerator
├── reports/                        # Genererade Markdown-rapporter
├── requirements.txt
└── README.md
```