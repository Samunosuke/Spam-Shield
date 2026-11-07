# EmailValidationAddon for THUNDERBIRD

**Target:** Thunderbird 128 ESR bis 158.0.1+ (64-Bit, Manifest V3)

Dieses Add-on erweitert Thunderbird um eine automatische sowie manuell ausführbare **Absender-Domain- und Authentifizierungs-Prüfung**, inklusive frei konfigurierbarem **Punkte-/Scoring-System** und **Live-Diagnose**.

## Hintergrund & Funktionsweise

Klassische Spam-Filter oder einfache DNS-Prüfungen scheitern häufig an modernen Spam-Wellen: Spammer registrieren heute automatisiert günstige Wegwerf-Domains (z. B. `snismirpel.com`) und richten dafür gültige `A`-, `MX`-, `SPF`- und `DKIM`-Einträge ein. Da in der Browser-/Thunderbird-WebExtension-Sandbox aus Sicherheitsgründen keine echten ICMP-Pings oder Raw-TCP-Sockets möglich sind, kombiniert dieses Add-on **9 mehrstufige Prüfungen über DNS-over-HTTPS (DoH), RDAP (WHOIS-Nachfolger) und E-Mail-Header-Analyse**:

| Nr. | Prüfung | Beschreibung | Standard-Score bei Fehler |
| :--- | :--- | :--- | :--- |
| **1** | **Domain-Existenz (`A` / `AAAA` / `MX`)** | Prüft, ob die Domain im DNS überhaupt existiert (kein `NXDOMAIN`). Schlägt dies fehl, wird standardmäßig sofort abgebrochen. | `-100` |
| **2** | **DNSSEC-Signatur (`AD`-Flag)** | Prüft, ob die DNS-Antwort kryptografisch per DNSSEC authentifiziert ist. | `-10` |
| **3** | **MX-Record vorhanden** | Prüft, ob die Absender-Domain selbst über Mail-Exchange-Server verfügt. | `-20` |
| **4** | **SPF-Record vorhanden (`v=spf1`)** | Prüft, ob ein gültiger SPF-TXT-Eintrag für die Domain veröffentlicht wurde. | `-50` |
| **5** | **DKIM-Signatur & DNS-Key (`s=` / `d=`)** | Liest Selektor (`s=`) und Signing-Domain (`d=`) aus dem `DKIM-Signature`-Header und prüft den Public-Key unter `<selector>._domainkey.<domain>`. | `-20` |
| **6** | **DMARC-Richtlinie (`_dmarc`)** | Prüft, ob ein DMARC-Record existiert und eine aktive Richtlinie (`p=quarantine` oder `p=reject`) durchsetzt. Wegwerf-Spam-Domains nutzen meist kein DMARC oder nur `p=none` (keine Durchsetzung). | `-20` |
| **7** | **Domain-Alter / NRD via RDAP** | Fragt über das offizielle RDAP-Protokoll (`rdap.org`) das Registrierungsdatum der Hauptdomain ab. Ist die Domain jünger als das konfigurierte Mindestalter (Standard: **90 Tage**), gilt sie als *Newly Registered Domain (NRD)*. *(Unterstützt eine Länder-TLD wie `.de` kein öffentliches RDAP, erfolgt kein Abzug).* | `-40` |
| **8** | **DNS-Blacklist (Domain & Server-IP)** | Prüft die Hauptdomain (`dbl.nordspam.com`, `dbl.spamhaus.org`) sowie die Einlieferungs-/A-Record-IPv4 (`bl.nordspam.com`, `bl.spamcop.net`, `bl.0spam.org`) auf bekannte Spam-Einträge. | `-80` |
| **9** | **SPF-Absender-IP-Abgleich (`Received`)** | Wertet `Authentication-Results` / `Received-SPF` sowie die tatsächliche Einlieferungs-IP aus den `Received`-Headern gegen die im SPF-Record freigegebenen IPv4-Adressen aus. | `-40` |

### Beispielrechnung an einer modernen Spam-Domain (`snismirpel.com`)
Obwohl der Spammer für `snismirpel.com` gültige `A`-, `MX`-, `SPF`- und `DKIM`-Records eingerichtet hat:
- Kein DNSSEC: **`-10`**
- DMARC steht nur auf `p=none` (keine Durchsetzung): **`-20`**
- Domain ist laut RDAP erst wenige Wochen alt (`< 90 Tage`): **`-40`**
- **Gesamt-Score:** **`-70`** (mit DKIM-Header in der E-Mail) bzw. **`-90`** (im manuellen Domain-Tester ohne DKIM-Header).
- Da der Score unter dem Schwellenwert (`< -50`) liegt, wird die E-Mail zuverlässig als **SPAM** erkannt.

---

## Features & Benutzeroberfläche

1. **Kontextmenü-Integration in Thunderbird**
   - **Rechtsklick auf einen Ordner** in der Ordnerliste -> *„Ordner auf Spam-Domains prüfen (Suke)“*
   - **Rechtsklick auf markierte E-Mail(s)** in der Nachrichtenliste -> *„Ausgewählte E-Mail(s) auf Spam-Domain prüfen (Suke)“*
2. **Toolbar-Popup ([popup.html](file:///home/samonosuke/Workspace/AntiGravity/Suke.EmailValidationAddon/popup.html))**
   - Schnellzugriff zum Prüfen des aktuell geöffneten Ordners oder der markierten E-Mails.
   - Direkt-Umschalter für den **Evaluierungs- / Dry-Run-Modus**.
   - Live-Fortschrittsbalken und Kompaktansicht der letzten 12 geprüften E-Mails.
3. **Konfigurations- & Live-Diagnose-Seite ([options.html](file:///home/samonosuke/Workspace/AntiGravity/Suke.EmailValidationAddon/options.html))**
   - Alle 9 Prüfungen einzeln aktivierbar/deaktivierbar und im Score frei einstellbar.
   - Einstellbarer **Spam-Schwellenwert** (Standard: `< -50`) und **Dry-Run-Modus** (nur bewerten & loggen, ohne E-Mails zu verschieben).
   - **Live-Domain-Tester**: Beliebige Domain oder E-Mail-Adresse (optional mit `DKIM-Signature`-Header) live gegen alle aktivierten Regeln testen.
   - **Live-Diagnose-Tabelle**: Zeigt die letzten *X* (Standard: 100) bewerteten E-Mails mit allen 9 Einzel-Badges, detaillierten Tooltips (Hover), Suchfunktion und Statusfilter.

---

## Build & Installation

Zum Erstellen des Add-on-Pakets (`Suke.EmailValidationAddon.xpi`):
```bash
./pack.sh
```

Installation in Thunderbird über **Add-ons-Verwaltung (`Strg + Umschalt + A`) -> Zahnrad-Symbol -> „Add-on aus Datei installieren…“ -> `Suke.EmailValidationAddon.xpi`**.
