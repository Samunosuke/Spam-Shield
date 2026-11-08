# Privacy Policy / Datenschutzerklärung

**Suke.EmailValidationAddon for Thunderbird**  
*Last updated: November 2026*

---

## English

### 1. General Principles
**Suke.EmailValidationAddon** is committed to protecting your privacy. The add-on is designed to operate locally within your Thunderbird client. It does not track you, does not include any analytics or advertising frameworks, and never sells or collects personal data.

### 2. Data Processed Locally
* **Email Sender & Headers:** To evaluate incoming emails, the add-on extracts the sender domain and relevant authentication headers (`DKIM-Signature`, `Received`, `Authentication-Results`).
* **Settings & Diagnostic Logs:** Your configuration rules, custom Whitelist/Blacklist patterns, and recent evaluation diagnostics are saved exclusively within your local Thunderbird storage (`storage.local`). This data never leaves your computer.

### 3. External Network Queries (DNS & RDAP)
To verify whether a sender domain is authentic and trustworthy, the add-on performs direct, encrypted DNS and RDAP queries:
1. **DNS-over-HTTPS (DoH):** Queries for standard DNS records (`A`, `AAAA`, `MX`, `TXT`/SPF, `_dmarc`, `_domainkey`) and public DNS-blacklists are sent over HTTPS to Cloudflare DNS (`https://cloudflare-dns.com/dns-query`).
2. **RDAP (Domain Registration Age):** To determine the age of a domain, the authoritative RDAP server for the corresponding top-level domain is queried (discovered via `https://data.iana.org/rdap/dns.json`).

**Important:** Only the sender domain name (e.g. `example.com`) is queried. **No email bodies, subjects, recipient addresses, attachments, credentials, or personal message contents are ever sent over the network.**

### 4. Third-Party Data Transmission
No personal data is collected or shared with the author or any third party. The third-party network interactions are strictly limited to the public DNS resolver (Cloudflare) and registry RDAP endpoints necessary to resolve domain reputation.

---

## Deutsch

### 1. Grundsätzliches
**Suke.EmailValidationAddon** schützt Ihre Privatsphäre. Die Erweiterung arbeitet primär lokal in Ihrem Thunderbird-Mailprogramm. Es werden keine Telemetrie- oder Analysedaten erhoben, keine Werbung ausgespielt und keinerlei personenbezogene Daten gesammelt oder verkauft.

### 2. Lokal verarbeitete Daten
* **Absender & E-Mail-Header:** Zur Bewertung eingehender E-Mails liest das Add-on die Domain des Absenders sowie relevante Authentifizierungs-Header (`DKIM-Signature`, `Received`, `Authentication-Results`) aus.
* **Einstellungen & Diagnose-Protokoll:** Sämtliche Filtereinstellungen, eigene Whitelist-/Blacklist-Einträge und die letzten Bewertungsergebnisse werden ausschließlich im lokalen Speicher von Thunderbird (`storage.local`) auf Ihrem Gerät gespeichert.

### 3. Externe Netzwerkabfragen (DNS & RDAP)
Zur technischen Prüfung der Absender-Domain führt das Add-on verschlüsselte Online-Abfragen durch:
1. **DNS-over-HTTPS (DoH):** Abfragen von DNS-Einträgen (`A`, `AAAA`, `MX`, `TXT`/SPF, `_dmarc`, `_domainkey`) sowie öffentlichen DNS-Blacklists erfolgen verschlüsselt über den Cloudflare-DNS-Dienst (`https://cloudflare-dns.com/dns-query`).
2. **RDAP (Domain-Alter):** Zur Ermittlung des Registrierungsdatums wird der offizielle RDAP-Server der jeweiligen Domain-Endung kontaktiert (ermittelt über die IANA-Verzeichnisliste `https://data.iana.org/rdap/dns.json`).

**Wichtig:** Es wird ausschließlich der Domainname des Absenders (z. B. `beispiel.de`) abgefragt. **Es werden niemals E-Mail-Inhalte, Betreffzeilen, Empfängeradressen, Passwörter oder Dateianhänge über das Netzwerk übertragen.**

### 4. Weitergabe an Dritte
Es erfolgt keine Weitergabe von Daten an den Entwickler oder sonstige Dritte, mit Ausnahme der rein technischen Domain-Abfragen an die genannten öffentlichen DNS-/RDAP-Dienste.

