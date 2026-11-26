# Privacy Policy / Datenschutzerklärung

**Spam Shield for Thunderbird**  
*Last updated: November 2026*

---

## English

### 1. General Principles
**Spam Shield** is committed to protecting your privacy. The add-on operates locally within your Thunderbird mail client. It does not track you, does not include any analytics or advertising frameworks, and never collects, sells, or shares personal data with the author or third parties for marketing or profiling purposes.

### 2. Website Visibility
**Spam Shield** runs exclusively within Thunderbird's email interface and background scripts. It does **not** inject scripts into web pages, does not browse or modify websites, and **does not make it apparent to websites that the add-on is installed**.

### 3. Data Processed & Stored Locally
* **Email Sender & Headers:** To evaluate incoming or manually scanned emails, the add-on reads the sender address/domain and relevant headers (`DKIM-Signature`, `Received`, `Authentication-Results`, `From`, `Reply-To`, `Return-Path`).
* **Settings & Diagnostic Logs:** Your filter configuration, custom Whitelist/Blacklist patterns, and recent evaluation diagnostics are stored exclusively in Thunderbird's local extension storage (`storage.local`) on your device. This stored data never leaves your computer.

### 4. External Network Queries (Encrypted via HTTPS)
To verify sender domain authenticity and reputation, the add-on performs direct, encrypted (`https://`) queries to the following external services when evaluating an email (subject to your enabled checks and local in-memory caching):

1. **DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`):**
   - **Data sent:** For each scanned email, Cloudflare DoH receives the **sender domain** (for `A`, `AAAA`, `MX`, and `TXT`/SPF lookups), **DKIM selector names** (`<selector>._domainkey.<domain>`), **`_dmarc` names** (`_dmarc.<domain>`), and **DNSBL query hosts** constructed from sender domains and `Received`-header IP addresses (e.g., reversed IP + DNSBL zone).
   - **Purpose:** Technical verification of mail server existence, SPF/DKIM/DMARC authentication, and public blocklist status.

2. **IANA RDAP Bootstrap (`https://data.iana.org/rdap/dns.json`) & Per-TLD RDAP Servers (`https://...`):**
   - **Data sent:** Fetching `https://data.iana.org/rdap/dns.json` transmits no email data; it retrieves the public mapping of top-level domains (TLDs) to authoritative HTTPS RDAP servers. Subsequently, the **registrable sender domain** of each scanned email is sent over `https://` to the corresponding TLD's RDAP server.
   - **Purpose:** Determining the domain's registration date/age. Non-HTTPS RDAP endpoints are never contacted.

**Important:** **No email bodies, subjects, recipient addresses, attachments, passwords, or account credentials are ever transmitted over the network.**

### 5. Data Sharing & Disclosure
No personal data is collected, stored on external servers, or disclosed to the add-on author. External transmissions are strictly limited to the technical domain, DKIM/DMARC, and DNSBL lookup queries sent to Cloudflare DoH (`cloudflare-dns.com`), IANA (`data.iana.org`), and the respective authoritative HTTPS RDAP registry servers described above.

---

## Deutsch

### 1. Grundsätzliches
**Spam Shield** schützt Ihre Privatsphäre. Die Erweiterung arbeitet lokal in Ihrem Thunderbird-Mailprogramm. Es werden keine Telemetrie- oder Analysedaten erhoben, keine Werbung ausgespielt und keinerlei personenbezogene Daten gesammelt, verkauft oder an Dritte zu Werbe- oder Analysezwecken weitergegeben.

### 2. Sichtbarkeit für Websites
**Spam Shield** läuft ausschließlich innerhalb von Thunderbird. Es werden **keine Skripte in Webseiten injiziert** und **Websites wird zu keinem Zeitpunkt signalisiert, dass dieses Add-on installiert ist**.

### 3. Lokal verarbeitete und gespeicherte Daten
* **Absender & E-Mail-Header:** Zur Bewertung eingehender oder manuell geprüfter E-Mails liest das Add-on die Absender-Domain sowie relevante Header (`DKIM-Signature`, `Received`, `Authentication-Results`, `From`, `Reply-To`, `Return-Path`) lokal aus.
* **Einstellungen & Diagnose-Protokoll:** Sämtliche Filtereinstellungen, eigene Whitelist-/Blacklist-Einträge und die letzten Bewertungsergebnisse werden ausschließlich im lokalen Speicher von Thunderbird (`storage.local`) auf Ihrem Gerät gespeichert und verlassen Ihren Rechner nicht.

### 4. Externe Netzwerkabfragen (ausschließlich verschlüsselt per HTTPS)
Zur technischen Prüfung der Absender-Domain führt das Add-on verschlüsselte (`https://`) Online-Abfragen an folgende Dienste durch (abhängig von den aktivierten Prüfmodulen und einem lokalen Zwischenspeicher):

1. **DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`):**
   - **Übermittelte Daten:** Für jede gescannte E-Mail erhält der Cloudflare-DoH-Dienst **Absender-Domains** (`A`, `AAAA`, `MX`, `TXT`/SPF), **DKIM-Selektor-Namen** (`<selector>._domainkey.<domain>`), **`_dmarc`-Namen** (`_dmarc.<domain>`) sowie **DNSBL-Abfragehosts**, die aus Absender-Domains und IP-Adressen aus `Received`-Headern gebildet werden.
   - **Zweck:** Technische Überprüfung von Mailserver-Einträgen, SPF/DKIM/DMARC sowie öffentlichen Spam-Blocklisten.

2. **IANA RDAP-Bootstrap (`https://data.iana.org/rdap/dns.json`) & TLD-RDAP-Server (`https://...`):**
   - **Übermittelte Daten:** Beim Abruf von `https://data.iana.org/rdap/dns.json` werden keine E-Mail-Daten übertragen; es wird lediglich die öffentliche Zuordnung von Top-Level-Domains zu autoritativen HTTPS-RDAP-Servern geladen. Anschließend wird die **registrierbare Absender-Domain** jeder gescannten E-Mail per `https://` an den zuständigen TLD-RDAP-Server gesendet.
   - **Zweck:** Ermittlung des Registrierungsdatums bzw. Domain-Alters. Nicht-HTTPS-Endpunkte werden ignoriert.

**Wichtig:** **Es werden niemals E-Mail-Inhalte, Betreffzeilen, Empfängeradressen, Passwörter oder Dateianhänge über das Netzwerk übertragen.**

### 5. Weitergabe an Dritte
Es erfolgt keine Erhebung oder Weitergabe von Daten an den Entwickler oder sonstige Dritte, mit Ausnahme der rein technischen Abfragen an Cloudflare DoH (`cloudflare-dns.com`), IANA (`data.iana.org`) und die jeweiligen autoritativen HTTPS-RDAP-Server wie oben beschrieben.

