# Spam Shield for THUNDERBIRD

**Target:** Thunderbird 128 ESR to 158.0.1+ (64-Bit, Manifest V3)  
**License:** [MIT License](LICENSE) · **Privacy:** [Privacy Policy](PRIVACY.md) · **Deutsche Version:** [README.de.md](README.de.md)

---

### 📌 Summary (for Thunderbird Add-ons / ATN)

> Reliably detects modern email spam using a 10-tier scoring engine: DNS-over-HTTPS, SPF, DKIM, DMARC policy, Domain Registration Age (RDAP), DNS blacklists, and spam-kit generator fingerprints — featuring configurable scores, Whitelist/Blacklist, folder scanning, and real-time live diagnostics.

---

## Background & How It Works

Traditional spam filters and naive domain checks frequently struggle against modern bulk spam campaigns: attackers automatically register low-cost disposable domains (e.g. `snismirpel.com`, `esourl.org`, `gottlieb.relusnelar.org`, `logicvanta.info`, `denesik.heatrica.shop`, `initives.org`), provision valid `A`, `MX`, `SPF`, and `DKIM` records via automated scripts, and host identical template websites (automated RSS news scrapers) to appear legitimate.

Because raw ICMP pings and raw TCP sockets are prohibited within the WebExtension security sandbox, this add-on combines **10 multi-tier checks using DNS-over-HTTPS (DoH), RDAP (the official WHOIS successor), email header inspection, and DNS spam-kit fingerprinting**:

| No. | Check | Description | Default Penalty |
| :--- | :--- | :--- | :--- |
| **0a** | **Whitelist (Highest Priority)** | Checks if the sender email (`user@domain.com`) or domain (`*.domain.com` / `domain.com`) is on the Whitelist. **Always overrides the Blacklist** and bypasses all DNS lookups. | `0` (Immediate **OK**) |
| **0b** | **Blacklist** | Checks if the sender email or domain (including wildcard subdomains like `*.relusnelar.org`) is blacklisted. | `-1000` (Immediate **SPAM**) |
| **1** | **Domain Existence (`A` / `AAAA` / `MX`)** | Verifies that the domain exists in DNS (no `NXDOMAIN`). If this fails, validation aborts immediately by default. | `-100` |
| **2** | **DNSSEC Signature (`AD` flag)** | Verifies whether the DNS response is cryptographically authenticated via DNSSEC. | `-10` |
| **3** | **MX Record Present** | Verifies whether the sender domain publishes active mail exchange servers. | `-20` |
| **4** | **SPF Record Present (`v=spf1`)** | Checks whether a valid SPF TXT record is published for the domain. | `-50` |
| **5** | **DKIM Signature & Key (`s=` / `d=`)** | Extracts selector (`s=`) and signing domain (`d=`) from the `DKIM-Signature` header and checks the public key at `<selector>._domainkey.<domain>`. | `-20` |
| **6** | **DMARC Policy (`_dmarc`)** | Checks for an active DMARC record and enforced policy (`p=quarantine` or `p=reject`). Disposable spam domains commonly omit DMARC or use `p=none` (no enforcement). | `-20` |
| **7** | **Domain Age / NRD via RDAP** | Queries the authoritative RDAP server via the official IANA bootstrap registry to determine domain age. Domains younger than the configured threshold (default: **90 days**) receive a penalty for being a *Newly Registered Domain (NRD)*. *(TLDs without public RDAP, such as `.de`, receive no penalty).* | `-40` |
| **8** | **DNS Blacklist (Domain & Server IP)** | Queries the root domain (`dbl.nordspam.com`, `dbl.spamhaus.org`) and connecting IPv4 (`bl.nordspam.com`, `bl.spamcop.net`, `bl.0spam.org`) against public reputation lists. | `-80` |
| **9** | **SPF Sender IP Match (`Received`)** | Validates `Authentication-Results` / `Received-SPF` headers and matches the connecting server IP against authorized IP ranges in the domain's SPF record. | `-40` |
| **10** | **Spam-Kit Generator Fingerprint** | Identifies automated bulk-spam domain provisioning via DNS heuristics (Self-MX `10 <domain>` + raw-IP SPF `v=spf1 a mx ip4:... -all`, boilerplate DMARC `p=none`, redundant A-record IPs, snowshoe subnet IPs, disposable subdomains). See [SPAM_KIT_FINGERPRINT.md](SPAM_KIT_FINGERPRINT.md). | `-80` |

### Example Scoring: Modern Spam Domain (`snismirpel.com`)
Even though the spammer configured valid `A`, `MX`, `SPF`, and `DKIM` records:
- Missing DNSSEC signature: **`-10`**
- DMARC set to `p=none` (no enforcement): **`-20`**
- Domain age < 90 days according to RDAP: **`-40`**
- Spam-kit fingerprint matched (Self-MX + Raw-IP SPF + Generator DMARC): **`-80`**
- **Total Score:** **`-150`** (well below the default spam threshold of `-50`).
- The email is reliably classified and handled as **SPAM**.

---

## Features & User Interface

1. **Native Thunderbird Context Menus**
   * **Right-click on any folder** in the folder pane -> *"Scan folder for spam domains (Spam Shield)"*
   * **Right-click on selected email(s)** in the message list ->
     * *"Scan selected email(s) for spam domain (Spam Shield)"*
     * *"Add sender email / domain (`*.domain`) to Whitelist"*
     * *"Add sender email / domain (`*.domain`) to Blacklist & mark as Spam"*
2. **Toolbar Popup ([popup.html](popup.html))**
   * Quick action buttons to scan the currently active folder or selected messages.
   * Instant toggle switch for **Evaluation / Dry-Run Mode**.
   * Live progress bar and compact feed of the last 12 evaluated emails with `+WL` / `⛔BL` quick-action buttons.
3. **Settings & Live Diagnostics Dashboard ([options.html](options.html))**
   * **Bilingual UI (English & German)**: Seamless automatic language detection based on Thunderbird/browser locale, with an instant manual selector (`auto`, `de`, `en`). All strings reside in [i18n.js](i18n.js).
   * **Whitelist & Blacklist Management**: Supports specific email addresses (`user@domain.com`) and wildcard domains (`*.relusnelar.org` or `relusnelar.org`). The Whitelist strictly takes precedence over the Blacklist.
   * Fully configurable scoring: enable/disable any of the 10 checks and adjust penalty scores freely.
   * Adjustable **Spam Threshold** (default: `< -50`) and **Dry-Run Mode** (scores and logs emails without moving them to Junk).
   * **Live Domain Tester**: Test any domain or full sender address (with optional `DKIM-Signature` header) in real time against your active rule set.
   * **Live Diagnostics Table**: Displays the last *X* (default: 100) evaluated emails with detailed check badges, hover tooltips, text search, status filters, and one-click `+WL` / `⛔BL` buttons plus right-click context menu.

---

## Building & Packaging

To generate the installation package (`spam.shield.xpi`):
```bash
./pack.sh
```

Install into Thunderbird via **Add-ons Manager (`Ctrl + Shift + A`) -> Gear Icon -> "Install Add-on From File…" -> select `spam.shield.xpi`**.
