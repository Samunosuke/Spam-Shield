# Technical Analysis: `evaluateSpamKitFingerprint`

## 1. Executive Summary & Purpose

The `evaluateSpamKitFingerprint` function implemented in [`background.js`](file:///home/samonosuke/Workspace/AntiGravity/Suke.EmailValidationAddon/background.js#L1468-L1545) is an heuristic engine designed to detect bulk-provisioned spam domains (such as `esourl.org`, `gottlieb.relusnelar.org`, `logicvanta.info`, `denesik.heatrica.shop`, `initives.org`, and `snismirpel.com`).

Modern spam actors register hundreds of cheap top-level domains (or disposable subdomains) and use automated orchestrators to configure DNS zones. While these domains pass basic authentication tests (valid `A`, `MX`, `SPF`, and `DKIM` records), their programmatic creation leaves distinct structural footprints.

`evaluateSpamKitFingerprint` detects these automated provisioning footprints **without issuing extra network requests**, keeping execution instantaneous and safe from origin-probing attacks.

---

## 2. Architecture & Design Principles

### 2.1. Zero Extra Network Calls (DoH Reuse)
Instead of issuing HTTP requests to the target domain (which can cause `NetworkError`, CORS failures, delays, or alert the spammer to recipient IP addresses), the algorithm operates strictly on DNS records already retrieved for standard checks:
* `aRecordIps`: Resolved IPv4 address(es) of the domain (`A` record).
* `mxRecordData`: The domain's Mail Exchange (`MX`) answer set.
* `spfRecord`: The raw `v=spf1` TXT record string.
* `dmarcRes`: The parsed DMARC TXT record object (`_dmarc.<domain>`).

### 2.2. Multi-Indicator Threshold
No single indicator triggers a positive classification. A domain is only flagged if **at least two (>= 2)** distinct generator indicators match simultaneously:

```javascript
const detected = dnsIndicators.length >= 2;
```

---

## 3. Analysis of the Five Indicators

### Indicator 1: Boilerplate Generator DMARC Pattern
* **Pattern**:
  ```text
  v=DMARC1; p=none; rua=mailto:postmaster@<domain>; ruf=mailto:dmarc@<domain>
  ```
* **Mechanic**: Automated spam kits set `p=none` so that unauthorized messages are never rejected by receiving servers during setup. They populate both `rua` and `ruf` with identical default mailboxes (`postmaster@` and `dmarc@` under the active domain name).
* **Significance**: Legitimate commercial senders often omit `ruf` (forensic reports are rarely supported by modern receivers), direct DMARC aggregates to dedicated third-party monitoring services (e.g., `dmarcian`, `valimail`), or configure `p=quarantine` / `p=reject`.

### Indicator 2: Self-Referential MX `10` + Rigid Raw-IP SPF
* **Pattern**:
  * MX answer is singular: `10 <domain>.`
  * SPF matches: `/^v=spf1\s+a\s+mx(?:\s+ip4:[0-9./]+)+\s+-all$/i`
* **Mechanic**:
  Automated VPS deployment scripts install a local Postfix/Exim server directly on the host machine. The provisioning software creates an MX record pointing directly to itself (`10 <domain>.`) and generates an SPF record authorizing only the machine's local IP addresses with a rigid `-all` tail.
* **Significance**: Legitimate senders almost always route mail through external providers or shared relays (`include:_spf.google.com`, `include:spf.protection.outlook.com`, `include:mailgun.org`, etc.).

### Indicator 3: Redundant A-Record IP in SPF
* **Pattern**:
  The IPv4 address obtained from the domain's `A` record appears explicitly inside an `ip4:<address>` mechanism in the SPF record:
  ```text
  A Record: 80.97.42.105
  SPF Record: v=spf1 a mx ip4:80.97.42.105 -all
  ```
* **Mechanic**: The `a` mechanism in SPF already authorizes the domain's `A` record. Splicing `ip4:<A-Record-IP>` into the same record is redundant and is a known artifact of naive automation scripts that blindly append the host IP to standard boilerplate flags (`v=spf1 a mx ip4:${SERVER_IP} -all`).

### Indicator 4: "Snowshoe" Multi-IP Allocation in the Same `/24` Subnet
* **Pattern**:
  The SPF record contains two or more `ip4:` entries sharing the same `/24` IPv4 prefix:
  ```text
  v=spf1 a mx ip4:213.246.56.179 ip4:213.246.56.9 ip4:213.246.56.89 -all
  ```
* **Mechanic**: Spammers employ "snowshoe spamming"—spreading outgoing mail volume across multiple IPs within a purchased or rented host subnet (e.g. `/24`) to dilute reputation penalties on any single IP.
* **Significance**: The function parses all `ip4:` mechanisms, groups them by `/24` prefix (`X.Y.Z.0/24`), and flags instances where two or more IPs share the same subnet.

### Indicator 5: Disposable Surname/Word Subdomains with Dedicated Self-MX
* **Pattern**:
  Mail sent from `<random-sub>.<rootdomain.tld>` where the subdomain publishes its own independent self-MX (`10 <random-sub>.<rootdomain.tld>.`).
* **Mechanic**:
  Spammers frequently rotate randomized subdomains (e.g., `gottlieb.relusnelar.org`, `denesik.heatrica.shop`) while keeping the root domain dormant. When evaluated, the algorithm extracts the subdomain prefix and compares it against standard operational subdomains (`mail`, `smtp`, `newsletter`, `support`, `billing`, etc.). If the prefix is non-standard and publishes its own self-referential MX, it is flagged.

---

## 4. How Spammers Can Bypass This Algorithm

Because `evaluateSpamKitFingerprint` relies on static pattern matching of DNS configuration artifacts, an informed operator could evade detection with configuration changes:

### 1. Eliminating Redundant SPF Tokens
* **Vector**: Removing `ip4:<A-IP>` when `a` is present, or using CIDR notation (e.g., `/28` or `/29`) instead of individual IP listings.
* **Result**: Indicator 3 and Indicator 4 will no longer match.

### 2. Randomizing DMARC Records
* **Vector**:
  * Omitting `ruf` or setting aggregate reports to a shared mailbox or sub-address.
  * Omitting the DMARC TXT record altogether (though this would trigger Check 6: `dmarc`).
  * Upgrading the policy to `p=quarantine` on single-use burner domains.
* **Result**: Indicator 1 will not match.

### 3. Masking MX Records Behind Generic Hostnames
* **Vector**: Setting the MX target to a dedicated hostname (e.g. `mail1.genericrelay.net`) rather than self-referencing `10 <domain>.`.
* **Result**: Indicator 2 and Indicator 5 will fail to match.

### 4. Utilizing Cloud Relays / Hybrid SPF
* **Vector**: Including dummy or real relay mechanisms (e.g. `include:sendgrid.net` or `redirect=`) to break the rigid regex `/^v=spf1\s+a\s+mx(?:\s+ip4:[0-9./]+)+\s+-all$/i`.
* **Result**: Indicator 2, 3, and 4 will not trigger.

---

## 5. Weaknesses & Limitations of the Algorithm

| Weakness | Description | Risk Level |
| :--- | :--- | :---: |
| **Brittle Regular Expressions** | Regexes expect specific flag orderings (`v=spf1 a mx ip4:... -all`). Rearranging flags (e.g. `v=spf1 ip4:... a mx -all`) breaks matching. | High |
| **Static Whitelist for Subdomains** | The `commonSubdomains` set is hardcoded. Legitimate unconventional subdomains (e.g. `engineering.company.com` or `community.project.org`) with self-hosted mail servers could match Indicator 5. | Low |
| **Heuristic False Positives on Hobbyist Mail Servers** | A self-hosted home server or small business running Postfix on a single VPS with `v=spf1 a mx ip4:<STATIC-IP> -all` and default DMARC `p=none` could trigger Indicators 1, 2, and 3 simultaneously. | Medium |
| **IPv6 Blind Spots** | Indicator 3 and Indicator 4 only analyze `ip4:` mechanisms; spammers transitioning to IPv6 (`ip6:`) subnets bypass the subnet aggregation and redundancy logic. | Medium |
| **No Cross-Domain Reputation Correlation** | The function inspects domains in isolation. It cannot detect when two distinct sender domains share the exact same DKIM public key or upstream nameservers without additional state tracking. | Medium |

---

## 6. Recommendations for Future Hardening

1. **Flexible SPF AST Parsing**: Parse SPF mechanisms into structured objects rather than using strict regular expressions.
2. **IPv6 Prefix Grouping**: Add `/48` or `/64` prefix grouping for IPv6 mechanisms.
3. **DKIM Key Hash Correlation**: Store observed DKIM public key hashes in extension storage to detect when multiple domains share identical cryptographic keys.
4. **Adaptive Scoring**: Rather than a static penalty of `-80`, weight indicators dynamically based on confidence (e.g., snowshoe subnets weighted higher than default DMARC templates).

