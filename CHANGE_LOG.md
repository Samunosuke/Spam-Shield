# Changelog

All notable changes to **Spam Shield** are documented in this file.

## [1.7] - 2026-11-10

### Added
- **In-Email Validation Banner (`message_banner.js`, `message_banner.css`):**
  - Displays overall status and score badge (`OK`, `DRY-RUN`, `SPAM`, `WHITELIST`), all individual check pills (`DNS`, `DNSSEC`, `MX`, `SPF`, `DKIM`, `DMARC`, `Age`, `DNSBL`, `SPF-IP`, `Spam-Kit`) with full hover tooltips, a re-check button (`↻`), and 1-click quick-action buttons (`+WL Mail`, `+WL *.Dom`, `⛔BL Mail`, `⛔BL *.Dom`) directly at the top of opened emails.
  - Injected via Thunderbird's Manifest V3 `scripting.messageDisplay` API inside an isolated Shadow DOM (with automatic Light/Dark mode support) so email HTML styles cannot break the banner layout.
- **Message Display Toolbar Badge (`message_display_action`):**
  - Added a toolbar action button inside the message display header showing dynamic score/status badges (`OK`, `WL`, `BL`, or numeric score) synchronized via `messageDisplay.onMessagesDisplayed`.
- **Colored Context Menu Icons:**
  - Added green Whitelist (`+`) and red Blacklist (`–`) icons alongside the Spam Shield scan icon inside the message list right-click submenu for faster visual recognition.
- **Thunderbird Message Tagging (`messagesTags`):**
  - Added configurable color-coded Thunderbird tags (`Spam Shield: OK`, `Spam Shield: Spam`, `Spam Shield: Dry-Run`, `Spam Shield: Whitelist`) visible in the message list's *Tags* column while preserving existing user tags.
- **Persistent Per-Message Evaluation Cache:**
  - Stored up to 3,000 evaluation results in `storage.local` (`messageEvalCache`) indexed by `headerMessageId`, ensuring scores and check badges persist across folder moves and Thunderbird restarts.
- **New Configuration Options:**
  - Toggle in-email badges & quick-action banner (`showMessageBanner`, default: enabled).
  - Toggle automatic evaluation when opening unscanned emails (`autoCheckOnDisplay`, default: disabled — displays a manual `🛡️ Check` button when off).
  - Toggle automatic Thunderbird tag assignment (`tagEvaluatedMessages`, default: enabled).
  - Deduplicated in-flight evaluations (`evaluateDisplayedMessageOnce`) so concurrent display triggers never execute duplicate DNS/RDAP lookups.

### Changed
- **CSS & Code Refactoring:**
  - Refactored `renderBanner` in `message_banner.js` into focused helper builders and moved banner styling into a dedicated `message_banner.css` file.
  - Extracted static inline styles from `popup.js` and `options.js` into semantic CSS classes in `styles.css`.
  - Consolidated duplicate status hex colors in `background.js` into a shared `STATUS_COLORS` constant.

### Fixed
- **Options Page Responsive Layout:**
  - Adjusted `.grid-2` breakpoint (`minmax(520px, 1fr)`), added `min-width: 0` grid safeguards, wrapped `.settings-table` in a scrollable `.settings-table-wrap` container, and switched `.dnsbl-providers-list` to auto-fitting columns so narrow windows no longer cause table borders or controls to overflow card boundaries.
- **Auto-Evaluation on Email Open:**
  - Fixed a guard conflict in `message_banner.js` (`initBanner`) that prevented `triggerEvaluation()` from dispatching `EVALUATE_DISPLAYED_MESSAGE` when `autoCheckOnDisplay` was enabled.

---

## [1.6] - 2026-11-08

### Added
- **Rebranding & Visual Identity:** Renamed add-on to **Spam Shield** (`spam-shield@addon.mozilla.org`) with custom shield icon assets.
- **Bilingual Support (EN/DE):** Added full English and German localization (`i18n.js`) with automatic browser/Thunderbird locale detection and a manual language selector.
- **Modular DNSBL Configuration:**
  - Added individual enable/disable toggles per blacklist provider (*Nordspam*, *Spamhaus DBL*, *SpamCop*, **NiX Spam / manitu**, *0spam BL*, and **DroneBL**).
  - Added configurable minimum blacklist hit threshold (`minHits`, default: `1`) to prevent false positives from single aggressive lists.
  - Enriched DNSBL tooltips with the tested public IP/domain, RFC 5782 return code, and localized reason descriptions (e.g. spam-trap hit, phishing, malware).
- **Documentation:** Added English and German READMEs, Privacy Policy, License, and ATN-compliant HTML store descriptions (`docs/`).

### Changed
- **ATN Security Compliance:** Replaced all `innerHTML` assignments in `popup.js`, `options.js`, and `i18n.js` with safe DOM APIs (`createElement`, `replaceChildren`, `DOMParser`) and added comprehensive JSDoc comments.

### Fixed
- **Junk/Spam Folder Scanning Stability:** Added strict timeouts for DoH (4s), RDAP bootstrap (4s), `getHeaders()` (5s), and per-message validation (15s), and skipped redundant moves when messages are already inside a Junk/Spam/Trash folder.

---

## [1.5] - 2026-11-07

### Added
- **Spam-Kit Generator Fingerprint Detection:** Added DNS heuristics (`spamKitFingerprint`) to detect automated bulk-spam domains using Self-MX (`10 <domain>`), raw-IP SPF rules, generator DMARC templates, and snowshoe subnets.

### Changed
- **Minimized Host Permissions:** Removed wildcard `http://*/*` and `https://*/*` permissions, restricting network access strictly to `https://cloudflare-dns.com/*` and `https://data.iana.org/*`.

