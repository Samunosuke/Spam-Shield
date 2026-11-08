/**
 * Internationalization (i18n) dictionary and helper utilities for Spam Shield.
 * Supports German ('de') and English ('en'), with automatic browser/Thunderbird locale detection ('auto').
 */

const I18N_MESSAGES = {
    de: {
        // Common & Badges
        lang_auto: 'Automatisch (Browser-Sprache)',
        lang_de: 'Deutsch (DE)',
        lang_en: 'English (EN)',
        mode_active_short: 'Aktiv (Verschieben nach Junk)',
        mode_dryrun_short: 'Evaluierungsmodus (Dry-Run)',
        badge_ok: 'OK',
        badge_spam: 'SPAM',
        badge_dryrun: 'DRY-RUN',
        badge_error: 'Fehler',
        status_disabled: 'Deaktiviert',
        status_off_short: 'aus',
        folder_default: 'Postfach',
        selection_default: 'Auswahl',
        unknown_domain: '(unbekannt)',
        no_subject: '(Kein Betreff)',

        // Check Pill short labels
        pill_whitelist: 'Whitelist',
        pill_blacklist: 'Blacklist',
        pill_domainExists: 'Existenz',
        pill_domainExists_short: 'DNS',
        pill_dnssec: 'DNSSEC',
        pill_mx: 'MX',
        pill_spf: 'SPF',
        pill_dkim: 'DKIM',
        pill_dmarc: 'DMARC',
        pill_domainAge: 'Alter',
        pill_dnsbl: 'DNSBL',
        pill_spfIpMatch: 'SPF-IP',
        pill_spamKitFingerprint: 'Spam-Kit',

        // Quick-Action Buttons
        btn_wl_mail: '+WL Mail',
        btn_wl_dom: '+WL *.Dom',
        btn_bl_mail: '⛔BL Mail',
        btn_bl_dom: '⛔BL *.Dom',
        title_wl_mail: 'E-Mail ({pattern}) zur Whitelist hinzufügen',
        title_wl_dom: 'Domain ({pattern}) zur Whitelist hinzufügen',
        title_bl_mail: 'E-Mail ({pattern}) zur Blacklist hinzufügen',
        title_bl_dom: 'Domain ({pattern}) zur Blacklist hinzufügen',
        title_remove_wl: 'Von Whitelist entfernen',
        title_remove_bl: 'Von Blacklist entfernen',

        // Context Menus (Thunderbird folder_pane & message_list)
        action_tooltip: 'Spam Shield – Live-Diagnose & Ordnerprüfung',
        menu_validate_folder: 'Ordner auf Spam-Domains prüfen (Spam Shield)',
        menu_validate_messages: 'Ausgewählte E-Mail(s) auf Spam-Domain prüfen (Spam Shield)',
        menu_whitelist_email: 'Absender-E-Mail zur Whitelist hinzufügen (Spam Shield)',
        menu_whitelist_domain: 'Absender-Domain (*.domain) zur Whitelist hinzufügen (Spam Shield)',
        menu_blacklist_email: 'Absender-E-Mail zur Blacklist hinzufügen & als Spam behandeln (Spam Shield)',
        menu_blacklist_domain: 'Absender-Domain (*.domain) zur Blacklist hinzufügen & als Spam behandeln (Spam Shield)',

        // Popup UI
        popup_title: 'Spam Shield',
        popup_loading: 'Lade Status…',
        popup_open_options: '⚙️ Einstellungen & Diagnose',
        popup_open_options_title: 'Konfiguration & ausführliche Live-Diagnose öffnen',
        popup_scan_folder: '📂 Aktuellen Ordner prüfen',
        popup_scan_selected: '✉️ Auswahl prüfen',
        popup_dryrun_label: 'Dry-Run',
        popup_dryrun_title: 'Wenn aktiv, werden Spam-Mails nur bewertet und geloggt, aber nicht verschoben',
        popup_scanning: 'Prüfe…',
        popup_recent_header: 'Letzte Bewertungen (Live)',
        popup_empty_log: 'Noch keine E-Mails in dieser Sitzung bewertet.',
        popup_log_summary_zero: '0 Einträge',
        popup_log_summary: '{total} geprüft · {spam} Spam',
        popup_mode_dryrun: 'Schwellenwert: < {threshold} · Evaluierungsmodus (Dry-Run)',
        popup_mode_active: 'Schwellenwert: < {threshold} · Aktiv (Verschieben nach Junk)',
        popup_scan_progress: '{source}: {processed}/{total} (Spam: {spam})',
        popup_status_added_list: '✓ "{pattern}" zur {list} hinzugefügt.',
        popup_status_load_err: 'Fehler beim Laden: {error}',
        popup_status_scanning_folder: 'Prüfe aktuellen Ordner…',
        popup_status_folder_err: 'Ordnerprüfung fehlgeschlagen: {error}',
        popup_status_folder_done: 'Ordner geprüft: {processed} E-Mails ({spam} Spam).',
        popup_status_scanning_sel: 'Prüfe ausgewählte E-Mails…',
        popup_status_sel_err: 'Auswahlprüfung fehlgeschlagen: {error}',
        popup_status_sel_done: 'Auswahl geprüft: {processed} E-Mails ({spam} Spam).',
        conn_error_short: 'Verbindungsfehler',

        // Options Page UI
        opt_page_title: 'Spam Shield – Konfiguration & Live-Diagnose',
        opt_header_title: '🛡️ Spam Shield – Konfiguration & Live-Diagnose',
        opt_header_subtitle: 'Konfiguriere Prüfregeln, Whitelist/Blacklist & Score-Gewichtungen, starte manuelle Ordnerprüfungen und überwache die letzten Bewertungen in Echtzeit.',
        opt_clear_cache_btn: '🔄 DNS/RDAP-Cache leeren',
        opt_clear_cache_title: 'Leert den In-Memory-Cache für DNS- und RDAP-Abfragen',
        opt_scan_running: 'Ordnerprüfung läuft…',
        opt_scan_progress: 'Prüfe "{source}": {processed} von {total} E-Mails ({spam} Spam)…',

        // Card 1: Filter Configuration & Scores
        opt_card_config_title: '⚙️ Filter-Konfiguration & Scores',
        opt_language_label: 'Sprache / Language',
        opt_language_hint: 'Sprache der Benutzeroberfläche (Standard: Automatisch nach Browser/Thunderbird).',
        opt_threshold_label: 'Spam-Schwellenwert (Score < Wert = Spam)',
        opt_threshold_hint: 'Fällt der Gesamt-Score einer Domain unter diesen Wert (z. B. -51 bei -50), gilt die Mail als Spam.',
        opt_dryrun_label: 'Evaluierungs- / Dry-Run-Modus',
        opt_dryrun_hint: 'Wenn aktiv, werden E-Mails nur bewertet und in der Live-Diagnose angezeigt, aber <strong>nicht</strong> verschoben oder als Junk markiert.',
        opt_monitor_all_label: 'Alle E-Mail-Ordner überwachen',
        opt_monitor_all_hint: 'Überwacht alle Ordner außer Systemordner (Junk, Papierkorb, Gesendet, Entwürfe, Archiv). Wenn aus: nur Posteingang.',
        opt_max_log_label: 'Anzahl Einträge in der Live-Diagnose (Letzte X E-Mails)',
        opt_max_log_hint: 'Wie viele geprüfte E-Mails im Diagnose-Protokoll gespeichert werden sollen.',
        opt_checks_heading: 'Einzelne DNS-, Reputations- & Authentifizierungs-Prüfungen',
        opt_th_active: 'Aktiv',
        opt_th_check: 'Prüfung',
        opt_th_score: 'Score bei Fehler',
        opt_th_option: 'Option',

        // 10 Checks in Settings Table
        chk1_title: '1. Domain-Existenz (A / AAAA / MX)',
        chk1_desc: 'Prüft, ob die Domain im DNS überhaupt existiert (kein NXDOMAIN).',
        chk1_opt_stop: 'Sofort abbrechen',
        chk1_opt_stop_title: 'Keine weiteren DNS-Abfragen durchführen, wenn die Domain nicht existiert',
        chk2_title: '2. DNSSEC-Signatur (AD-Flag)',
        chk2_desc: 'Prüft, ob die DNS-Antwort kryptografisch per DNSSEC signiert ist.',
        chk3_title: '3. MX-Record vorhanden',
        chk3_desc: 'Prüft, ob die Absender-Domain selbst E-Mails empfangen kann.',
        chk4_title: '4. SPF-Record vorhanden (v=spf1)',
        chk4_desc: 'Prüft, ob ein gültiger SPF-TXT-Eintrag für die Domain veröffentlicht ist.',
        chk5_title: '5. DKIM-Signatur & DNS-Key',
        chk5_desc: 'Prüft den DKIM-Signature-Header (s=/d=) und den öffentlichen Schlüssel im DNS.',
        chk6_title: '6. DMARC-Richtlinie (_dmarc)',
        chk6_desc: 'Prüft auf gültige DMARC-Policy (<code>p=quarantine</code> / <code>p=reject</code>). Spammer nutzen oft gar kein DMARC oder nur <code>p=none</code>.',
        chk6_opt_none: '<code>p=none</code> abstrafen',
        chk6_opt_none_title: 'Wenn aktiv, führt auch p=none (keine Durchsetzung) zum Punktabzug',
        chk7_title: '7. Domain-Alter / Neu registrierte Domains (RDAP)',
        chk7_desc: 'Prüft über RDAP (WHOIS-Nachfolger), ob die Domain erst kürzlich für Spam-Kampagnen registriert wurde.',
        chk7_opt_days: 'Min. Tage:',
        chk7_opt_days_title: 'Domains, die jünger als diese Anzahl an Tagen sind, erhalten den Punktabzug',
        chk8_title: '8. DNS-Blacklist (Domain & Server-IP)',
        chk8_desc: 'Prüft Domain und Einlieferungs-/A-Record-IP gegen öffentliche DNS-Blacklists (Nordspam, SpamCop, 0spam, Spamhaus).',
        chk9_title: '9. SPF-Absender-IP-Abgleich (Received-Header)',
        chk9_desc: 'Prüft anhand von <code>Authentication-Results</code> / <code>Received</code>-Headern, ob die sendende Server-IP wirklich durch den SPF-Record autorisiert ist.',
        chk10_title: '10. Spam-Baukasten-Fingerabdruck (DNS-Generator-Muster)',
        chk10_desc: 'Erkennt automatisiert generierte Fake-/Spam-Domains (wie <code>esourl.org</code>, <code>*.relusnelar.org</code>, <code>logicvanta.info</code>, <code>*.heatrica.shop</code>, <code>initives.org</code>) anhand kombinierter DNS-Baukasten-Muster (Self-MX <code>10 &lt;domain&gt;</code> + Raw-IP-SPF + Generator-DMARC + Snowshoe-Subdomains).',

        opt_save_btn: '💾 Einstellungen speichern',
        opt_reset_btn: '↺ Standardwerte wiederherstellen',

        // Card 2: Manual Folder & Message Scan
        opt_card_scan_title: '📂 Manuelle Ordner- & Nachrichtenprüfung',
        opt_card_scan_desc: 'Du kannst jeden Ordner auch direkt in Thunderbird per <strong>Rechtsklick auf den Ordner</strong> oder <strong>Rechtsklick auf ausgewählte E-Mails</strong> prüfen lassen.',
        opt_folders_loading: 'Ordner werden geladen…',
        opt_folders_empty: 'Keine Ordner gefunden',
        opt_folders_err: 'Fehler beim Laden der Ordner: {error}',
        opt_scan_selected_folder_btn: '▶️ Ausgewählten Ordner prüfen',
        opt_scan_active_folder_btn: '📂 Aktuell geöffneten Ordner prüfen',
        opt_scan_selected_msgs_btn: '✉️ Markierte E-Mails prüfen',

        // Card 3: Live Domain Tester
        opt_card_tester_title: '🔬 Einzelne Domain / Absenderadresse live testen',
        opt_card_tester_desc: 'Teste sofort, welchen Score eine Domain oder Absenderadresse mit den aktuell gespeicherten Regeln (inkl. Whitelist/Blacklist) erhält.',
        opt_tester_domain_placeholder: 'z.B. no-reply@snismirpel.com oder google.com',
        opt_tester_dkim_placeholder: 'Optional: DKIM-Signature Header (z.B. v=1; a=rsa-sha256; d=beispiel.de; s=default; ...)',
        opt_tester_run_btn: '🔍 Domain prüfen',
        opt_tester_empty_err: 'Bitte eine Domain oder E-Mail-Adresse eingeben.',
        opt_tester_running: 'Prüfe Whitelist/Blacklist, DNS, SPF, DKIM, DMARC, RDAP (Domain-Alter), DNSBL & Spam-Baukasten…',
        opt_tester_status_spam: 'SPAM (unter Schwellenwert)',
        opt_tester_status_ok: 'OK (Vertrauenswürdig)',

        // Card 4: Whitelist & Blacklist Management
        opt_card_lists_title: '📋 Whitelist & Blacklist Verwaltung',
        opt_card_lists_desc: 'Unterstützt einzelne E-Mail-Adressen (<code>name@domain.de</code>) sowie ganze Domains inkl. Subdomains (<code>*.relusnelar.org</code> oder <code>relusnelar.org</code>). <strong>Die Whitelist hat immer Vorrang vor der Blacklist.</strong>',
        opt_wl_heading: '✅ Whitelist (Immer erlauben)',
        opt_bl_heading: '⛔ Blacklist (Immer als Spam blockieren)',
        opt_list_count: '{count} Einträge',
        opt_wl_placeholder: 'z.B. *.wichtig.de oder info@partner.com',
        opt_wl_add_btn: '➕ Zur Whitelist',
        opt_wl_empty: 'Keine Einträge auf der Whitelist.',
        opt_bl_placeholder: 'z.B. *.relusnelar.org oder spammer@domain.xyz',
        opt_bl_add_btn: '⛔ Zur Blacklist',
        opt_bl_empty: 'Keine Einträge auf der Blacklist.',

        // Card 5: Live Diagnostics Table
        opt_card_diag_title: '📊 Live-Diagnose – Letzte bewertete E-Mails',
        opt_card_diag_tip: '(Tipp: Rechtsklick oder Schnell-Buttons für Whitelist/Blacklist)',
        opt_diag_stats: '{total} gespeichert · {spam} als Spam eingestuft',
        opt_filter_all: 'Alle Status anzeigen',
        opt_filter_spam: 'Nur erkannte Spam-Mails',
        opt_filter_ok: 'Nur unauffällige Mails (OK)',
        opt_search_placeholder: 'Suche nach Domain, Absender, Betreff…',
        opt_clear_log_btn: '🗑️ Protokoll leeren',
        opt_th_time: 'Zeit',
        opt_th_source: 'Quelle / Ordner',
        opt_th_sender: 'Domain & Absender',
        opt_th_subject: 'Betreff',
        opt_th_checks: 'Einzel-Prüfungen (Hover für Details)',
        opt_th_score_col: 'Score',
        opt_th_result: 'Ergebnis / Aktion',
        opt_th_quick: 'Schnell-Regel (WL / BL)',
        opt_diag_empty: 'Noch keine E-Mails geprüft.',
        opt_diag_no_match: 'Keine passenden Einträge im Diagnose-Protokoll gefunden.',

        // Source labels
        src_auto: 'Automatisch',
        src_folder_scan: 'Ordner-Scan',
        src_context_folder: 'Kontextmenü (Ordner)',
        src_context_messages: 'Kontextmenü (Auswahl)',
        src_selected_messages: 'Auswahl-Scan',
        src_unknown: 'Unbekannt',

        // Context Menu in History Table
        ctx_header_default: 'Absender / Domain',
        ctx_wl_email: '✅ E-Mail zur Whitelist ({email})',
        ctx_wl_domain: '✅ Domain zur Whitelist ({domain})',
        ctx_bl_email: '⛔ E-Mail zur Blacklist ({email})',
        ctx_bl_domain: '⛔ Domain zur Blacklist ({domain})',

        // Status & Toast messages in Options
        toast_saved: '✓ Einstellungen gespeichert',
        toast_reset: '↺ Standard-Scores wiederhergestellt',
        toast_cache_cleared: '✓ DNS/RDAP-Cache geleert',
        toast_list_added: '✓ "{pattern}" zur {list} hinzugefügt',
        toast_list_removed: '✓ "{pattern}" von {list} entfernt',
        toast_err: 'Fehler: {error}',
        scan_starting_folder: 'Starte Prüfung für "{folder}"…',
        scan_starting_active: 'Starte Prüfung des aktiven Ordners…',
        scan_starting_selected: 'Prüfe markierte E-Mails…',
        scan_done_folder: '✓ Ordnerprüfung abgeschlossen: {processed} E-Mails geprüft, {spam} als Spam eingestuft.',
        scan_done_active: '✓ Aktiver Ordner geprüft: {processed} E-Mails geprüft, {spam} als Spam eingestuft.',
        scan_done_selected: '✓ Auswahl geprüft: {processed} E-Mails geprüft, {spam} als Spam eingestuft.',
        bg_not_reachable: 'Hintergrundskript nicht erreichbar – bitte diesen Tab einmal mit F5 neu laden.',

        // Diagnostic check info strings generated in background.js
        info_whitelisted: 'Freigegeben durch Whitelist-Regel: {rule}',
        info_blacklisted: 'Gesperrt durch Blacklist-Regel: {rule}',
        info_dns_active: 'DNS aktiv ({records})',
        info_nxdomain: 'NXDOMAIN (existiert nicht)',
        info_no_a_aaaa_mx: 'Keine A/AAAA/MX Records',
        info_dnssec_valid: 'DNSSEC gültig (AD=true)',
        info_dnssec_none: 'Keine DNSSEC-Signatur',
        info_mx_present: 'MX vorhanden ({count})',
        info_mx_none: 'Kein MX-Record',
        info_spf_none: 'Kein SPF-Record (v=spf1)',
        info_dkim_no_header: 'Kein DKIM-Signature Header in E-Mail',
        info_dkim_found: 'DKIM Schlüssel gefunden ({query})',
        info_dkim_missing: 'Kein DNS-Eintrag für {query}',
        info_dmarc_none: 'Kein DMARC-Record (_dmarc)',
        info_dmarc_active: 'DMARC aktiv (p={policy})',
        info_dmarc_p_none_penalized: 'DMARC hat nur p=none (keine Durchsetzung / typisch für Spam-Domains)',
        info_dmarc_p_none_ok: 'DMARC vorhanden (p=none)',
        info_dmarc_present: 'DMARC vorhanden ({record})',
        info_rdap_unavailable: 'RDAP für TLD nicht verfügbar ({reason})',
        info_rdap_skipped: 'übersprungen',
        info_rdap_invalid_domain: 'Ungültige Domain',
        info_rdap_no_tld: 'Kein RDAP für .{tld}',
        info_rdap_no_regdate: 'Kein Registrierungsdatum im RDAP',
        info_rdap_invalid_date: 'Ungültiges Datum',
        info_rdap_unreachable: 'RDAP-Server nicht erreichbar',
        info_age_ok: 'Alter: {days} Tage (registriert {date}, >= {min}d)',
        info_age_young: 'Frisch registriert: erst {days} Tage alt ({date}, < {min}d)',
        info_dnsbl_clean_ip: 'Nicht gelistet (Domain + IP {ip})',
        info_dnsbl_clean_dom: 'Nicht gelistet (Domain)',
        info_dnsbl_listed: 'Gelistet auf Blacklist: {lists}',
        info_spf_manual_test: 'Keine E-Mail-Header (Manueller Domain-Test)',
        info_spf_header_fail: 'Laut Mailserver-Header ist SPF fehlgeschlagen (spf=fail/softfail)',
        info_spf_header_pass: 'SPF-IP laut Mailserver-Header autorisiert (spf=pass)',
        info_spf_sender_ip: 'Einlieferungs-IP: {ip}',
        info_spf_no_sender_ip: 'Keine externe Einlieferungs-IP im Header',
        info_spf_ip_mismatch: 'Einlieferungs-IP ({ip}) stimmt nicht mit SPF ({allowed}) überein',
        info_spf_ip_plausible: 'Einlieferungs-IP ({ip}) plausibel',
        info_kit_dmarc: 'Generator-DMARC (p=none + postmaster/dmarc)',
        info_kit_mx_spf: 'Spam-Kit MX/SPF-Muster (10 <domain> + v=spf1 a mx ip4 -all)',
        info_kit_dup_ip: 'Redundante A-Record-IP im Baukasten-SPF ({ip})',
        info_kit_snowshoe: 'Snowshoe-SPF ({count} IPs im Netz {prefix}.0/24)',
        info_kit_subdomain: 'Wegwerf-Subdomain mit eigenem Self-MX ({sub}.*)',
        info_kit_detected: 'Spam-Baukasten erkannt: {indicators}',
        info_kit_single: 'Unauffällig (1 Einzelmerkmal: {indicator})',
        info_kit_clean: 'Kein bekannter Spam-Baukasten-Fingerabdruck',

        // Action labels in log entries
        act_no_domain: 'Keine Domain erkannt',
        act_whitelist: 'Whitelist ({rule})',
        act_blacklist_dryrun: 'Blacklist ({rule}) · Dry-Run',
        act_spam_dryrun: 'Spam (Dry-Run – nicht verschoben)',
        act_blacklist_moved: 'Blacklist ({rule}) · Verschoben',
        act_spam_moved: 'Als Spam markiert & verschoben',
        act_error_prefix: 'Fehler: {error}',
        err_mailtabs_unavail: 'mailTabs API nicht verfügbar.',
        err_no_active_folder: 'Kein aktiver Ordner in Thunderbird ausgewählt.',
        err_no_selected_msgs: 'Keine E-Mails in der aktuellen Ansicht ausgewählt.',
        err_no_folder_id: 'Keine Ordner-ID angegeben.',
        err_invalid_domain_input: 'Bitte eine gültige Domain oder E-Mail-Adresse eingeben.',
        err_invalid_list_pattern: 'Kein gültiger Eintrag angegeben.'
    },

    en: {
        // Common & Badges
        lang_auto: 'Automatic (Browser Language)',
        lang_de: 'Deutsch (DE)',
        lang_en: 'English (EN)',
        mode_active_short: 'Active (Move to Junk)',
        mode_dryrun_short: 'Evaluation Mode (Dry-Run)',
        badge_ok: 'OK',
        badge_spam: 'SPAM',
        badge_dryrun: 'DRY-RUN',
        badge_error: 'Error',
        status_disabled: 'Disabled',
        status_off_short: 'off',
        folder_default: 'Mailbox',
        selection_default: 'Selection',
        unknown_domain: '(unknown)',
        no_subject: '(No Subject)',

        // Check Pill short labels
        pill_whitelist: 'Whitelist',
        pill_blacklist: 'Blacklist',
        pill_domainExists: 'Existence',
        pill_domainExists_short: 'DNS',
        pill_dnssec: 'DNSSEC',
        pill_mx: 'MX',
        pill_spf: 'SPF',
        pill_dkim: 'DKIM',
        pill_dmarc: 'DMARC',
        pill_domainAge: 'Age',
        pill_dnsbl: 'DNSBL',
        pill_spfIpMatch: 'SPF-IP',
        pill_spamKitFingerprint: 'Spam-Kit',

        // Quick-Action Buttons
        btn_wl_mail: '+WL Mail',
        btn_wl_dom: '+WL *.Dom',
        btn_bl_mail: '⛔BL Mail',
        btn_bl_dom: '⛔BL *.Dom',
        title_wl_mail: 'Add email ({pattern}) to Whitelist',
        title_wl_dom: 'Add domain ({pattern}) to Whitelist',
        title_bl_mail: 'Add email ({pattern}) to Blacklist',
        title_bl_dom: 'Add domain ({pattern}) to Blacklist',
        title_remove_wl: 'Remove from Whitelist',
        title_remove_bl: 'Remove from Blacklist',

        // Context Menus (Thunderbird folder_pane & message_list)
        action_tooltip: 'Spam Shield – Live diagnostics & folder scanner',
        menu_validate_folder: 'Scan folder for spam domains (Spam Shield)',
        menu_validate_messages: 'Scan selected email(s) for spam domain (Spam Shield)',
        menu_whitelist_email: 'Add sender email to Whitelist (Spam Shield)',
        menu_whitelist_domain: 'Add sender domain (*.domain) to Whitelist (Spam Shield)',
        menu_blacklist_email: 'Add sender email to Blacklist & mark as Spam (Spam Shield)',
        menu_blacklist_domain: 'Add sender domain (*.domain) to Blacklist & mark as Spam (Spam Shield)',

        // Popup UI
        popup_title: 'Spam Shield',
        popup_loading: 'Loading status…',
        popup_open_options: '⚙️ Settings & Diagnostics',
        popup_open_options_title: 'Open configuration & detailed live diagnostics',
        popup_scan_folder: '📂 Scan Current Folder',
        popup_scan_selected: '✉️ Scan Selection',
        popup_dryrun_label: 'Dry-Run',
        popup_dryrun_title: 'When enabled, spam emails are only scored and logged, not moved',
        popup_scanning: 'Scanning…',
        popup_recent_header: 'Recent Evaluations (Live)',
        popup_empty_log: 'No emails evaluated in this session yet.',
        popup_log_summary_zero: '0 entries',
        popup_log_summary: '{total} scanned · {spam} Spam',
        popup_mode_dryrun: 'Threshold: < {threshold} · Evaluation Mode (Dry-Run)',
        popup_mode_active: 'Threshold: < {threshold} · Active (Move to Junk)',
        popup_scan_progress: '{source}: {processed}/{total} (Spam: {spam})',
        popup_status_added_list: '✓ Added "{pattern}" to {list}.',
        popup_status_load_err: 'Failed to load state: {error}',
        popup_status_scanning_folder: 'Scanning current folder…',
        popup_status_folder_err: 'Folder scan failed: {error}',
        popup_status_folder_done: 'Folder scanned: {processed} emails ({spam} Spam).',
        popup_status_scanning_sel: 'Scanning selected emails…',
        popup_status_sel_err: 'Selection scan failed: {error}',
        popup_status_sel_done: 'Selection scanned: {processed} emails ({spam} Spam).',
        conn_error_short: 'Connection error',

        // Options Page UI
        opt_page_title: 'Spam Shield – Configuration & Live Diagnostics',
        opt_header_title: '🛡️ Spam Shield – Configuration & Live Diagnostics',
        opt_header_subtitle: 'Configure validation rules, Whitelist/Blacklist & score weights, run manual folder scans, and monitor recent evaluations in real time.',
        opt_clear_cache_btn: '🔄 Clear DNS/RDAP Cache',
        opt_clear_cache_title: 'Clears the in-memory cache for DNS and RDAP lookups',
        opt_scan_running: 'Folder scan in progress…',
        opt_scan_progress: 'Scanning "{source}": {processed} of {total} emails ({spam} Spam)…',

        // Card 1: Filter Configuration & Scores
        opt_card_config_title: '⚙️ Filter Configuration & Scores',
        opt_language_label: 'Language / Sprache',
        opt_language_hint: 'User interface language (Default: Automatic based on Browser/Thunderbird).',
        opt_threshold_label: 'Spam Threshold (Score < Value = Spam)',
        opt_threshold_hint: 'If a domain’s total score falls below this value (e.g. -51 when set to -50), the email is classified as spam.',
        opt_dryrun_label: 'Evaluation / Dry-Run Mode',
        opt_dryrun_hint: 'When enabled, emails are only scored and listed in Live Diagnostics, but <strong>never</strong> moved or marked as Junk.',
        opt_monitor_all_label: 'Monitor All Email Folders',
        opt_monitor_all_hint: 'Monitors all folders except system folders (Junk, Trash, Sent, Drafts, Archives). When off: Inbox only.',
        opt_max_log_label: 'Live Diagnostics History Size (Last X Emails)',
        opt_max_log_hint: 'Maximum number of evaluated emails stored in the diagnostic log.',
        opt_checks_heading: 'Individual DNS, Reputation & Authentication Checks',
        opt_th_active: 'Enabled',
        opt_th_check: 'Check',
        opt_th_score: 'Penalty Score',
        opt_th_option: 'Option',

        // 10 Checks in Settings Table
        chk1_title: '1. Domain Existence (A / AAAA / MX)',
        chk1_desc: 'Checks whether the domain exists in DNS at all (no NXDOMAIN).',
        chk1_opt_stop: 'Abort immediately',
        chk1_opt_stop_title: 'Skip further DNS queries if the domain does not exist',
        chk2_title: '2. DNSSEC Signature (AD Flag)',
        chk2_desc: 'Checks whether the DNS response is cryptographically signed via DNSSEC.',
        chk3_title: '3. MX Record Present',
        chk3_desc: 'Checks whether the sender domain can receive emails itself.',
        chk4_title: '4. SPF Record Present (v=spf1)',
        chk4_desc: 'Checks whether a valid SPF TXT record is published for the domain.',
        chk5_title: '5. DKIM Signature & DNS Key',
        chk5_desc: 'Verifies the DKIM-Signature header (s=/d=) and the public key in DNS.',
        chk6_title: '6. DMARC Policy (_dmarc)',
        chk6_desc: 'Checks for an enforced DMARC policy (<code>p=quarantine</code> / <code>p=reject</code>). Spammers often omit DMARC or use <code>p=none</code>.',
        chk6_opt_none: 'Penalize <code>p=none</code>',
        chk6_opt_none_title: 'When enabled, p=none (no enforcement) also incurs the penalty score',
        chk7_title: '7. Domain Age / Newly Registered Domains (RDAP)',
        chk7_desc: 'Queries RDAP (WHOIS successor) to detect domains registered very recently for spam campaigns.',
        chk7_opt_days: 'Min. days:',
        chk7_opt_days_title: 'Domains younger than this number of days receive the penalty score',
        chk8_title: '8. DNS Blacklist (Domain & Server IP)',
        chk8_desc: 'Checks the domain and sender/A-record IP against public DNS blacklists (Nordspam, SpamCop, 0spam, Spamhaus).',
        chk9_title: '9. SPF Sender IP Match (Received Header)',
        chk9_desc: 'Checks <code>Authentication-Results</code> / <code>Received</code> headers to verify whether the sending server IP is authorized by SPF.',
        chk10_title: '10. Spam-Kit Fingerprint (DNS Generator Pattern)',
        chk10_desc: 'Detects automatically provisioned fake/spam domains (such as <code>esourl.org</code>, <code>*.relusnelar.org</code>, <code>logicvanta.info</code>, <code>*.heatrica.shop</code>, <code>initives.org</code>) via combined DNS generator patterns (Self-MX <code>10 &lt;domain&gt;</code> + raw-IP SPF + generator DMARC + snowshoe subdomains).',

        opt_save_btn: '💾 Save Settings',
        opt_reset_btn: '↺ Restore Defaults',

        // Card 2: Manual Folder & Message Scan
        opt_card_scan_title: '📂 Manual Folder & Message Scan',
        opt_card_scan_desc: 'You can also scan any folder directly in Thunderbird via <strong>right-click on a folder</strong> or <strong>right-click on selected emails</strong>.',
        opt_folders_loading: 'Loading folders…',
        opt_folders_empty: 'No folders found',
        opt_folders_err: 'Error loading folders: {error}',
        opt_scan_selected_folder_btn: '▶️ Scan Selected Folder',
        opt_scan_active_folder_btn: '📂 Scan Currently Open Folder',
        opt_scan_selected_msgs_btn: '✉️ Scan Selected Emails',

        // Card 3: Live Domain Tester
        opt_card_tester_title: '🔬 Live Domain / Sender Address Tester',
        opt_card_tester_desc: 'Test immediately what score a domain or sender address receives under the currently saved rules (including Whitelist/Blacklist).',
        opt_tester_domain_placeholder: 'e.g. no-reply@snismirpel.com or google.com',
        opt_tester_dkim_placeholder: 'Optional: DKIM-Signature header (e.g. v=1; a=rsa-sha256; d=example.com; s=default; ...)',
        opt_tester_run_btn: '🔍 Check Domain',
        opt_tester_empty_err: 'Please enter a domain or email address.',
        opt_tester_running: 'Checking Whitelist/Blacklist, DNS, SPF, DKIM, DMARC, RDAP (Domain Age), DNSBL & Spam-Kit…',
        opt_tester_status_spam: 'SPAM (below threshold)',
        opt_tester_status_ok: 'OK (Trusted)',

        // Card 4: Whitelist & Blacklist Management
        opt_card_lists_title: '📋 Whitelist & Blacklist Management',
        opt_card_lists_desc: 'Supports individual email addresses (<code>name@domain.com</code>) as well as entire domains including subdomains (<code>*.relusnelar.org</code> or <code>relusnelar.org</code>). <strong>The Whitelist always takes precedence over the Blacklist.</strong>',
        opt_wl_heading: '✅ Whitelist (Always Allow)',
        opt_bl_heading: '⛔ Blacklist (Always Block as Spam)',
        opt_list_count: '{count} entries',
        opt_wl_placeholder: 'e.g. *.trusted.com or info@partner.org',
        opt_wl_add_btn: '➕ Add to Whitelist',
        opt_wl_empty: 'No entries on the Whitelist.',
        opt_bl_placeholder: 'e.g. *.relusnelar.org or spammer@domain.xyz',
        opt_bl_add_btn: '⛔ Add to Blacklist',
        opt_bl_empty: 'No entries on the Blacklist.',

        // Card 5: Live Diagnostics Table
        opt_card_diag_title: '📊 Live Diagnostics – Recently Evaluated Emails',
        opt_card_diag_tip: '(Tip: Right-click or use quick buttons for Whitelist/Blacklist)',
        opt_diag_stats: '{total} stored · {spam} classified as Spam',
        opt_filter_all: 'Show all statuses',
        opt_filter_spam: 'Show detected Spam only',
        opt_filter_ok: 'Show clean emails (OK) only',
        opt_search_placeholder: 'Search domain, sender, subject…',
        opt_clear_log_btn: '🗑️ Clear Log',
        opt_th_time: 'Time',
        opt_th_source: 'Source / Folder',
        opt_th_sender: 'Domain & Sender',
        opt_th_subject: 'Subject',
        opt_th_checks: 'Individual Checks (Hover for details)',
        opt_th_score_col: 'Score',
        opt_th_result: 'Result / Action',
        opt_th_quick: 'Quick Rule (WL / BL)',
        opt_diag_empty: 'No emails evaluated yet.',
        opt_diag_no_match: 'No matching entries found in the diagnostic log.',

        // Source labels
        src_auto: 'Automatic',
        src_folder_scan: 'Folder Scan',
        src_context_folder: 'Context Menu (Folder)',
        src_context_messages: 'Context Menu (Selection)',
        src_selected_messages: 'Selection Scan',
        src_unknown: 'Unknown',

        // Context Menu in History Table
        ctx_header_default: 'Sender / Domain',
        ctx_wl_email: '✅ Add email to Whitelist ({email})',
        ctx_wl_domain: '✅ Add domain to Whitelist ({domain})',
        ctx_bl_email: '⛔ Add email to Blacklist ({email})',
        ctx_bl_domain: '⛔ Add domain to Blacklist ({domain})',

        // Status & Toast messages in Options
        toast_saved: '✓ Settings saved',
        toast_reset: '↺ Default scores restored',
        toast_cache_cleared: '✓ DNS/RDAP cache cleared',
        toast_list_added: '✓ Added "{pattern}" to {list}',
        toast_list_removed: '✓ Removed "{pattern}" from {list}',
        toast_err: 'Error: {error}',
        scan_starting_folder: 'Starting scan for "{folder}"…',
        scan_starting_active: 'Starting scan of active folder…',
        scan_starting_selected: 'Scanning selected emails…',
        scan_done_folder: '✓ Folder scan complete: {processed} emails scanned, {spam} classified as spam.',
        scan_done_active: '✓ Active folder scanned: {processed} emails scanned, {spam} classified as spam.',
        scan_done_selected: '✓ Selection scanned: {processed} emails scanned, {spam} classified as spam.',
        bg_not_reachable: 'Background script not reachable – please reload this tab once (F5).',

        // Diagnostic check info strings generated in background.js
        info_whitelisted: 'Allowed by Whitelist rule: {rule}',
        info_blacklisted: 'Blocked by Blacklist rule: {rule}',
        info_dns_active: 'DNS active ({records})',
        info_nxdomain: 'NXDOMAIN (does not exist)',
        info_no_a_aaaa_mx: 'No A/AAAA/MX records',
        info_dnssec_valid: 'DNSSEC valid (AD=true)',
        info_dnssec_none: 'No DNSSEC signature',
        info_mx_present: 'MX present ({count})',
        info_mx_none: 'No MX record',
        info_spf_none: 'No SPF record (v=spf1)',
        info_dkim_no_header: 'No DKIM-Signature header in email',
        info_dkim_found: 'DKIM key found ({query})',
        info_dkim_missing: 'No DNS record for {query}',
        info_dmarc_none: 'No DMARC record (_dmarc)',
        info_dmarc_active: 'DMARC active (p={policy})',
        info_dmarc_p_none_penalized: 'DMARC is p=none only (no enforcement / typical for spam domains)',
        info_dmarc_p_none_ok: 'DMARC present (p=none)',
        info_dmarc_present: 'DMARC present ({record})',
        info_rdap_unavailable: 'RDAP unavailable for TLD ({reason})',
        info_rdap_skipped: 'skipped',
        info_rdap_invalid_domain: 'Invalid domain',
        info_rdap_no_tld: 'No RDAP for .{tld}',
        info_rdap_no_regdate: 'No registration date in RDAP',
        info_rdap_invalid_date: 'Invalid date',
        info_rdap_unreachable: 'RDAP server unreachable',
        info_age_ok: 'Age: {days} days (registered {date}, >= {min}d)',
        info_age_young: 'Newly registered: only {days} days old ({date}, < {min}d)',
        info_dnsbl_clean_ip: 'Not listed (Domain + IP {ip})',
        info_dnsbl_clean_dom: 'Not listed (Domain)',
        info_dnsbl_listed: 'Listed on blacklist: {lists}',
        info_spf_manual_test: 'No email headers (Manual domain test)',
        info_spf_header_fail: 'Mail server header reports SPF failure (spf=fail/softfail)',
        info_spf_header_pass: 'SPF IP authorized according to mail server header (spf=pass)',
        info_spf_sender_ip: 'Sender IP: {ip}',
        info_spf_no_sender_ip: 'No external sender IP in header',
        info_spf_ip_mismatch: 'Sender IP ({ip}) does not match SPF ({allowed})',
        info_spf_ip_plausible: 'Sender IP ({ip}) plausible',
        info_kit_dmarc: 'Generator DMARC (p=none + postmaster/dmarc)',
        info_kit_mx_spf: 'Spam-Kit MX/SPF pattern (10 <domain> + v=spf1 a mx ip4 -all)',
        info_kit_dup_ip: 'Redundant A-record IP in spam-kit SPF ({ip})',
        info_kit_snowshoe: 'Snowshoe SPF ({count} IPs in subnet {prefix}.0/24)',
        info_kit_subdomain: 'Disposable subdomain with own Self-MX ({sub}.*)',
        info_kit_detected: 'Spam-kit detected: {indicators}',
        info_kit_single: 'Clean (1 single indicator: {indicator})',
        info_kit_clean: 'No known spam-kit fingerprint',

        // Action labels in log entries
        act_no_domain: 'No domain detected',
        act_whitelist: 'Whitelist ({rule})',
        act_blacklist_dryrun: 'Blacklist ({rule}) · Dry-Run',
        act_spam_dryrun: 'Spam (Dry-Run – not moved)',
        act_blacklist_moved: 'Blacklist ({rule}) · Moved',
        act_spam_moved: 'Marked as Spam & moved',
        act_error_prefix: 'Error: {error}',
        err_mailtabs_unavail: 'mailTabs API not available.',
        err_no_active_folder: 'No active folder selected in Thunderbird.',
        err_no_selected_msgs: 'No emails selected in the current view.',
        err_no_folder_id: 'No folder ID specified.',
        err_invalid_domain_input: 'Please enter a valid domain or email address.',
        err_invalid_list_pattern: 'No valid entry specified.'
    }
};

/**
 * Detects the browser / Thunderbird UI language and resolves 'auto' | 'de' | 'en' to either 'de' or 'en'.
 * If the browser language starts with 'de', 'de' is returned; otherwise 'en'.
 * @param {string} [langPref='auto']
 * @returns {'de'|'en'}
 */
function resolveLanguage(langPref = 'auto') {
    const pref = String(langPref || 'auto').toLowerCase().trim();
    if (pref === 'de' || pref === 'en') {
        return pref;
    }

    let uiLang = '';
    try {
        if (typeof messenger !== 'undefined' && messenger.i18n && typeof messenger.i18n.getUILanguage === 'function') {
            uiLang = messenger.i18n.getUILanguage();
        }
    } catch (_err) {
        // Ignore and fall back to navigator.language
    }

    if (!uiLang && typeof navigator !== 'undefined') {
        uiLang = navigator.language || (Array.isArray(navigator.languages) && navigator.languages[0]) || '';
    }

    return String(uiLang || '').toLowerCase().startsWith('de') ? 'de' : 'en';
}

/**
 * Translates a key into the resolved language and interpolates {placeholder} tokens.
 * @param {string} key
 * @param {Record<string, string|number>} [params={}]
 * @param {string} [langPref='auto']
 * @returns {string}
 */
function t(key, params = {}, langPref = 'auto') {
    const lang = resolveLanguage(langPref);
    const dict = I18N_MESSAGES[lang] || I18N_MESSAGES.de;
    let template = dict[key] !== undefined ? dict[key] : (I18N_MESSAGES.de[key] !== undefined ? I18N_MESSAGES.de[key] : key);

    if (params && typeof params === 'object') {
        for (const [k, v] of Object.entries(params)) {
            template = template.replace(new RegExp(`\\{${k}\\}`, 'g'), String(v ?? ''));
        }
    }
    return template;
}

/**
 * Applies translations to all DOM elements carrying data-i18n, data-i18n-html,
 * data-i18n-title, or data-i18n-placeholder attributes.
 * @param {string} [langPref='auto']
 */
function applyI18nToDOM(langPref = 'auto') {
    if (typeof document === 'undefined') {
        return;
    }
    const lang = resolveLanguage(langPref);
    document.documentElement.lang = lang;

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key) {
            el.textContent = t(key, {}, lang);
        }
    });

    document.querySelectorAll('[data-i18n-html]').forEach(el => {
        const key = el.getAttribute('data-i18n-html');
        if (key) {
            el.innerHTML = t(key, {}, lang);
        }
    });

    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (key) {
            el.setAttribute('title', t(key, {}, lang));
        }
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (key) {
            el.setAttribute('placeholder', t(key, {}, lang));
        }
    });
}

