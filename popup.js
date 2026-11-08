/**
 * Spam Shield – Toolbar Popup Controller
 * Manages quick scanning actions (current folder / selected messages),
 * dry-run toggling, live progress banner updates, and recent evaluation history.
 */

// DOM Elements
const modeIndicator = document.getElementById('modeIndicator');
const openOptionsBtn = document.getElementById('openOptionsBtn');
const scanFolderBtn = document.getElementById('scanFolderBtn');
const scanSelectedBtn = document.getElementById('scanSelectedBtn');
const quickDryRunToggle = document.getElementById('quickDryRunToggle');
const scanBanner = document.getElementById('scanBanner');
const scanText = document.getElementById('scanText');
const scanProgressFill = document.getElementById('scanProgressFill');
const statusMsg = document.getElementById('statusMsg');
const popupLogList = document.getElementById('popupLogList');
const logSummary = document.getElementById('logSummary');

// State variables
let currentSettings = null;
let currentLang = 'auto';

/**
 * Safely transmits a message payload to the background service worker/script.
 * Catches and logs errors without throwing unhandled exceptions if the background is inactive.
 * @param {object} payload Message payload containing an `action` property and optional parameters.
 * @returns {Promise<any|null>} Response from background.js, or null on communication error.
 */
async function sendToBackground(payload) {
    if (!messenger.runtime || typeof messenger.runtime.sendMessage !== 'function') {
        return null;
    }
    try {
        return await messenger.runtime.sendMessage(payload);
    } catch (err) {
        console.warn(`sendMessage(${payload && payload.action}) error:`, err);
        return null;
    }
}

/**
 * Displays a temporary status or error notification message beneath the header.
 * @param {string} text The localized status message text to show.
 * @param {boolean} [isError=false] Whether the status represents an error (styled in danger color).
 */
function showStatus(text, isError = false) {
    statusMsg.style.display = 'block';
    statusMsg.style.color = isError ? 'var(--danger)' : 'var(--text-muted)';
    statusMsg.textContent = text;
}

/**
 * Updates the active scan progress banner (percentage, item counts, source label)
 * or hides the banner when no scan is actively running.
 * @param {object|null} scanState The current scan progress object from background.js.
 */
function updateScanBanner(scanState) {
    if (!scanState || !scanState.running) {
        scanBanner.classList.add('hidden');
        scanFolderBtn.disabled = false;
        scanSelectedBtn.disabled = false;
        return;
    }

    scanBanner.classList.remove('hidden');
    scanFolderBtn.disabled = true;
    scanSelectedBtn.disabled = true;
    const pct = scanState.total > 0 ? Math.round((scanState.processed / scanState.total) * 100) : 0;
    scanText.textContent = t('popup_scan_progress', {
        source: scanState.sourceName,
        processed: scanState.processed,
        total: scanState.total,
        spam: scanState.spamCount
    }, currentLang);
    scanProgressFill.style.width = `${pct}%`;
}

/**
 * Builds an array of DOM span elements representing diagnostic check pill badges.
 * Formats passed (green), failed (red), and disabled (grey) statuses with localized tooltip details.
 * @param {object|null} checks Dictionary of check results from validateDomainDetailed.
 * @param {string} lang Active locale code ('de', 'en', or 'auto').
 * @returns {HTMLElement[]} Array of HTMLSpanElement nodes to insert into the DOM.
 */
function buildCheckPills(checks, lang) {
    if (!checks) return [];
    if (checks.whitelist) {
        const wlLabel = t('pill_whitelist', {}, lang);
        const pill = document.createElement('span');
        pill.className = 'check-pill pass';
        pill.title = checks.whitelist.info || wlLabel;
        pill.textContent = `✓ ${wlLabel}`;
        return [pill];
    }
    if (checks.blacklist) {
        const blLabel = t('pill_blacklist', {}, lang);
        const pill = document.createElement('span');
        pill.className = 'check-pill fail';
        pill.title = checks.blacklist.info || blLabel;
        pill.textContent = `⛔ ${blLabel}`;
        return [pill];
    }

    const labels = [
        ['domainExists', t('pill_domainExists_short', {}, lang)],
        ['dnssec', t('pill_dnssec', {}, lang)],
        ['mx', t('pill_mx', {}, lang)],
        ['spf', t('pill_spf', {}, lang)],
        ['dkim', t('pill_dkim', {}, lang)],
        ['dmarc', t('pill_dmarc', {}, lang)],
        ['domainAge', t('pill_domainAge', {}, lang)],
        ['dnsbl', t('pill_dnsbl', {}, lang)],
        ['spfIpMatch', t('pill_spfIpMatch', {}, lang)],
        ['spamKitFingerprint', t('pill_spamKitFingerprint', {}, lang)]
    ];
    const disabledTxt = t('status_disabled', {}, lang).toLowerCase();
    const pills = [];
    for (const [key, label] of labels) {
        const c = checks[key];
        const pill = document.createElement('span');
        if (!c || !c.enabled) {
            pill.className = 'check-pill off';
            pill.title = `${label}: ${disabledTxt}`;
            pill.textContent = label;
        } else {
            const cls = c.passed ? 'pass' : 'fail';
            const deltaStr = c.scoreDelta ? ` (${c.scoreDelta})` : '';
            const info = c.info || '';
            pill.className = `check-pill ${cls}`;
            pill.title = `${label}: ${info}${deltaStr}`;
            pill.textContent = `${label}${deltaStr}`;
        }
        pills.push(pill);
    }
    return pills;
}

/**
 * Creates a fully populated DOM node for a single evaluation entry in the popup log.
 * Avoids innerHTML assignments by assembling safe DOM child elements directly.
 * @param {object} entry Evaluation log record (domain, score, author, subject, checks, etc.).
 * @param {string} localeCode Standardized locale string (e.g. 'de-DE' or 'en-US') for time formatting.
 * @returns {HTMLElement} The root div element for the log item card.
 */
function createPopupLogItem(entry, localeCode) {
    const item = document.createElement('div');
    item.className = 'popup-log-item';

    // 1. Header row: domain name and overall score badge
    const header = document.createElement('div');
    header.className = 'popup-log-item-header';
    const strongDomain = document.createElement('strong');
    strongDomain.className = 'truncate';
    strongDomain.title = entry.author || '';
    strongDomain.textContent = entry.domain || '';

    const badge = document.createElement('span');
    let badgeClass = 'badge-ok';
    let badgeText = `${t('badge_ok', {}, currentLang)} (${entry.score})`;
    if (entry.actionTaken === 'moved') {
        badgeClass = 'badge-spam';
        badgeText = `${t('badge_spam', {}, currentLang)} (${entry.score})`;
    } else if (entry.actionTaken === 'dry-run') {
        badgeClass = 'badge-warn';
        badgeText = `${t('badge_dryrun', {}, currentLang)} (${entry.score})`;
    } else if (entry.actionTaken === 'error') {
        badgeClass = 'badge-neutral';
        badgeText = t('badge_error', {}, currentLang);
    }
    badge.className = `badge ${badgeClass}`;
    badge.title = entry.actionLabel || '';
    badge.textContent = badgeText;
    header.append(strongDomain, badge);

    // 2. Subject line
    const subjDiv = document.createElement('div');
    subjDiv.className = 'truncate muted';
    subjDiv.style.fontSize = '11.5px';
    subjDiv.title = entry.subject || '';
    subjDiv.textContent = entry.subject || '';

    // 3. Meta row: individual check pill badges + folder name and timestamp
    const metaRow = document.createElement('div');
    metaRow.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:6px; margin-top:2px;';
    const pillsDiv = document.createElement('div');
    pillsDiv.className = 'check-pills';
    pillsDiv.append(...buildCheckPills(entry.checks, currentLang));

    const timeStr = new Date(entry.timestamp).toLocaleTimeString(localeCode, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const metaSpan = document.createElement('span');
    metaSpan.className = 'muted';
    metaSpan.style.cssText = 'font-size:10.5px; white-space:nowrap;';
    metaSpan.textContent = `${entry.folderName || ''} · ${timeStr}`;
    metaRow.append(pillsDiv, metaSpan);

    // 4. Quick action buttons: Whitelist / Blacklist for specific email and wildcard domain
    const btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex; justify-content:flex-end; gap:4px; margin-top:2px;';

    const email = entry.senderEmail || getEmailFromAuthorString(entry.author);
    const rootDom = getRegistrableDomain(entry.domain) || (entry.domain !== '(unbekannt)' && entry.domain !== '(unknown)' && entry.domain !== '-' ? entry.domain : '');
    const domainWildcard = rootDom ? `*.${rootDom}` : '';

    if (email) {
        const btnWlMail = document.createElement('button');
        btnWlMail.type = 'button';
        btnWlMail.className = 'mini-btn wl';
        btnWlMail.dataset.quickList = 'whitelist';
        btnWlMail.dataset.quickPattern = email;
        btnWlMail.title = t('title_wl_mail', { pattern: email }, currentLang);
        btnWlMail.textContent = t('btn_wl_mail', {}, currentLang);
        btnRow.appendChild(btnWlMail);
    }
    if (domainWildcard) {
        const btnWlDom = document.createElement('button');
        btnWlDom.type = 'button';
        btnWlDom.className = 'mini-btn wl';
        btnWlDom.dataset.quickList = 'whitelist';
        btnWlDom.dataset.quickPattern = domainWildcard;
        btnWlDom.title = t('title_wl_dom', { pattern: domainWildcard }, currentLang);
        btnWlDom.textContent = t('btn_wl_dom', {}, currentLang);
        btnRow.appendChild(btnWlDom);
    }
    if (email) {
        const btnBlMail = document.createElement('button');
        btnBlMail.type = 'button';
        btnBlMail.className = 'mini-btn bl';
        btnBlMail.dataset.quickList = 'blacklist';
        btnBlMail.dataset.quickPattern = email;
        btnBlMail.title = t('title_bl_mail', { pattern: email }, currentLang);
        btnBlMail.textContent = t('btn_bl_mail', {}, currentLang);
        btnRow.appendChild(btnBlMail);
    }
    if (domainWildcard) {
        const btnBlDom = document.createElement('button');
        btnBlDom.type = 'button';
        btnBlDom.className = 'mini-btn bl';
        btnBlDom.dataset.quickList = 'blacklist';
        btnBlDom.dataset.quickPattern = domainWildcard;
        btnBlDom.title = t('title_bl_dom', { pattern: domainWildcard }, currentLang);
        btnBlDom.textContent = t('btn_bl_dom', {}, currentLang);
        btnRow.appendChild(btnBlDom);
    }

    item.append(header, subjDiv, metaRow, btnRow);
    return item;
}

/**
 * Renders the compact list of recent evaluations in the popup window.
 * Limits the feed to the last 12 entries and uses replaceChildren for fast, safe DOM updates.
 * @param {Array<object>} log Array of recent evaluation log entries.
 */
function renderPopupLog(log) {
    if (!Array.isArray(log) || log.length === 0) {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'muted';
        emptyDiv.style.cssText = 'padding:16px; text-align:center;';
        emptyDiv.textContent = t('popup_empty_log', {}, currentLang);
        popupLogList.replaceChildren(emptyDiv);
        logSummary.textContent = t('popup_log_summary_zero', {}, currentLang);
        return;
    }

    const spamTotal = log.filter(e => e.isSpam).length;
    logSummary.textContent = t('popup_log_summary', { total: log.length, spam: spamTotal }, currentLang);

    const localeCode = resolveLanguage(currentLang) === 'de' ? 'de-DE' : 'en-US';
    const recent = log.slice(0, 12);
    const items = recent.map(entry => createPopupLogItem(entry, localeCode));
    popupLogList.replaceChildren(...items);
}

/**
 * Escapes unsafe characters in plain text for safe inclusion in HTML or attributes.
 * @param {string} str The raw string to escape.
 * @returns {string} Sanitized string safe for DOM usage.
 */
function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Extracts a normalized email address from a RFC 5322 author string (e.g. "Name <user@domain.com>").
 * @param {string} author Raw author string from message header.
 * @returns {string} Normalized lowercase email address or empty string.
 */
function getEmailFromAuthorString(author) {
    if (!author || typeof author !== 'string') return '';
    const angleMatch = author.match(/<([^<>]+)>/);
    const part = (angleMatch ? angleMatch[1] : author).trim();
    if (!part.includes('@')) return '';
    return part.replace(/^[<"'\s]+|[>"'\s]+$/g, '').toLowerCase();
}

/**
 * Extracts the registrable root domain (e.g. 'example.co.uk' or 'example.com') from a hostname,
 * correctly handling recognized multi-part second-level public suffixes.
 * @param {string} domain Domain or hostname string.
 * @returns {string} Clean root domain or empty string.
 */
function getRegistrableDomain(domain) {
    if (!domain || domain === '(unbekannt)' || domain === '(unknown)' || domain === '-') return '';
    const parts = domain.toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    const twoPartTlds = new Set([
        'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
        'co.at', 'or.at', 'gv.at', 'ac.at',
        'com.au', 'net.au', 'org.au',
        'co.jp', 'ne.jp', 'or.jp',
        'com.br', 'com.mx', 'co.nz', 'co.za', 'com.tr', 'com.pl', 'com.cn'
    ]);
    const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}

/**
 * Refreshes the popup state by fetching configuration, active scan status,
 * and the latest diagnostic evaluation entries from storage and background.js.
 * @returns {Promise<void>}
 */
async function refreshState() {
    try {
        let localData = {};
        if (messenger.storage && messenger.storage.local) {
            localData = await messenger.storage.local.get(['settings', 'diagnosticLog']);
        }
        const state = await sendToBackground({ action: 'GET_STATE' });
        currentSettings = (state && state.settings) || localData.settings || { language: 'auto', spamThreshold: -50, dryRun: false };
        currentLang = currentSettings.language || 'auto';
        applyI18nToDOM(currentLang);

        quickDryRunToggle.checked = Boolean(currentSettings.dryRun);
        modeIndicator.textContent = currentSettings.dryRun
            ? t('popup_mode_dryrun', { threshold: currentSettings.spamThreshold }, currentLang)
            : t('popup_mode_active', { threshold: currentSettings.spamThreshold }, currentLang);
        updateScanBanner(state ? state.scanState : null);
        renderPopupLog((state && state.diagnosticLog) || localData.diagnosticLog || []);
    } catch (err) {
        showStatus(t('popup_status_load_err', { error: err.message || err }, currentLang), true);
    }
}

// ---------------------------------------------------------------------------
// Event Listeners
// ---------------------------------------------------------------------------

// Handles quick Whitelist / Blacklist action button clicks in the recent evaluations log
popupLogList.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-quick-list]');
    if (!btn) return;
    const listType = btn.getAttribute('data-quick-list');
    const pattern = String(btn.getAttribute('data-quick-pattern') || '').trim().toLowerCase();
    if (!pattern) return;

    await sendToBackground({
        action: 'MODIFY_LIST',
        listType,
        op: 'add',
        pattern
    });
    const label = listType === 'whitelist' ? t('pill_whitelist', {}, currentLang) : t('pill_blacklist', {}, currentLang);
    showStatus(t('popup_status_added_list', { pattern, list: label }, currentLang));
});

// Opens the full options and detailed live diagnostics page in a dedicated tab
openOptionsBtn.addEventListener('click', () => {
    messenger.runtime.openOptionsPage();
    window.close();
});

// Toggles Evaluation / Dry-Run mode immediately and syncs with background storage
quickDryRunToggle.addEventListener('change', async () => {
    if (!currentSettings) return;
    currentSettings.dryRun = quickDryRunToggle.checked;
    if (messenger.storage && messenger.storage.local) {
        await messenger.storage.local.set({ settings: currentSettings });
    }
    await sendToBackground({
        action: 'SAVE_SETTINGS',
        settings: currentSettings
    });
    await refreshState();
});

// Triggers manual validation scan of all messages in the currently active Thunderbird folder
scanFolderBtn.addEventListener('click', async () => {
    showStatus(t('popup_status_scanning_folder', {}, currentLang));
    const res = await sendToBackground({ action: 'SCAN_ACTIVE_FOLDER' });
    if (!res || res.error) {
        showStatus(t('popup_status_folder_err', { error: (res && res.error) || t('conn_error_short', {}, currentLang) }, currentLang), true);
        return;
    }
    showStatus(t('popup_status_folder_done', { processed: res.processed, spam: res.spamCount }, currentLang));
    await refreshState();
});

// Triggers manual validation scan of currently highlighted/selected messages in Thunderbird
scanSelectedBtn.addEventListener('click', async () => {
    showStatus(t('popup_status_scanning_sel', {}, currentLang));
    const res = await sendToBackground({ action: 'SCAN_SELECTED_MESSAGES' });
    if (!res || res.error) {
        showStatus(t('popup_status_sel_err', { error: (res && res.error) || t('conn_error_short', {}, currentLang) }, currentLang), true);
        return;
    }
    showStatus(t('popup_status_sel_done', { processed: res.processed, spam: res.spamCount }, currentLang));
    await refreshState();
});

// Listens for real-time progress broadcasts and live log updates from background.js
if (messenger.runtime && messenger.runtime.onMessage) {
    messenger.runtime.onMessage.addListener((msg) => {
        if (!msg) return;
        if (msg.type === 'SCAN_PROGRESS' || msg.type === 'SCAN_COMPLETE') {
            updateScanBanner(msg.scanState);
            if (msg.type === 'SCAN_COMPLETE') {
                refreshState();
            }
        } else if (msg.type === 'LOG_UPDATED' || msg.type === 'SETTINGS_UPDATED') {
            refreshState();
        }
    });
}

// Initial state load on popup open
refreshState();
