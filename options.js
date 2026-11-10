/**
 * Spam Shield – Options & Live Diagnostics Page Controller
 *
 * Responsibilities:
 *  - Loading, editing, validating and persisting the add-on configuration (scores, thresholds, toggles)
 *  - Managing the Whitelist / Blacklist (chips, inputs, quick buttons, right-click context menu)
 *  - Triggering manual folder / selection scans and displaying live scan progress
 *  - Running the interactive Live Domain Tester
 *  - Rendering the filterable Live Diagnostics history table
 *
 * All DOM output is built with safe DOM APIs (createElement / textContent / replaceChildren);
 * no innerHTML assignments are used (required for addons.thunderbird.net review).
 */

// ---------------------------------------------------------------------------
// Default configuration
// ---------------------------------------------------------------------------

/**
 * Default configuration (kept in sync with background.js so the options page can also
 * operate directly on storage.local when the background script is temporarily unavailable).
 * Each entry in `checks` corresponds to one validation tier:
 *  - enabled: whether the check is evaluated at all
 *  - score:   penalty (negative number) added to the total score if the check fails
 *  - additional per-check options (stopOnFail, penalizeNone, minAgeDays)
 */
const DEFAULT_SETTINGS = {
    language: 'auto',
    spamThreshold: -50,
    dryRun: false,
    monitorAllFolders: true,
    maxLogEntries: 100,
    showMessageBanner: true,
    autoCheckOnDisplay: false,
    tagEvaluatedMessages: true,
    whitelist: [],
    blacklist: [],
    checks: {
        domainExists: { enabled: true, score: -100, stopOnFail: true },
        dnssec: { enabled: true, score: -10 },
        mx: { enabled: true, score: -20 },
        spf: { enabled: true, score: -50 },
        dkim: { enabled: true, score: -20 },
        dmarc: { enabled: true, score: -20, penalizeNone: true },
        domainAge: { enabled: true, score: -40, minAgeDays: 90 },
        dnsbl: {
            enabled: true,
            score: -80,
            minHits: 1,
            providers: {
                nordspam: true,
                spamhaus: true,
                spamcop: true,
                nixspam: true,
                zerospam: true,
                dronebl: false
            }
        },
        spfIpMatch: { enabled: true, score: -40 },
        spamKitFingerprint: { enabled: true, score: -80 }
    }
};

/**
 * Creates a deep copy of DEFAULT_SETTINGS so callers can mutate the result
 * without accidentally modifying the shared default object.
 * @returns {object} A fresh, independent settings object containing all default values.
 */
function cloneDefaults() {
    return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
}

/**
 * Merges a (possibly partial or outdated) saved settings object with the current defaults.
 * Ensures that newly introduced checks or options always exist with sensible default values,
 * even if the stored configuration was written by an older add-on version.
 * @param {object|null|undefined} saved Settings object loaded from storage or background.js.
 * @returns {object} A complete settings object (all checks present, whitelist/blacklist guaranteed to be arrays).
 */
function mergeWithDefaults(saved) {
    const base = cloneDefaults();
    if (!saved || typeof saved !== 'object') {
        return base;
    }
    // Merge each check individually so that missing sub-options fall back to their defaults
    const mergedChecks = {};
    for (const [key, defVal] of Object.entries(base.checks)) {
        const savedCheck = saved.checks && saved.checks[key] ? saved.checks[key] : {};
        const mergedCheck = Object.assign({}, defVal, savedCheck);
        if (defVal.providers) {
            mergedCheck.providers = Object.assign({}, defVal.providers, savedCheck.providers || {});
        }
        mergedChecks[key] = mergedCheck;
    }
    const whitelist = Array.isArray(saved.whitelist) ? saved.whitelist : [];
    const blacklist = Array.isArray(saved.blacklist) ? saved.blacklist : [];
    return Object.assign({}, base, saved, { checks: mergedChecks, whitelist, blacklist });
}

/**
 * Safely sends a runtime message to background.js without throwing an uncaught exception
 * if the background event page is asleep or the options tab was kept open across an addon reload.
 * @param {object} payload Message object containing an `action` property and optional parameters.
 * @returns {Promise<any|null>} The response of background.js, or null if communication failed.
 */
async function sendToBackground(payload) {
    if (!messenger.runtime || typeof messenger.runtime.sendMessage !== 'function') {
        return null;
    }
    try {
        return await messenger.runtime.sendMessage(payload);
    } catch (err) {
        console.warn(`sendMessage(${payload && payload.action}) fallback:`, err);
        return null;
    }
}

// ---------------------------------------------------------------------------
// DOM element references
// ---------------------------------------------------------------------------

// DOM elements – Settings
const languageSelect = document.getElementById('languageSelect');
const spamThresholdInput = document.getElementById('spamThreshold');
const dryRunInput = document.getElementById('dryRun');
const monitorAllFoldersInput = document.getElementById('monitorAllFolders');
const maxLogEntriesInput = document.getElementById('maxLogEntries');
const showMessageBannerInput = document.getElementById('showMessageBanner');
const autoCheckOnDisplayInput = document.getElementById('autoCheckOnDisplay');
const tagEvaluatedMessagesInput = document.getElementById('tagEvaluatedMessages');
const currentModeBadge = document.getElementById('currentModeBadge');
const saveStatus = document.getElementById('saveStatus');
const clearCacheBtn = document.getElementById('clearCacheBtn');
const cacheCountEl = document.getElementById('cacheCount');

/**
 * Maps each validation check key to its corresponding form controls.
 * Used by populateSettingsForm() and collectSettingsFromForm() to read/write values generically.
 * Optional controls (stopOnFail, penalizeNone, minAgeDays) only exist for specific checks.
 */
const chkFields = {
    domainExists: {
        enabled: document.getElementById('chk_domainExists_enabled'),
        score: document.getElementById('chk_domainExists_score'),
        stopOnFail: document.getElementById('chk_domainExists_stop')
    },
    dnssec: {
        enabled: document.getElementById('chk_dnssec_enabled'),
        score: document.getElementById('chk_dnssec_score')
    },
    mx: {
        enabled: document.getElementById('chk_mx_enabled'),
        score: document.getElementById('chk_mx_score')
    },
    spf: {
        enabled: document.getElementById('chk_spf_enabled'),
        score: document.getElementById('chk_spf_score')
    },
    dkim: {
        enabled: document.getElementById('chk_dkim_enabled'),
        score: document.getElementById('chk_dkim_score')
    },
    dmarc: {
        enabled: document.getElementById('chk_dmarc_enabled'),
        score: document.getElementById('chk_dmarc_score'),
        penalizeNone: document.getElementById('chk_dmarc_penalizeNone')
    },
    domainAge: {
        enabled: document.getElementById('chk_domainAge_enabled'),
        score: document.getElementById('chk_domainAge_score'),
        minAgeDays: document.getElementById('chk_domainAge_minDays')
    },
    dnsbl: {
        enabled: document.getElementById('chk_dnsbl_enabled'),
        score: document.getElementById('chk_dnsbl_score'),
        minHits: document.getElementById('chk_dnsbl_minHits'),
        providers: {
            nordspam: document.getElementById('chk_dnsbl_prov_nordspam'),
            spamhaus: document.getElementById('chk_dnsbl_prov_spamhaus'),
            spamcop: document.getElementById('chk_dnsbl_prov_spamcop'),
            nixspam: document.getElementById('chk_dnsbl_prov_nixspam'),
            zerospam: document.getElementById('chk_dnsbl_prov_zerospam'),
            dronebl: document.getElementById('chk_dnsbl_prov_dronebl')
        }
    },
    spfIpMatch: {
        enabled: document.getElementById('chk_spfIpMatch_enabled'),
        score: document.getElementById('chk_spfIpMatch_score')
    },
    spamKitFingerprint: {
        enabled: document.getElementById('chk_spamKitFingerprint_enabled'),
        score: document.getElementById('chk_spamKitFingerprint_score')
    }
};

const saveSettingsBtn = document.getElementById('saveSettingsBtn');
const resetSettingsBtn = document.getElementById('resetSettingsBtn');

// DOM elements – Whitelist & Blacklist
const whitelistInput = document.getElementById('whitelistInput');
const addWhitelistBtn = document.getElementById('addWhitelistBtn');
const whitelistChips = document.getElementById('whitelistChips');
const whitelistCount = document.getElementById('whitelistCount');

const blacklistInput = document.getElementById('blacklistInput');
const addBlacklistBtn = document.getElementById('addBlacklistBtn');
const blacklistChips = document.getElementById('blacklistChips');
const blacklistCount = document.getElementById('blacklistCount');

// DOM elements – Folder Scan & Domain Tester
const folderSelect = document.getElementById('folderSelect');
const scanSelectedFolderBtn = document.getElementById('scanSelectedFolderBtn');
const scanActiveFolderBtn = document.getElementById('scanActiveFolderBtn');
const scanSelectedMsgsBtn = document.getElementById('scanSelectedMsgsBtn');
const folderScanResult = document.getElementById('folderScanResult');
const scanBanner = document.getElementById('scanBanner');
const scanText = document.getElementById('scanText');
const scanProgressFill = document.getElementById('scanProgressFill');

const testDomainInput = document.getElementById('testDomainInput');
const testDkimInput = document.getElementById('testDkimInput');
const runDomainTestBtn = document.getElementById('runDomainTestBtn');
const domainTestOutput = document.getElementById('domainTestOutput');

// DOM elements – Live Diagnostics Table & Context Menu
const diagStats = document.getElementById('diagStats');
const logFilterStatus = document.getElementById('logFilterStatus');
const logSearchInput = document.getElementById('logSearchInput');
const clearLogBtn = document.getElementById('clearLogBtn');
const diagTableBody = document.getElementById('diagTableBody');

const historyContextMenu = document.getElementById('historyContextMenu');
const ctxMenuHeader = document.getElementById('ctxMenuHeader');
const ctxWlEmail = document.getElementById('ctxWlEmail');
const ctxWlDomain = document.getElementById('ctxWlDomain');
const ctxBlEmail = document.getElementById('ctxBlEmail');
const ctxBlDomain = document.getElementById('ctxBlDomain');

// ---------------------------------------------------------------------------
// Page state
// ---------------------------------------------------------------------------

/** Currently active (merged) settings shown in the form. */
let currentSettingsState = cloneDefaults();
/** Complete diagnostic log (unfiltered) as delivered by background.js / storage. */
let fullDiagnosticLog = [];
/** Email address and wildcard domain of the history row the context menu was opened on. */
let ctxMenuTarget = { email: '', domainPattern: '' };
/** Last folder list received from background.js (cached to re-render after a language switch). */
let lastFolderList = null;

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

/**
 * Shortcut translation helper bound to the currently configured UI language.
 * @param {string} key Translation key from I18N_MESSAGES (i18n.js).
 * @param {object} [params={}] Placeholder values, e.g. { count: 3 } for "{count}".
 * @returns {string} The localized and interpolated text.
 */
function tr(key, params = {}) {
    return t(key, params, currentSettingsState.language || 'auto');
}

/**
 * Returns the BCP 47 locale code used for date/time formatting in the diagnostics table.
 * @returns {string} 'de-DE' when the effective UI language is German, otherwise 'en-US'.
 */
function getLocaleCode() {
    return resolveLanguage(currentSettingsState.language || 'auto') === 'de' ? 'de-DE' : 'en-US';
}

/**
 * Escapes HTML special characters in a string.
 * Kept as a defensive utility; current rendering uses textContent and does not require it.
 * @param {string} str Raw input text.
 * @returns {string} Escaped text that is safe to embed in HTML markup or attributes.
 */
function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Shows a short-lived status toast in the page header (e.g. "Saved", "Cache cleared").
 * The message is cleared automatically after 3.5 seconds unless it was replaced in the meantime.
 * @param {string} msg Localized message to display.
 */
function flashSaveStatus(msg) {
    saveStatus.textContent = msg;
    setTimeout(() => {
        if (saveStatus.textContent === msg) {
            saveStatus.textContent = '';
        }
    }, 3500);
}

/**
 * Extracts a normalized email address from an RFC 5322 author string
 * (e.g. "John Doe <john@example.com>" -> "john@example.com").
 * @param {string} author Raw author/From header value.
 * @returns {string} Lowercase email address, or an empty string if none could be found.
 */
function getEmailFromAuthorString(author) {
    if (!author || typeof author !== 'string') return '';
    const angleMatch = author.match(/<([^<>]+)>/);
    const part = (angleMatch ? angleMatch[1] : author).trim();
    if (!part.includes('@')) return '';
    return part.replace(/^[<"'\s]+|[>"'\s]+$/g, '').toLowerCase();
}

/**
 * Checks whether a domain value is a placeholder for "no domain could be determined".
 * Placeholders are written by background.js when sender parsing fails.
 * @param {string} domain Domain value from a log entry.
 * @returns {boolean} True if the domain is empty or a known placeholder ('(unbekannt)', '(unknown)', '-').
 */
function isUnknownDomain(domain) {
    return !domain || domain === '(unbekannt)' || domain === '(unknown)' || domain === '-';
}

/**
 * Extracts the registrable root domain from a hostname (e.g. "mail.news.example.co.uk" -> "example.co.uk").
 * Uses a small built-in list of common two-part public suffixes instead of the full Public Suffix List.
 * Used to build wildcard patterns such as "*.example.com" for the Whitelist / Blacklist quick buttons.
 * @param {string} domain Hostname or domain.
 * @returns {string} Registrable domain, or an empty string for unknown/placeholder values.
 */
function getRegistrableDomain(domain) {
    if (isUnknownDomain(domain)) return '';
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

// ---------------------------------------------------------------------------
// Rendering: language, mode badge, rule lists
// ---------------------------------------------------------------------------

/**
 * Re-applies all static and dynamic translations for the currently selected language.
 * Static texts are translated via data-i18n attributes (applyI18nToDOM in i18n.js);
 * dynamically generated parts (badge, chips, table, folder dropdown) are re-rendered.
 */
function applyLanguage() {
    applyI18nToDOM(currentSettingsState.language || 'auto');
    updateModeBadge(currentSettingsState.dryRun);
    renderRuleLists(currentSettingsState);
    renderDiagnosticTable();
    if (lastFolderList) {
        renderFolderOptions(lastFolderList);
    }
}

/**
 * Updates the mode badge next to the Dry-Run setting.
 * @param {boolean} isDryRun True = evaluation mode (no messages are moved), false = active mode.
 */
function updateModeBadge(isDryRun) {
    if (isDryRun) {
        currentModeBadge.className = 'badge badge-warn';
        currentModeBadge.textContent = tr('mode_dryrun_short');
    } else {
        currentModeBadge.className = 'badge badge-ok';
        currentModeBadge.textContent = tr('mode_active_short');
    }
}

/**
 * Renders the Whitelist and Blacklist as removable "chips" including their entry counters.
 * Each chip contains a remove button carrying data-list / data-pattern attributes, which are
 * handled by the delegated click listeners on whitelistChips / blacklistChips.
 * @param {object} settings Settings object containing `whitelist` and `blacklist` arrays.
 */
function renderRuleLists(settings) {
    const wl = Array.isArray(settings.whitelist) ? settings.whitelist : [];
    const bl = Array.isArray(settings.blacklist) ? settings.blacklist : [];

    whitelistCount.textContent = tr('opt_list_count', { count: wl.length });
    blacklistCount.textContent = tr('opt_list_count', { count: bl.length });

    if (wl.length === 0) {
        const span = document.createElement('span');
        span.className = 'muted text-md';
        span.textContent = tr('opt_wl_empty');
        whitelistChips.replaceChildren(span);
    } else {
        const removeTitle = tr('title_remove_wl');
        const chipNodes = wl.map(pattern => {
            const chip = document.createElement('span');
            chip.className = 'rule-chip whitelist-chip';
            const label = document.createElement('span');
            label.textContent = pattern;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.dataset.list = 'whitelist';
            btn.dataset.pattern = pattern;
            btn.title = removeTitle;
            btn.textContent = '✕';
            chip.append(label, btn);
            return chip;
        });
        whitelistChips.replaceChildren(...chipNodes);
    }

    if (bl.length === 0) {
        const span = document.createElement('span');
        span.className = 'muted text-md';
        span.textContent = tr('opt_bl_empty');
        blacklistChips.replaceChildren(span);
    } else {
        const removeTitle = tr('title_remove_bl');
        const chipNodes = bl.map(pattern => {
            const chip = document.createElement('span');
            chip.className = 'rule-chip blacklist-chip';
            const label = document.createElement('span');
            label.textContent = pattern;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.dataset.list = 'blacklist';
            btn.dataset.pattern = pattern;
            btn.title = removeTitle;
            btn.textContent = '✕';
            chip.append(label, btn);
            return chip;
        });
        blacklistChips.replaceChildren(...chipNodes);
    }
}

// ---------------------------------------------------------------------------
// Settings & list persistence
// ---------------------------------------------------------------------------

/**
 * Adds or removes a pattern on the Whitelist or Blacklist.
 * The change is applied locally (optimistic UI), written to storage.local and forwarded to
 * background.js so the running filter immediately uses the updated rule set.
 * New entries are inserted at the top; duplicates (case-insensitive) are ignored.
 * @param {'whitelist'|'blacklist'} listType Target list.
 * @param {'add'|'remove'} op Operation to perform.
 * @param {string} rawPattern Email address (user@domain.tld) or domain pattern (*.domain.tld / domain.tld).
 * @returns {Promise<void>}
 */
async function modifyListEntry(listType, op, rawPattern) {
    const pattern = String(rawPattern || '').trim().toLowerCase();
    if (!pattern) return;

    const list = Array.isArray(currentSettingsState[listType]) ? [...currentSettingsState[listType]] : [];
    if (op === 'add') {
        if (!list.some(item => String(item).toLowerCase() === pattern)) {
            list.unshift(pattern);
        }
    } else if (op === 'remove') {
        const idx = list.findIndex(item => String(item).toLowerCase() === pattern);
        if (idx !== -1) {
            list.splice(idx, 1);
        }
    }

    currentSettingsState[listType] = list;
    if (messenger.storage && messenger.storage.local) {
        await messenger.storage.local.set({ settings: currentSettingsState });
    }
    await sendToBackground({
        action: 'MODIFY_LIST',
        listType,
        op,
        pattern
    });

    renderRuleLists(currentSettingsState);
    const listLabel = listType === 'whitelist' ? tr('pill_whitelist') : tr('pill_blacklist');
    flashSaveStatus(op === 'add'
        ? tr('toast_list_added', { pattern, list: listLabel })
        : tr('toast_list_removed', { pattern, list: listLabel }));
}

/**
 * Fills all form controls (language, threshold, dry-run, check toggles, scores and options)
 * from the given settings and stores the merged result as the current page state.
 * @param {object} settings Settings object (partial objects are merged with defaults).
 */
function populateSettingsForm(settings) {
    const merged = mergeWithDefaults(settings);
    currentSettingsState = merged;

    languageSelect.value = ['auto', 'de', 'en'].includes(merged.language) ? merged.language : 'auto';
    spamThresholdInput.value = merged.spamThreshold ?? -50;
    dryRunInput.checked = Boolean(merged.dryRun);
    monitorAllFoldersInput.checked = merged.monitorAllFolders !== false;
    maxLogEntriesInput.value = merged.maxLogEntries ?? 100;
    if (showMessageBannerInput) showMessageBannerInput.checked = merged.showMessageBanner !== false;
    if (autoCheckOnDisplayInput) autoCheckOnDisplayInput.checked = Boolean(merged.autoCheckOnDisplay);
    if (tagEvaluatedMessagesInput) tagEvaluatedMessagesInput.checked = merged.tagEvaluatedMessages !== false;

    const checks = merged.checks || {};
    for (const [key, fields] of Object.entries(chkFields)) {
        if (!fields.enabled || !fields.score) continue;
        const cfg = checks[key] || {};
        fields.enabled.checked = cfg.enabled !== false;
        fields.score.value = cfg.score ?? 0;
        if (fields.stopOnFail) {
            fields.stopOnFail.checked = cfg.stopOnFail !== false;
        }
        if (fields.penalizeNone) {
            fields.penalizeNone.checked = cfg.penalizeNone !== false;
        }
        if (fields.minAgeDays) {
            fields.minAgeDays.value = cfg.minAgeDays ?? 90;
        }
        if (fields.minHits) {
            fields.minHits.value = Math.max(1, Number(cfg.minHits) || 1);
        }
        if (fields.providers) {
            const defProv = (DEFAULT_SETTINGS.checks[key] && DEFAULT_SETTINGS.checks[key].providers) || {};
            const provCfg = cfg.providers || {};
            for (const [pKey, pInput] of Object.entries(fields.providers)) {
                if (pInput) {
                    const fallback = defProv[pKey] ?? true;
                    pInput.checked = provCfg[pKey] !== undefined ? Boolean(provCfg[pKey]) : fallback;
                }
            }
        }
    }

    syncDnsblProvidersState();
    applyLanguage();
}

/**
 * Reads all form controls and builds a complete settings object ready to be persisted.
 * Numeric inputs are sanitized (fallback to defaults, minimum values enforced).
 * Whitelist and Blacklist are taken from the current state, as they are edited separately.
 * @returns {object} Settings object in the same structure as DEFAULT_SETTINGS.
 */
function collectSettingsFromForm() {
    const checks = {};
    for (const [key, fields] of Object.entries(chkFields)) {
        if (!fields.enabled || !fields.score) continue;
        checks[key] = {
            enabled: fields.enabled.checked,
            score: Number(fields.score.value) || 0
        };
        if (fields.stopOnFail) {
            checks[key].stopOnFail = fields.stopOnFail.checked;
        }
        if (fields.penalizeNone) {
            checks[key].penalizeNone = fields.penalizeNone.checked;
        }
        if (fields.minAgeDays) {
            checks[key].minAgeDays = Math.max(1, Number(fields.minAgeDays.value) || 90);
        }
        if (fields.minHits) {
            checks[key].minHits = Math.max(1, Number(fields.minHits.value) || 1);
        }
        if (fields.providers) {
            checks[key].providers = {};
            for (const [pKey, pInput] of Object.entries(fields.providers)) {
                if (pInput) {
                    checks[key].providers[pKey] = pInput.checked;
                }
            }
        }
    }

    return {
        language: languageSelect.value || 'auto',
        spamThreshold: Number(spamThresholdInput.value) || -50,
        dryRun: dryRunInput.checked,
        monitorAllFolders: monitorAllFoldersInput.checked,
        maxLogEntries: Math.max(10, Number(maxLogEntriesInput.value) || 100),
        showMessageBanner: showMessageBannerInput ? showMessageBannerInput.checked : true,
        autoCheckOnDisplay: autoCheckOnDisplayInput ? autoCheckOnDisplayInput.checked : false,
        tagEvaluatedMessages: tagEvaluatedMessagesInput ? tagEvaluatedMessagesInput.checked : true,
        whitelist: Array.isArray(currentSettingsState.whitelist) ? currentSettingsState.whitelist : [],
        blacklist: Array.isArray(currentSettingsState.blacklist) ? currentSettingsState.blacklist : [],
        checks
    };
}

// ---------------------------------------------------------------------------
// Rendering: diagnostics table, scan banner, folder dropdown
// ---------------------------------------------------------------------------

/**
 * Builds a container element holding one "pill" badge per validation check.
 *  - Whitelisted / blacklisted results show a single pill (all other checks were skipped).
 *  - Otherwise each check is shown as passed (✓, green), failed (✗, red, incl. score delta)
 *    or disabled (grey). The detailed check info is available as hover tooltip.
 * @param {object|null} checks Check results as returned by validateDomainDetailed (background.js).
 * @returns {HTMLDivElement} A div.check-pills element ready to be appended to the DOM.
 */
function buildCheckPillsElement(checks) {
    const container = document.createElement('div');
    container.className = 'check-pills';

    if (!checks || Object.keys(checks).length === 0) {
        const span = document.createElement('span');
        span.className = 'muted';
        span.textContent = '–';
        container.appendChild(span);
        return container;
    }
    if (checks.whitelist) {
        const label = tr('pill_whitelist');
        const pill = document.createElement('span');
        pill.className = 'check-pill pass';
        pill.title = checks.whitelist.info || label;
        pill.textContent = `✓ ${label}`;
        container.appendChild(pill);
        return container;
    }
    if (checks.blacklist) {
        const label = tr('pill_blacklist');
        const pill = document.createElement('span');
        pill.className = 'check-pill fail';
        pill.title = checks.blacklist.info || label;
        pill.textContent = `⛔ ${label} (${checks.blacklist.scoreDelta})`;
        container.appendChild(pill);
        return container;
    }

    const labels = [
        ['domainExists', tr('pill_domainExists')],
        ['dnssec', tr('pill_dnssec')],
        ['mx', tr('pill_mx')],
        ['spf', tr('pill_spf')],
        ['dkim', tr('pill_dkim')],
        ['dmarc', tr('pill_dmarc')],
        ['domainAge', tr('pill_domainAge')],
        ['dnsbl', tr('pill_dnsbl')],
        ['spfIpMatch', tr('pill_spfIpMatch')],
        ['spamKitFingerprint', tr('pill_spamKitFingerprint')]
    ];
    for (const [key, label] of labels) {
        const c = checks[key];
        if (!c) continue;
        const pill = document.createElement('span');
        if (!c.enabled) {
            pill.className = 'check-pill off';
            pill.title = `${label}: ${tr('status_disabled')}`;
            pill.textContent = `${label}: ${tr('status_off_short')}`;
        } else {
            const cls = c.passed ? 'pass' : 'fail';
            const icon = c.passed ? '✓' : '✗';
            const deltaStr = c.scoreDelta ? ` (${c.scoreDelta})` : '';
            pill.className = `check-pill ${cls}`;
            pill.title = `${label}: ${c.info || ''}`;
            pill.textContent = `${icon} ${label}${deltaStr}`;
        }
        container.appendChild(pill);
    }
    return container;
}

/**
 * Translates the internal scan source identifier of a log entry into a readable label.
 * @param {string} source 'auto' | 'folder-scan' | 'context-folder' | 'context-messages' | 'selected-messages'
 * @returns {string} Localized label (falls back to the raw value or "unknown").
 */
function formatSourceLabel(source) {
    switch (source) {
        case 'auto': return tr('src_auto');
        case 'folder-scan': return tr('src_folder_scan');
        case 'context-folder': return tr('src_context_folder');
        case 'context-messages': return tr('src_context_messages');
        case 'selected-messages': return tr('src_selected_messages');
        default: return source || tr('src_unknown');
    }
}

/**
 * Creates a single table row (<tr>) for the Live Diagnostics history table.
 * Columns: 1) time/date, 2) folder/source, 3) domain/author, 4) subject,
 *          5) check pills, 6) score/threshold, 7) action badge, 8) quick list buttons.
 * The row carries data-row-email / data-row-domain attributes used by the right-click context menu.
 * @param {object} entry Diagnostic log entry written by background.js.
 * @param {string} localeCode Locale code for date/time formatting (see getLocaleCode()).
 * @returns {HTMLTableRowElement} Fully populated table row.
 */
function createDiagnosticRow(entry, localeCode) {
    const trEl = document.createElement('tr');
    const email = entry.senderEmail || getEmailFromAuthorString(entry.author);
    const rootDom = getRegistrableDomain(entry.domain) || (!isUnknownDomain(entry.domain) ? entry.domain : '');
    const domainWildcard = rootDom ? `*.${rootDom}` : '';

    if (email) trEl.dataset.rowEmail = email;
    if (domainWildcard) trEl.dataset.rowDomain = domainWildcard;

    // Col 1: Time & Date
    const tdTime = document.createElement('td');
    tdTime.className = 'nowrap';
    const dt = new Date(entry.timestamp);
    const timeStr = dt.toLocaleTimeString(localeCode, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const dateStr = dt.toLocaleDateString(localeCode);
    const dTime = document.createElement('div');
    const strongTime = document.createElement('strong');
    strongTime.textContent = timeStr;
    dTime.appendChild(strongTime);
    const dDate = document.createElement('div');
    dDate.className = 'muted text-xs';
    dDate.textContent = dateStr;
    tdTime.append(dTime, dDate);

    // Col 2: Folder & Source
    const tdFolder = document.createElement('td');
    const dFold = document.createElement('div');
    const strongFold = document.createElement('strong');
    strongFold.textContent = entry.folderName || '';
    dFold.appendChild(strongFold);
    const dSrc = document.createElement('div');
    dSrc.className = 'muted text-sm';
    dSrc.textContent = formatSourceLabel(entry.source);
    tdFolder.append(dFold, dSrc);

    // Col 3: Domain & Author
    const tdDom = document.createElement('td');
    const dDom = document.createElement('div');
    const strongDom = document.createElement('strong');
    strongDom.textContent = entry.domain || '';
    dDom.appendChild(strongDom);
    const dAuth = document.createElement('div');
    dAuth.className = 'muted truncate diag-auth';
    dAuth.title = entry.author || '';
    dAuth.textContent = entry.author || '';
    tdDom.append(dDom, dAuth);

    // Col 4: Subject
    const tdSubj = document.createElement('td');
    tdSubj.className = 'diag-subj';
    const dSubj = document.createElement('div');
    dSubj.title = entry.subject || '';
    dSubj.textContent = entry.subject || '';
    tdSubj.appendChild(dSubj);

    // Col 5: Check pills
    const tdChecks = document.createElement('td');
    tdChecks.className = 'diag-checks';
    tdChecks.appendChild(buildCheckPillsElement(entry.checks));

    // Col 6: Score
    const tdScore = document.createElement('td');
    tdScore.className = 'nowrap';
    const strongScore = document.createElement('strong');
    strongScore.className = entry.isSpam ? 'diag-score-val text-danger' : 'diag-score-val text-success';
    strongScore.textContent = String(entry.score);
    const spanThresh = document.createElement('span');
    spanThresh.className = 'muted text-sm';
    spanThresh.textContent = ` / ${entry.threshold}`;
    tdScore.append(strongScore, spanThresh);

    // Col 7: Badge / Status
    const tdStatus = document.createElement('td');
    const badge = document.createElement('span');
    let badgeClass = 'badge-ok';
    if (entry.actionTaken === 'moved') {
        badgeClass = 'badge-spam';
    } else if (entry.actionTaken === 'dry-run') {
        badgeClass = 'badge-warn';
    } else if (entry.actionTaken === 'error') {
        badgeClass = 'badge-neutral';
    }
    badge.className = `badge ${badgeClass}`;
    badge.textContent = entry.actionLabel || entry.actionTaken;
    tdStatus.appendChild(badge);

    // Col 8: Quick buttons
    const tdActions = document.createElement('td');
    if (email || domainWildcard) {
        const btnGroup = document.createElement('div');
        btnGroup.className = 'mini-btn-group';

        if (email) {
            const btnWlMail = document.createElement('button');
            btnWlMail.type = 'button';
            btnWlMail.className = 'mini-btn wl';
            btnWlMail.dataset.quickList = 'whitelist';
            btnWlMail.dataset.quickPattern = email;
            btnWlMail.title = tr('title_wl_mail', { pattern: email });
            btnWlMail.textContent = tr('btn_wl_mail');
            btnGroup.appendChild(btnWlMail);
        }
        if (domainWildcard) {
            const btnWlDom = document.createElement('button');
            btnWlDom.type = 'button';
            btnWlDom.className = 'mini-btn wl';
            btnWlDom.dataset.quickList = 'whitelist';
            btnWlDom.dataset.quickPattern = domainWildcard;
            btnWlDom.title = tr('title_wl_dom', { pattern: domainWildcard });
            btnWlDom.textContent = tr('btn_wl_dom');
            btnGroup.appendChild(btnWlDom);
        }
        if (email) {
            const btnBlMail = document.createElement('button');
            btnBlMail.type = 'button';
            btnBlMail.className = 'mini-btn bl';
            btnBlMail.dataset.quickList = 'blacklist';
            btnBlMail.dataset.quickPattern = email;
            btnBlMail.title = tr('title_bl_mail', { pattern: email });
            btnBlMail.textContent = tr('btn_bl_mail');
            btnGroup.appendChild(btnBlMail);
        }
        if (domainWildcard) {
            const btnBlDom = document.createElement('button');
            btnBlDom.type = 'button';
            btnBlDom.className = 'mini-btn bl';
            btnBlDom.dataset.quickList = 'blacklist';
            btnBlDom.dataset.quickPattern = domainWildcard;
            btnBlDom.title = tr('title_bl_dom', { pattern: domainWildcard });
            btnBlDom.textContent = tr('btn_bl_dom');
            btnGroup.appendChild(btnBlDom);
        }
        tdActions.appendChild(btnGroup);
    } else {
        const spanMuted = document.createElement('span');
        spanMuted.className = 'muted';
        spanMuted.textContent = '–';
        tdActions.appendChild(spanMuted);
    }

    trEl.append(tdTime, tdFolder, tdDom, tdSubj, tdChecks, tdScore, tdStatus, tdActions);
    return trEl;
}

/**
 * Renders the Live Diagnostics table from fullDiagnosticLog.
 * Applies the status filter (all / spam / ok) and the free-text search (domain, author,
 * subject, folder), updates the statistics line and shows an empty-state row if nothing matches.
 */
function renderDiagnosticTable() {
    const statusFilter = logFilterStatus.value;
    const query = (logSearchInput.value || '').trim().toLowerCase();

    const spamCount = fullDiagnosticLog.filter(e => e.isSpam).length;
    diagStats.textContent = tr('opt_diag_stats', { total: fullDiagnosticLog.length, spam: spamCount });

    const filtered = fullDiagnosticLog.filter(entry => {
        if (statusFilter === 'spam' && !entry.isSpam) return false;
        if (statusFilter === 'ok' && entry.isSpam) return false;
        if (query) {
            const hay = `${entry.domain} ${entry.author} ${entry.subject} ${entry.folderName}`.toLowerCase();
            if (!hay.includes(query)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        const emptyKey = fullDiagnosticLog.length === 0 ? 'opt_diag_empty' : 'opt_diag_no_match';
        const emptyTr = document.createElement('tr');
        const emptyTd = document.createElement('td');
        emptyTd.colSpan = 8;
        emptyTd.className = 'muted empty-table-cell';
        emptyTd.textContent = tr(emptyKey);
        emptyTr.appendChild(emptyTd);
        diagTableBody.replaceChildren(emptyTr);
        return;
    }

    const localeCode = getLocaleCode();
    const rows = filtered.map(entry => createDiagnosticRow(entry, localeCode));
    diagTableBody.replaceChildren(...rows);
}

/**
 * Shows/updates the scan progress banner (text and progress bar) while a scan is running
 * and disables all scan buttons to prevent parallel scans. Hides the banner when finished.
 * @param {object|null} scanState Scan state from background.js ({ running, sourceName, processed, total, spamCount }).
 */
function updateScanBanner(scanState) {
    if (!scanState || !scanState.running) {
        scanBanner.classList.add('hidden');
        scanSelectedFolderBtn.disabled = false;
        scanActiveFolderBtn.disabled = false;
        scanSelectedMsgsBtn.disabled = false;
        return;
    }

    scanBanner.classList.remove('hidden');
    scanSelectedFolderBtn.disabled = true;
    scanActiveFolderBtn.disabled = true;
    scanSelectedMsgsBtn.disabled = true;

    const pct = scanState.total > 0 ? Math.round((scanState.processed / scanState.total) * 100) : 0;
    scanText.textContent = tr('opt_scan_progress', {
        source: scanState.sourceName,
        processed: scanState.processed,
        total: scanState.total,
        spam: scanState.spamCount
    });
    scanProgressFill.style.width = `${pct}%`;
}

/**
 * Fills the folder dropdown used for manual folder scans.
 * The previously selected folder is restored if it still exists in the new list.
 * @param {Array<{id: string, displayPath: string}>} folders Folder list from background.js.
 */
function renderFolderOptions(folders) {
    if (!Array.isArray(folders) || folders.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = tr('opt_folders_empty');
        folderSelect.replaceChildren(opt);
        return;
    }
    const currentVal = folderSelect.value;
    const optionNodes = folders.map(f => {
        const opt = document.createElement('option');
        opt.value = f.id;
        opt.textContent = f.displayPath;
        return opt;
    });
    folderSelect.replaceChildren(...optionNodes);
    if (currentVal && folders.some(f => f.id === currentVal)) {
        folderSelect.value = currentVal;
    }
}

/**
 * Requests the list of all mail folders (across all accounts) from background.js
 * and populates the folder dropdown. Shows an error option if loading fails.
 * @returns {Promise<void>}
 */
async function loadFoldersDropdown() {
    try {
        const res = await sendToBackground({ action: 'GET_ALL_FOLDERS' });
        lastFolderList = (res && res.folders) || [];
        renderFolderOptions(lastFolderList);
    } catch (err) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = tr('opt_folders_err', { error: err.message });
        folderSelect.replaceChildren(opt);
    }
}

/**
 * Loads the current add-on state (settings, diagnostic log, cache size, scan state).
 * storage.local is read first as a fallback; the live state from background.js takes precedence.
 * @param {boolean} [includeSettingsForm=false] If true, all form fields are overwritten with the loaded
 *        settings (used on initial page load). If false, only lists/table are refreshed so that
 *        unsaved form edits by the user are not lost.
 * @returns {Promise<void>}
 */
async function loadState(includeSettingsForm = false) {
    try {
        let storedSettings = null;
        let storedLog = null;
        if (messenger.storage && messenger.storage.local) {
            const localData = await messenger.storage.local.get(['settings', 'diagnosticLog']);
            storedSettings = localData.settings;
            storedLog = localData.diagnosticLog;
        }

        const state = await sendToBackground({ action: 'GET_STATE' });
        const effectiveSettings = mergeWithDefaults((state && state.settings) || storedSettings);

        cacheCountEl.textContent = (state && state.cacheSize) ?? 0;
        fullDiagnosticLog = (state && Array.isArray(state.diagnosticLog))
            ? state.diagnosticLog
            : (Array.isArray(storedLog) ? storedLog : []);

        if (includeSettingsForm) {
            populateSettingsForm(effectiveSettings);
        } else {
            const langChanged = effectiveSettings.language !== currentSettingsState.language;
            currentSettingsState = effectiveSettings;
            if (langChanged) {
                applyLanguage();
            } else {
                renderRuleLists(effectiveSettings);
                renderDiagnosticTable();
            }
        }
        updateScanBanner(state ? state.scanState : null);
    } catch (err) {
        console.error('Failed to load state:', err);
    }
}

/**
 * Persists the given settings both directly in storage.local and via background.js.
 * Writing to storage.local directly ensures the change survives even if the background
 * script is currently not reachable; the SAVE_SETTINGS message updates the running filter.
 * @param {object} newSettings Complete settings object to store.
 * @returns {Promise<void>}
 */
async function persistSettings(newSettings) {
    if (messenger.storage && messenger.storage.local) {
        await messenger.storage.local.set({ settings: newSettings });
    }
    await sendToBackground({
        action: 'SAVE_SETTINGS',
        settings: newSettings
    });
}

/**
 * Enables or disables the individual DNSBL provider checkboxes depending on whether
 * the primary DNSBL check checkbox is enabled.
 */
function syncDnsblProvidersState() {
    const isEnabled = chkFields.dnsbl && chkFields.dnsbl.enabled ? chkFields.dnsbl.enabled.checked : true;
    if (chkFields.dnsbl && chkFields.dnsbl.minHits) {
        chkFields.dnsbl.minHits.disabled = !isEnabled;
    }
    if (chkFields.dnsbl && chkFields.dnsbl.providers) {
        for (const input of Object.values(chkFields.dnsbl.providers)) {
            if (input) {
                input.disabled = !isEnabled;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Event listeners
// ---------------------------------------------------------------------------

if (chkFields.dnsbl && chkFields.dnsbl.enabled) {
    chkFields.dnsbl.enabled.addEventListener('change', syncDnsblProvidersState);
}

// Event listeners – Language switch (applied and saved immediately)
languageSelect.addEventListener('change', async () => {
    currentSettingsState.language = languageSelect.value || 'auto';
    try {
        await persistSettings(currentSettingsState);
    } catch (err) {
        console.error('Save language error:', err);
    }
    applyLanguage();
    flashSaveStatus(tr('toast_saved'));
});

// Event listeners – Settings
// Save: collect all form values, persist them and re-render the form with the normalized values
saveSettingsBtn.addEventListener('click', async () => {
    try {
        const newSettings = collectSettingsFromForm();
        await persistSettings(newSettings);
        populateSettingsForm(newSettings);
        flashSaveStatus(tr('toast_saved'));
    } catch (err) {
        console.error('Save settings error:', err);
        flashSaveStatus(tr('toast_err', { error: err.message || err }));
    }
});

// Reset: restore default checks/scores while keeping the user's lists and language
resetSettingsBtn.addEventListener('click', async () => {
    try {
        const defaults = cloneDefaults();
        // Keep the user's custom whitelist/blacklist and language when resetting check scores
        defaults.whitelist = Array.isArray(currentSettingsState.whitelist) ? currentSettingsState.whitelist : [];
        defaults.blacklist = Array.isArray(currentSettingsState.blacklist) ? currentSettingsState.blacklist : [];
        defaults.language = currentSettingsState.language || 'auto';
        await persistSettings(defaults);
        populateSettingsForm(defaults);
        flashSaveStatus(tr('toast_reset'));
    } catch (err) {
        console.error('Reset settings error:', err);
        flashSaveStatus(tr('toast_err', { error: err.message || err }));
    }
});

// Event listeners – Whitelist & Blacklist inputs & chip removal
// Add buttons read the input field, clear it and add the pattern; Enter key triggers the add button
addWhitelistBtn.addEventListener('click', async () => {
    const val = whitelistInput.value.trim();
    if (!val) return;
    whitelistInput.value = '';
    await modifyListEntry('whitelist', 'add', val);
});

whitelistInput.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        addWhitelistBtn.click();
    }
});

addBlacklistBtn.addEventListener('click', async () => {
    const val = blacklistInput.value.trim();
    if (!val) return;
    blacklistInput.value = '';
    await modifyListEntry('blacklist', 'add', val);
});

blacklistInput.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        addBlacklistBtn.click();
    }
});

// Delegated click handlers: remove a list entry when its chip's ✕ button is clicked
whitelistChips.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-list="whitelist"]');
    if (!btn) return;
    await modifyListEntry('whitelist', 'remove', btn.getAttribute('data-pattern'));
});

blacklistChips.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-list="blacklist"]');
    if (!btn) return;
    await modifyListEntry('blacklist', 'remove', btn.getAttribute('data-pattern'));
});

// Event listeners – Quick buttons & right-click context menu in the history table
// Quick buttons (+WL / ⛔BL) inside the history table rows (delegated click handler)
diagTableBody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-quick-list]');
    if (!btn) return;
    const listType = btn.getAttribute('data-quick-list');
    const pattern = btn.getAttribute('data-quick-pattern');
    await modifyListEntry(listType, 'add', pattern);
});

// Custom right-click context menu on history rows: offers Whitelist/Blacklist actions
// for the row's sender email and wildcard domain. The menu is clamped to stay inside the viewport.
diagTableBody.addEventListener('contextmenu', (e) => {
    const row = e.target.closest('tr[data-row-email], tr[data-row-domain]');
    if (!row) return;
    const email = row.getAttribute('data-row-email') || '';
    const domainPattern = row.getAttribute('data-row-domain') || '';
    if (!email && !domainPattern) return;

    e.preventDefault();
    ctxMenuTarget = { email, domainPattern };
    ctxMenuHeader.textContent = email ? `${email} (${domainPattern})` : domainPattern;

    ctxWlEmail.classList.toggle('hidden', !email);
    ctxWlEmail.textContent = tr('ctx_wl_email', { email });

    ctxWlDomain.classList.toggle('hidden', !domainPattern);
    ctxWlDomain.textContent = tr('ctx_wl_domain', { domain: domainPattern });

    ctxBlEmail.classList.toggle('hidden', !email);
    ctxBlEmail.textContent = tr('ctx_bl_email', { email });

    ctxBlDomain.classList.toggle('hidden', !domainPattern);
    ctxBlDomain.textContent = tr('ctx_bl_domain', { domain: domainPattern });

    // Approximate menu dimensions used to keep the menu fully visible near the window edges
    const menuWidth = 310;
    const menuHeight = 160;
    const x = Math.min(e.clientX, window.innerWidth - menuWidth - 10);
    const y = Math.min(e.clientY, window.innerHeight - menuHeight - 10);

    historyContextMenu.style.left = `${Math.max(8, x)}px`;
    historyContextMenu.style.top = `${Math.max(8, y)}px`;
    historyContextMenu.classList.add('visible');
});

/**
 * Hides the custom history context menu.
 * Triggered by any click on the page or by scrolling.
 */
function hideContextMenu() {
    historyContextMenu.classList.remove('visible');
}

document.addEventListener('click', hideContextMenu);
window.addEventListener('scroll', hideContextMenu, true);

// Context menu actions use the target captured when the menu was opened
ctxWlEmail.addEventListener('click', () => modifyListEntry('whitelist', 'add', ctxMenuTarget.email));
ctxWlDomain.addEventListener('click', () => modifyListEntry('whitelist', 'add', ctxMenuTarget.domainPattern));
ctxBlEmail.addEventListener('click', () => modifyListEntry('blacklist', 'add', ctxMenuTarget.email));
ctxBlDomain.addEventListener('click', () => modifyListEntry('blacklist', 'add', ctxMenuTarget.domainPattern));

// Event listeners – Cache, Folder Scan, Domain Tester
// Clears the in-memory DNS/RDAP cache in background.js (forces fresh lookups on the next scan)
clearCacheBtn.addEventListener('click', async () => {
    await sendToBackground({ action: 'CLEAR_DNS_CACHE' });
    cacheCountEl.textContent = '0';
    flashSaveStatus(tr('toast_cache_cleared'));
});

/**
 * Displays the result of a manual scan request below the scan buttons.
 * @param {object|null} res Response from background.js ({ processed, spamCount } or { error }).
 * @param {string} doneKey Translation key for the success message.
 * @returns {boolean} True if the scan succeeded (caller should reload the state), false on error.
 */
function reportScanResult(res, doneKey) {
    if (!res || res.error) {
        folderScanResult.textContent = tr('toast_err', { error: (res && res.error) || tr('bg_not_reachable') });
        return false;
    }
    folderScanResult.textContent = tr(doneKey, { processed: res.processed, spam: res.spamCount });
    return true;
}

// Scans the folder selected in the dropdown
scanSelectedFolderBtn.addEventListener('click', async () => {
    const folderId = folderSelect.value;
    if (!folderId) return;
    const folderName = folderSelect.options[folderSelect.selectedIndex]?.text || folderId;
    folderScanResult.textContent = tr('scan_starting_folder', { folder: folderName });
    const res = await sendToBackground({
        action: 'SCAN_FOLDER_BY_ID',
        folderId,
        folderName
    });
    if (reportScanResult(res, 'scan_done_folder')) {
        await loadState(false);
    }
});

// Scans the folder currently displayed in the active Thunderbird mail tab
scanActiveFolderBtn.addEventListener('click', async () => {
    folderScanResult.textContent = tr('scan_starting_active');
    const res = await sendToBackground({ action: 'SCAN_ACTIVE_FOLDER' });
    if (reportScanResult(res, 'scan_done_active')) {
        await loadState(false);
    }
});

// Scans the messages currently selected in the active Thunderbird mail tab
scanSelectedMsgsBtn.addEventListener('click', async () => {
    folderScanResult.textContent = tr('scan_starting_selected');
    const res = await sendToBackground({ action: 'SCAN_SELECTED_MESSAGES' });
    if (reportScanResult(res, 'scan_done_selected')) {
        await loadState(false);
    }
});

// Live Domain Tester: validates a domain or full sender address (optionally with a DKIM-Signature
// header) against the active rule set and renders the result card with score, status and check pills
runDomainTestBtn.addEventListener('click', async () => {
    const input = testDomainInput.value.trim();
    const dkimHeader = testDkimInput.value.trim();
    if (!input) {
        const span = document.createElement('span');
        span.className = 'text-danger';
        span.textContent = tr('opt_tester_empty_err');
        domainTestOutput.replaceChildren(span);
        return;
    }

    const spanRunning = document.createElement('span');
    spanRunning.className = 'muted';
    spanRunning.textContent = tr('opt_tester_running');
    domainTestOutput.replaceChildren(spanRunning);

    const res = await sendToBackground({
        action: 'TEST_DOMAIN',
        input,
        dkimHeader: dkimHeader || null
    });
    if (!res || res.error) {
        const spanErr = document.createElement('span');
        spanErr.className = 'text-danger';
        spanErr.textContent = tr('toast_err', { error: (res && res.error) || tr('bg_not_reachable') });
        domainTestOutput.replaceChildren(spanErr);
        return;
    }
    const badgeCls = res.isSpam ? 'badge-spam' : 'badge-ok';
    const statusTxt = res.whitelisted
        ? `WHITELIST (${res.matchedRule})`
        : (res.blacklisted ? `BLACKLIST (${res.matchedRule})` : (res.isSpam ? tr('opt_tester_status_spam') : tr('opt_tester_status_ok')));

    const card = document.createElement('div');
    card.className = 'tester-card';

    const cardHeader = document.createElement('div');
    cardHeader.className = 'tester-card-header';

    const strongTitle = document.createElement('strong');
    strongTitle.textContent = `Domain: ${res.domain}${res.senderEmail ? ` (${res.senderEmail})` : ''}`;

    const badgeSpan = document.createElement('span');
    badgeSpan.className = `badge ${badgeCls}`;
    badgeSpan.textContent = `Score: ${res.score} · ${statusTxt}`;

    cardHeader.append(strongTitle, badgeSpan);
    card.append(cardHeader, buildCheckPillsElement(res.checks));
    domainTestOutput.replaceChildren(card);

    await loadState(false);
});

// Re-render the history table whenever the status filter or the search text changes
logFilterStatus.addEventListener('change', renderDiagnosticTable);
logSearchInput.addEventListener('input', renderDiagnosticTable);

// Clears the complete diagnostic history (storage.local and in-memory log in background.js)
clearLogBtn.addEventListener('click', async () => {
    if (messenger.storage && messenger.storage.local) {
        await messenger.storage.local.set({ diagnosticLog: [] });
    }
    await sendToBackground({ action: 'CLEAR_LOG' });
    fullDiagnosticLog = [];
    renderDiagnosticTable();
});

// Live updates broadcast by background.js: scan progress, scan completion, new log entries, settings changes
if (messenger.runtime && messenger.runtime.onMessage) {
    messenger.runtime.onMessage.addListener((msg) => {
        if (!msg) return;
        if (msg.type === 'SCAN_PROGRESS' || msg.type === 'SCAN_COMPLETE') {
            updateScanBanner(msg.scanState);
            if (msg.type === 'SCAN_COMPLETE') {
                loadState(false);
            }
        } else if (msg.type === 'LOG_UPDATED' || msg.type === 'SETTINGS_UPDATED') {
            loadState(false);
        }
    });
}

// Keeps the page in sync when storage.local is modified elsewhere
// (e.g. by the popup, the Thunderbird context menus or another open options tab)
if (messenger.storage && messenger.storage.onChanged) {
    messenger.storage.onChanged.addListener((changes, area) => {
        if (area === 'local') {
            if (changes.diagnosticLog) {
                fullDiagnosticLog = Array.isArray(changes.diagnosticLog.newValue) ? changes.diagnosticLog.newValue : [];
                renderDiagnosticTable();
            }
            if (changes.settings && changes.settings.newValue) {
                const next = mergeWithDefaults(changes.settings.newValue);
                const langChanged = next.language !== currentSettingsState.language;
                currentSettingsState = next;
                if (langChanged) {
                    languageSelect.value = next.language || 'auto';
                    applyLanguage();
                } else {
                    renderRuleLists(currentSettingsState);
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Initial load: translate static texts, load state incl. form values, populate folder dropdown
// ---------------------------------------------------------------------------
applyI18nToDOM(currentSettingsState.language);
loadState(true);
loadFoldersDropdown();
