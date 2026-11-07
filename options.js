// Default configuration (kept in sync with background.js so the options page can also operate directly on storage.local)
const DEFAULT_SETTINGS = {
    language: 'auto',
    spamThreshold: -50,
    dryRun: false,
    monitorAllFolders: true,
    maxLogEntries: 100,
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
        dnsbl: { enabled: true, score: -80 },
        spfIpMatch: { enabled: true, score: -40 },
        spamKitFingerprint: { enabled: true, score: -80 }
    }
};

function cloneDefaults() {
    return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
}

function mergeWithDefaults(saved) {
    const base = cloneDefaults();
    if (!saved || typeof saved !== 'object') {
        return base;
    }
    const mergedChecks = {};
    for (const [key, defVal] of Object.entries(base.checks)) {
        mergedChecks[key] = Object.assign({}, defVal, saved.checks && saved.checks[key] ? saved.checks[key] : {});
    }
    const whitelist = Array.isArray(saved.whitelist) ? saved.whitelist : [];
    const blacklist = Array.isArray(saved.blacklist) ? saved.blacklist : [];
    return Object.assign({}, base, saved, { checks: mergedChecks, whitelist, blacklist });
}

/**
 * Safely sends a runtime message to background.js without throwing an uncaught exception
 * if the background event page is asleep or the options tab was kept open across an addon reload.
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

// DOM elements – Settings
const languageSelect = document.getElementById('languageSelect');
const spamThresholdInput = document.getElementById('spamThreshold');
const dryRunInput = document.getElementById('dryRun');
const monitorAllFoldersInput = document.getElementById('monitorAllFolders');
const maxLogEntriesInput = document.getElementById('maxLogEntries');
const currentModeBadge = document.getElementById('currentModeBadge');
const saveStatus = document.getElementById('saveStatus');
const clearCacheBtn = document.getElementById('clearCacheBtn');
const cacheCountEl = document.getElementById('cacheCount');

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
        score: document.getElementById('chk_dnsbl_score')
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

let currentSettingsState = cloneDefaults();
let fullDiagnosticLog = [];
let ctxMenuTarget = { email: '', domainPattern: '' };
let lastFolderList = null;

/**
 * Shortcut translation helper bound to the currently configured UI language.
 */
function tr(key, params = {}) {
    return t(key, params, currentSettingsState.language || 'auto');
}

function getLocaleCode() {
    return resolveLanguage(currentSettingsState.language || 'auto') === 'de' ? 'de-DE' : 'en-US';
}

function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function flashSaveStatus(msg) {
    saveStatus.textContent = msg;
    setTimeout(() => {
        if (saveStatus.textContent === msg) {
            saveStatus.textContent = '';
        }
    }, 3500);
}

function getEmailFromAuthorString(author) {
    if (!author || typeof author !== 'string') return '';
    const angleMatch = author.match(/<([^<>]+)>/);
    const part = (angleMatch ? angleMatch[1] : author).trim();
    if (!part.includes('@')) return '';
    return part.replace(/^[<"'\s]+|[>"'\s]+$/g, '').toLowerCase();
}

function isUnknownDomain(domain) {
    return !domain || domain === '(unbekannt)' || domain === '(unknown)' || domain === '-';
}

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

/**
 * Re-applies all static and dynamic translations for the currently selected language.
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

function updateModeBadge(isDryRun) {
    if (isDryRun) {
        currentModeBadge.className = 'badge badge-warn';
        currentModeBadge.textContent = tr('mode_dryrun_short');
    } else {
        currentModeBadge.className = 'badge badge-ok';
        currentModeBadge.textContent = tr('mode_active_short');
    }
}

function renderRuleLists(settings) {
    const wl = Array.isArray(settings.whitelist) ? settings.whitelist : [];
    const bl = Array.isArray(settings.blacklist) ? settings.blacklist : [];

    whitelistCount.textContent = tr('opt_list_count', { count: wl.length });
    blacklistCount.textContent = tr('opt_list_count', { count: bl.length });

    if (wl.length === 0) {
        whitelistChips.innerHTML = `<span class="muted" style="font-size:11.5px;">${escapeHtml(tr('opt_wl_empty'))}</span>`;
    } else {
        const removeTitle = escapeHtml(tr('title_remove_wl'));
        whitelistChips.innerHTML = wl.map(pattern => `
          <span class="rule-chip whitelist-chip">
            <span>${escapeHtml(pattern)}</span>
            <button type="button" data-list="whitelist" data-pattern="${escapeHtml(pattern)}" title="${removeTitle}">✕</button>
          </span>
        `).join('');
    }

    if (bl.length === 0) {
        blacklistChips.innerHTML = `<span class="muted" style="font-size:11.5px;">${escapeHtml(tr('opt_bl_empty'))}</span>`;
    } else {
        const removeTitle = escapeHtml(tr('title_remove_bl'));
        blacklistChips.innerHTML = bl.map(pattern => `
          <span class="rule-chip blacklist-chip">
            <span>${escapeHtml(pattern)}</span>
            <button type="button" data-list="blacklist" data-pattern="${escapeHtml(pattern)}" title="${removeTitle}">✕</button>
          </span>
        `).join('');
    }
}

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

function populateSettingsForm(settings) {
    const merged = mergeWithDefaults(settings);
    currentSettingsState = merged;

    languageSelect.value = ['auto', 'de', 'en'].includes(merged.language) ? merged.language : 'auto';
    spamThresholdInput.value = merged.spamThreshold ?? -50;
    dryRunInput.checked = Boolean(merged.dryRun);
    monitorAllFoldersInput.checked = merged.monitorAllFolders !== false;
    maxLogEntriesInput.value = merged.maxLogEntries ?? 100;

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
    }

    applyLanguage();
}

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
    }

    return {
        language: languageSelect.value || 'auto',
        spamThreshold: Number(spamThresholdInput.value) || -50,
        dryRun: dryRunInput.checked,
        monitorAllFolders: monitorAllFoldersInput.checked,
        maxLogEntries: Math.max(10, Number(maxLogEntriesInput.value) || 100),
        whitelist: Array.isArray(currentSettingsState.whitelist) ? currentSettingsState.whitelist : [],
        blacklist: Array.isArray(currentSettingsState.blacklist) ? currentSettingsState.blacklist : [],
        checks
    };
}

function renderCheckPills(checks) {
    if (!checks || Object.keys(checks).length === 0) {
        return '<span class="muted">–</span>';
    }
    if (checks.whitelist) {
        const label = tr('pill_whitelist');
        return `<div class="check-pills"><span class="check-pill pass" title="${escapeHtml(checks.whitelist.info || label)}">✓ ${escapeHtml(label)}</span></div>`;
    }
    if (checks.blacklist) {
        const label = tr('pill_blacklist');
        return `<div class="check-pills"><span class="check-pill fail" title="${escapeHtml(checks.blacklist.info || label)}">⛔ ${escapeHtml(label)} (${checks.blacklist.scoreDelta})</span></div>`;
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
    return `<div class="check-pills">${labels.map(([key, label]) => {
        const c = checks[key];
        if (!c) return '';
        if (!c.enabled) {
            return `<span class="check-pill off" title="${escapeHtml(label)}: ${escapeHtml(tr('status_disabled'))}">${escapeHtml(label)}: ${escapeHtml(tr('status_off_short'))}</span>`;
        }
        const cls = c.passed ? 'pass' : 'fail';
        const icon = c.passed ? '✓' : '✗';
        const deltaStr = c.scoreDelta ? ` (${c.scoreDelta})` : '';
        return `<span class="check-pill ${cls}" title="${escapeHtml(label + ': ' + (c.info || ''))}">${icon} ${escapeHtml(label)}${deltaStr}</span>`;
    }).join('')}</div>`;
}

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
        diagTableBody.innerHTML = `
          <tr>
            <td colspan="8" class="muted" style="text-align:center; padding:24px;">
              ${escapeHtml(tr(emptyKey))}
            </td>
          </tr>
        `;
        return;
    }

    const localeCode = getLocaleCode();
    diagTableBody.innerHTML = filtered.map(entry => {
        const dt = new Date(entry.timestamp);
        const timeStr = dt.toLocaleTimeString(localeCode, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const dateStr = dt.toLocaleDateString(localeCode);

        const email = entry.senderEmail || getEmailFromAuthorString(entry.author);
        const rootDom = getRegistrableDomain(entry.domain) || (!isUnknownDomain(entry.domain) ? entry.domain : '');
        const domainWildcard = rootDom ? `*.${rootDom}` : '';

        let badgeClass = 'badge-ok';
        if (entry.actionTaken === 'moved') {
            badgeClass = 'badge-spam';
        } else if (entry.actionTaken === 'dry-run') {
            badgeClass = 'badge-warn';
        } else if (entry.actionTaken === 'error') {
            badgeClass = 'badge-neutral';
        }

        const quickButtonsHtml = (email || domainWildcard) ? `
          <div class="mini-btn-group">
            ${email ? `<button type="button" class="mini-btn wl" data-quick-list="whitelist" data-quick-pattern="${escapeHtml(email)}" title="${escapeHtml(tr('title_wl_mail', { pattern: email }))}">${escapeHtml(tr('btn_wl_mail'))}</button>` : ''}
            ${domainWildcard ? `<button type="button" class="mini-btn wl" data-quick-list="whitelist" data-quick-pattern="${escapeHtml(domainWildcard)}" title="${escapeHtml(tr('title_wl_dom', { pattern: domainWildcard }))}">${escapeHtml(tr('btn_wl_dom'))}</button>` : ''}
            ${email ? `<button type="button" class="mini-btn bl" data-quick-list="blacklist" data-quick-pattern="${escapeHtml(email)}" title="${escapeHtml(tr('title_bl_mail', { pattern: email }))}">${escapeHtml(tr('btn_bl_mail'))}</button>` : ''}
            ${domainWildcard ? `<button type="button" class="mini-btn bl" data-quick-list="blacklist" data-quick-pattern="${escapeHtml(domainWildcard)}" title="${escapeHtml(tr('title_bl_dom', { pattern: domainWildcard }))}">${escapeHtml(tr('btn_bl_dom'))}</button>` : ''}
          </div>
        ` : '<span class="muted">–</span>';

        return `
          <tr data-row-email="${escapeHtml(email)}" data-row-domain="${escapeHtml(domainWildcard)}">
            <td style="white-space:nowrap;">
              <div><strong>${timeStr}</strong></div>
              <div class="muted" style="font-size:10.5px;">${dateStr}</div>
            </td>
            <td>
              <div><strong>${escapeHtml(entry.folderName)}</strong></div>
              <div class="muted" style="font-size:11px;">${escapeHtml(formatSourceLabel(entry.source))}</div>
            </td>
            <td>
              <div><strong>${escapeHtml(entry.domain)}</strong></div>
              <div class="muted truncate" style="font-size:11px; max-width:210px;" title="${escapeHtml(entry.author)}">${escapeHtml(entry.author)}</div>
            </td>
            <td style="max-width:260px;">
              <div title="${escapeHtml(entry.subject)}">${escapeHtml(entry.subject)}</div>
            </td>
            <td style="min-width:440px;">${renderCheckPills(entry.checks)}</td>
            <td style="white-space:nowrap;">
              <strong style="font-size:13px; color:${entry.isSpam ? 'var(--danger)' : 'var(--success)'};">${entry.score}</strong>
              <span class="muted" style="font-size:11px;"> / ${entry.threshold}</span>
            </td>
            <td>
              <span class="badge ${badgeClass}">${escapeHtml(entry.actionLabel || entry.actionTaken)}</span>
            </td>
            <td>${quickButtonsHtml}</td>
          </tr>
        `;
    }).join('');
}

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

function renderFolderOptions(folders) {
    if (!Array.isArray(folders) || folders.length === 0) {
        folderSelect.innerHTML = `<option value="">${escapeHtml(tr('opt_folders_empty'))}</option>`;
        return;
    }
    const currentVal = folderSelect.value;
    folderSelect.innerHTML = folders.map(f =>
        `<option value="${escapeHtml(f.id)}">${escapeHtml(f.displayPath)}</option>`
    ).join('');
    if (currentVal && folders.some(f => f.id === currentVal)) {
        folderSelect.value = currentVal;
    }
}

async function loadFoldersDropdown() {
    try {
        const res = await sendToBackground({ action: 'GET_ALL_FOLDERS' });
        lastFolderList = (res && res.folders) || [];
        renderFolderOptions(lastFolderList);
    } catch (err) {
        folderSelect.innerHTML = `<option value="">${escapeHtml(tr('opt_folders_err', { error: err.message }))}</option>`;
    }
}

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
diagTableBody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-quick-list]');
    if (!btn) return;
    const listType = btn.getAttribute('data-quick-list');
    const pattern = btn.getAttribute('data-quick-pattern');
    await modifyListEntry(listType, 'add', pattern);
});

diagTableBody.addEventListener('contextmenu', (e) => {
    const row = e.target.closest('tr[data-row-email], tr[data-row-domain]');
    if (!row) return;
    const email = row.getAttribute('data-row-email') || '';
    const domainPattern = row.getAttribute('data-row-domain') || '';
    if (!email && !domainPattern) return;

    e.preventDefault();
    ctxMenuTarget = { email, domainPattern };
    ctxMenuHeader.textContent = email ? `${email} (${domainPattern})` : domainPattern;

    ctxWlEmail.style.display = email ? 'flex' : 'none';
    ctxWlEmail.textContent = tr('ctx_wl_email', { email });

    ctxWlDomain.style.display = domainPattern ? 'flex' : 'none';
    ctxWlDomain.textContent = tr('ctx_wl_domain', { domain: domainPattern });

    ctxBlEmail.style.display = email ? 'flex' : 'none';
    ctxBlEmail.textContent = tr('ctx_bl_email', { email });

    ctxBlDomain.style.display = domainPattern ? 'flex' : 'none';
    ctxBlDomain.textContent = tr('ctx_bl_domain', { domain: domainPattern });

    const menuWidth = 310;
    const menuHeight = 160;
    const x = Math.min(e.clientX, window.innerWidth - menuWidth - 10);
    const y = Math.min(e.clientY, window.innerHeight - menuHeight - 10);

    historyContextMenu.style.left = `${Math.max(8, x)}px`;
    historyContextMenu.style.top = `${Math.max(8, y)}px`;
    historyContextMenu.classList.add('visible');
});

function hideContextMenu() {
    historyContextMenu.classList.remove('visible');
}

document.addEventListener('click', hideContextMenu);
window.addEventListener('scroll', hideContextMenu, true);

ctxWlEmail.addEventListener('click', () => modifyListEntry('whitelist', 'add', ctxMenuTarget.email));
ctxWlDomain.addEventListener('click', () => modifyListEntry('whitelist', 'add', ctxMenuTarget.domainPattern));
ctxBlEmail.addEventListener('click', () => modifyListEntry('blacklist', 'add', ctxMenuTarget.email));
ctxBlDomain.addEventListener('click', () => modifyListEntry('blacklist', 'add', ctxMenuTarget.domainPattern));

// Event listeners – Cache, Folder Scan, Domain Tester
clearCacheBtn.addEventListener('click', async () => {
    await sendToBackground({ action: 'CLEAR_DNS_CACHE' });
    cacheCountEl.textContent = '0';
    flashSaveStatus(tr('toast_cache_cleared'));
});

function reportScanResult(res, doneKey) {
    if (!res || res.error) {
        folderScanResult.textContent = tr('toast_err', { error: (res && res.error) || tr('bg_not_reachable') });
        return false;
    }
    folderScanResult.textContent = tr(doneKey, { processed: res.processed, spam: res.spamCount });
    return true;
}

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

scanActiveFolderBtn.addEventListener('click', async () => {
    folderScanResult.textContent = tr('scan_starting_active');
    const res = await sendToBackground({ action: 'SCAN_ACTIVE_FOLDER' });
    if (reportScanResult(res, 'scan_done_active')) {
        await loadState(false);
    }
});

scanSelectedMsgsBtn.addEventListener('click', async () => {
    folderScanResult.textContent = tr('scan_starting_selected');
    const res = await sendToBackground({ action: 'SCAN_SELECTED_MESSAGES' });
    if (reportScanResult(res, 'scan_done_selected')) {
        await loadState(false);
    }
});

runDomainTestBtn.addEventListener('click', async () => {
    const input = testDomainInput.value.trim();
    const dkimHeader = testDkimInput.value.trim();
    if (!input) {
        domainTestOutput.innerHTML = `<span style="color:var(--danger);">${escapeHtml(tr('opt_tester_empty_err'))}</span>`;
        return;
    }

    domainTestOutput.innerHTML = `<span class="muted">${escapeHtml(tr('opt_tester_running'))}</span>`;
    const res = await sendToBackground({
        action: 'TEST_DOMAIN',
        input,
        dkimHeader: dkimHeader || null
    });
    if (!res || res.error) {
        domainTestOutput.innerHTML = `<span style="color:var(--danger);">${escapeHtml(tr('toast_err', { error: (res && res.error) || tr('bg_not_reachable') }))}</span>`;
        return;
    }
    const badgeCls = res.isSpam ? 'badge-spam' : 'badge-ok';
    const statusTxt = res.whitelisted
        ? `WHITELIST (${res.matchedRule})`
        : (res.blacklisted ? `BLACKLIST (${res.matchedRule})` : (res.isSpam ? tr('opt_tester_status_spam') : tr('opt_tester_status_ok')));
    domainTestOutput.innerHTML = `
      <div style="padding:10px; border:1px solid var(--border); border-radius:6px; background:var(--surface-alt); display:flex; flex-direction:column; gap:6px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>Domain: ${escapeHtml(res.domain)}${res.senderEmail ? ` (${escapeHtml(res.senderEmail)})` : ''}</strong>
          <span class="badge ${badgeCls}">Score: ${res.score} · ${escapeHtml(statusTxt)}</span>
        </div>
        ${renderCheckPills(res.checks)}
      </div>
    `;
    await loadState(false);
});

logFilterStatus.addEventListener('change', renderDiagnosticTable);
logSearchInput.addEventListener('input', renderDiagnosticTable);

clearLogBtn.addEventListener('click', async () => {
    if (messenger.storage && messenger.storage.local) {
        await messenger.storage.local.set({ diagnosticLog: [] });
    }
    await sendToBackground({ action: 'CLEAR_LOG' });
    fullDiagnosticLog = [];
    renderDiagnosticTable();
});

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

// Initial load
applyI18nToDOM(currentSettingsState.language);
loadState(true);
loadFoldersDropdown();
