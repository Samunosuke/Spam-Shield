// Default configuration (kept in sync with background.js so options page can also operate directly on storage.local)
const DEFAULT_SETTINGS = {
    spamThreshold: -50,
    dryRun: false,
    monitorAllFolders: true,
    maxLogEntries: 100,
    checks: {
        domainExists: { enabled: true, score: -100, stopOnFail: true },
        dnssec: { enabled: true, score: -10 },
        mx: { enabled: true, score: -20 },
        spf: { enabled: true, score: -50 },
        dkim: { enabled: true, score: -20 },
        dmarc: { enabled: true, score: -20, penalizeNone: true },
        domainAge: { enabled: true, score: -40, minAgeDays: 90 },
        dnsbl: { enabled: true, score: -80 },
        spfIpMatch: { enabled: true, score: -40 }
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
    return Object.assign({}, base, saved, { checks: mergedChecks });
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
    }
};

const saveSettingsBtn = document.getElementById('saveSettingsBtn');
const resetSettingsBtn = document.getElementById('resetSettingsBtn');

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

// DOM elements – Live Diagnostics Table
const diagStats = document.getElementById('diagStats');
const logFilterStatus = document.getElementById('logFilterStatus');
const logSearchInput = document.getElementById('logSearchInput');
const clearLogBtn = document.getElementById('clearLogBtn');
const diagTableBody = document.getElementById('diagTableBody');

let fullDiagnosticLog = [];

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
    }, 3000);
}

function populateSettingsForm(settings) {
    const merged = mergeWithDefaults(settings);
    spamThresholdInput.value = merged.spamThreshold ?? -50;
    dryRunInput.checked = Boolean(merged.dryRun);
    monitorAllFoldersInput.checked = merged.monitorAllFolders !== false;
    maxLogEntriesInput.value = merged.maxLogEntries ?? 100;

    if (merged.dryRun) {
        currentModeBadge.className = 'badge badge-warn';
        currentModeBadge.textContent = 'Evaluierungsmodus (Dry-Run)';
    } else {
        currentModeBadge.className = 'badge badge-ok';
        currentModeBadge.textContent = 'Aktiv (Verschieben nach Junk)';
    }

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
        spamThreshold: Number(spamThresholdInput.value) || -50,
        dryRun: dryRunInput.checked,
        monitorAllFolders: monitorAllFoldersInput.checked,
        maxLogEntries: Math.max(10, Number(maxLogEntriesInput.value) || 100),
        checks
    };
}

function renderCheckPills(checks) {
    if (!checks || Object.keys(checks).length === 0) {
        return '<span class="muted">–</span>';
    }
    const labels = [
        ['domainExists', 'Existenz'],
        ['dnssec', 'DNSSEC'],
        ['mx', 'MX'],
        ['spf', 'SPF'],
        ['dkim', 'DKIM'],
        ['dmarc', 'DMARC'],
        ['domainAge', 'Alter'],
        ['dnsbl', 'DNSBL'],
        ['spfIpMatch', 'SPF-IP']
    ];
    return `<div class="check-pills">${labels.map(([key, label]) => {
        const c = checks[key];
        if (!c) {
            return `<span class="check-pill off" title="${label}: nicht ausgeführt">${label}: –</span>`;
        }
        if (!c.enabled) {
            return `<span class="check-pill off" title="${label}: deaktiviert">${label}: aus</span>`;
        }
        const cls = c.passed ? 'pass' : 'fail';
        const icon = c.passed ? '✓' : '✗';
        const deltaStr = c.scoreDelta ? ` (${c.scoreDelta})` : '';
        return `<span class="check-pill ${cls}" title="${escapeHtml(label + ': ' + (c.info || ''))}">${icon} ${label}${deltaStr}</span>`;
    }).join('')}</div>`;
}

function formatSourceLabel(source) {
    switch (source) {
        case 'auto': return 'Automatisch';
        case 'folder-scan': return 'Ordner-Scan';
        case 'context-folder': return 'Kontextmenü (Ordner)';
        case 'context-messages': return 'Kontextmenü (Auswahl)';
        case 'selected-messages': return 'Auswahl-Scan';
        default: return source || 'Unbekannt';
    }
}

function renderDiagnosticTable() {
    const statusFilter = logFilterStatus.value;
    const query = (logSearchInput.value || '').trim().toLowerCase();

    const spamCount = fullDiagnosticLog.filter(e => e.isSpam).length;
    diagStats.textContent = `${fullDiagnosticLog.length} gespeichert · ${spamCount} als Spam eingestuft`;

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
        diagTableBody.innerHTML = `
          <tr>
            <td colspan="7" class="muted" style="text-align:center; padding:24px;">
              Keine passenden Einträge im Diagnose-Protokoll gefunden.
            </td>
          </tr>
        `;
        return;
    }

    diagTableBody.innerHTML = filtered.map(entry => {
        const dt = new Date(entry.timestamp);
        const timeStr = dt.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const dateStr = dt.toLocaleDateString('de-DE');

        let badgeClass = 'badge-ok';
        if (entry.actionTaken === 'moved') {
            badgeClass = 'badge-spam';
        } else if (entry.actionTaken === 'dry-run') {
            badgeClass = 'badge-warn';
        } else if (entry.actionTaken === 'error') {
            badgeClass = 'badge-neutral';
        }

        return `
          <tr>
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
              <div class="muted truncate" style="font-size:11px; max-width:220px;" title="${escapeHtml(entry.author)}">${escapeHtml(entry.author)}</div>
            </td>
            <td style="max-width:260px;">
              <div title="${escapeHtml(entry.subject)}">${escapeHtml(entry.subject)}</div>
            </td>
            <td>${renderCheckPills(entry.checks)}</td>
            <td style="white-space:nowrap;">
              <strong style="font-size:13px; color:${entry.isSpam ? 'var(--danger)' : 'var(--success)'};">${entry.score}</strong>
              <span class="muted" style="font-size:11px;"> / ${entry.threshold}</span>
            </td>
            <td>
              <span class="badge ${badgeClass}">${escapeHtml(entry.actionLabel || entry.actionTaken)}</span>
            </td>
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
    scanText.textContent = `Prüfe "${scanState.sourceName}": ${scanState.processed} von ${scanState.total} E-Mails (${scanState.spamCount} Spam)…`;
    scanProgressFill.style.width = `${pct}%`;
}

async function loadFoldersDropdown() {
    try {
        const res = await sendToBackground({ action: 'GET_ALL_FOLDERS' });
        const folders = (res && res.folders) || [];
        if (folders.length === 0) {
            folderSelect.innerHTML = '<option value="">Keine Ordner gefunden</option>';
            return;
        }
        const currentVal = folderSelect.value;
        folderSelect.innerHTML = folders.map(f =>
            `<option value="${escapeHtml(f.id)}">${escapeHtml(f.displayPath)}</option>`
        ).join('');
        if (currentVal && folders.some(f => f.id === currentVal)) {
            folderSelect.value = currentVal;
        }
    } catch (err) {
        folderSelect.innerHTML = `<option value="">Fehler beim Laden der Ordner: ${escapeHtml(err.message)}</option>`;
    }
}

async function loadState(includeSettingsForm = false) {
    try {
        // First read directly from storage.local so it always works even if background page is asleep
        let storedSettings = null;
        let storedLog = null;
        if (messenger.storage && messenger.storage.local) {
            const localData = await messenger.storage.local.get(['settings', 'diagnosticLog']);
            storedSettings = localData.settings;
            storedLog = localData.diagnosticLog;
        }

        const state = await sendToBackground({ action: 'GET_STATE' });
        const effectiveSettings = mergeWithDefaults((state && state.settings) || storedSettings);

        if (includeSettingsForm) {
            populateSettingsForm(effectiveSettings);
        }
        cacheCountEl.textContent = (state && state.cacheSize) ?? 0;
        fullDiagnosticLog = (state && Array.isArray(state.diagnosticLog))
            ? state.diagnosticLog
            : (Array.isArray(storedLog) ? storedLog : []);
        updateScanBanner(state ? state.scanState : null);
        renderDiagnosticTable();
    } catch (err) {
        console.error('Failed to load state:', err);
    }
}

// Event listeners
saveSettingsBtn.addEventListener('click', async () => {
    try {
        const newSettings = collectSettingsFromForm();
        if (messenger.storage && messenger.storage.local) {
            await messenger.storage.local.set({ settings: newSettings });
        }
        await sendToBackground({
            action: 'SAVE_SETTINGS',
            settings: newSettings
        });
        populateSettingsForm(newSettings);
        flashSaveStatus('✓ Einstellungen gespeichert');
    } catch (err) {
        console.error('Save settings error:', err);
        flashSaveStatus(`Fehler: ${err.message || err}`);
    }
});

resetSettingsBtn.addEventListener('click', async () => {
    try {
        const defaults = cloneDefaults();
        if (messenger.storage && messenger.storage.local) {
            await messenger.storage.local.set({ settings: defaults });
        }
        await sendToBackground({ action: 'RESET_SETTINGS' });
        populateSettingsForm(defaults);
        flashSaveStatus('↺ Standardwerte wiederhergestellt');
    } catch (err) {
        console.error('Reset settings error:', err);
        flashSaveStatus(`Fehler: ${err.message || err}`);
    }
});

clearCacheBtn.addEventListener('click', async () => {
    await sendToBackground({ action: 'CLEAR_DNS_CACHE' });
    cacheCountEl.textContent = '0';
    flashSaveStatus('✓ DNS/RDAP-Cache geleert');
});

scanSelectedFolderBtn.addEventListener('click', async () => {
    const folderId = folderSelect.value;
    if (!folderId) return;
    const folderName = folderSelect.options[folderSelect.selectedIndex]?.text || folderId;
    folderScanResult.textContent = `Starte Prüfung für "${folderName}"…`;
    const res = await sendToBackground({
        action: 'SCAN_FOLDER_BY_ID',
        folderId,
        folderName
    });
    if (!res || res.error) {
        folderScanResult.textContent = `Fehler: ${(res && res.error) || 'Hintergrundskript nicht erreichbar – bitte diesen Tab einmal neu laden (F5).'}`;
        return;
    }
    folderScanResult.textContent = `✓ Ordnerprüfung abgeschlossen: ${res.processed} E-Mails geprüft, ${res.spamCount} als Spam eingestuft.`;
    await loadState(false);
});

scanActiveFolderBtn.addEventListener('click', async () => {
    folderScanResult.textContent = 'Starte Prüfung des aktiven Ordners…';
    const res = await sendToBackground({ action: 'SCAN_ACTIVE_FOLDER' });
    if (!res || res.error) {
        folderScanResult.textContent = `Fehler: ${(res && res.error) || 'Hintergrundskript nicht erreichbar – bitte diesen Tab einmal neu laden (F5).'}`;
        return;
    }
    folderScanResult.textContent = `✓ Aktiver Ordner geprüft: ${res.processed} E-Mails geprüft, ${res.spamCount} als Spam eingestuft.`;
    await loadState(false);
});

scanSelectedMsgsBtn.addEventListener('click', async () => {
    folderScanResult.textContent = 'Prüfe markierte E-Mails…';
    const res = await sendToBackground({ action: 'SCAN_SELECTED_MESSAGES' });
    if (!res || res.error) {
        folderScanResult.textContent = `Fehler: ${(res && res.error) || 'Hintergrundskript nicht erreichbar – bitte diesen Tab einmal neu laden (F5).'}`;
        return;
    }
    folderScanResult.textContent = `✓ Auswahl geprüft: ${res.processed} E-Mails geprüft, ${res.spamCount} als Spam eingestuft.`;
    await loadState(false);
});

runDomainTestBtn.addEventListener('click', async () => {
    const input = testDomainInput.value.trim();
    const dkimHeader = testDkimInput.value.trim();
    if (!input) {
        domainTestOutput.innerHTML = '<span style="color:var(--danger);">Bitte eine Domain oder E-Mail-Adresse eingeben.</span>';
        return;
    }

    domainTestOutput.innerHTML = '<span class="muted">Frage DNS, SPF, DKIM, DMARC, RDAP (Domain-Alter) &amp; DNSBL ab…</span>';
    const res = await sendToBackground({
        action: 'TEST_DOMAIN',
        input,
        dkimHeader: dkimHeader || null
    });
    if (!res || res.error) {
        domainTestOutput.innerHTML = `<span style="color:var(--danger);">Fehler: ${escapeHtml((res && res.error) || 'Hintergrundskript nach Add-on-Update noch nicht verbunden – bitte diesen Tab einmal mit F5 neu laden.')}</span>`;
        return;
    }
    const badgeCls = res.isSpam ? 'badge-spam' : 'badge-ok';
    const statusTxt = res.isSpam ? 'SPAM (unter Schwellenwert)' : 'OK (Vertrauenswürdig)';
    domainTestOutput.innerHTML = `
      <div style="padding:10px; border:1px solid var(--border); border-radius:6px; background:var(--surface-alt); display:flex; flex-direction:column; gap:6px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>Domain: ${escapeHtml(res.domain)}</strong>
          <span class="badge ${badgeCls}">Score: ${res.score} · ${statusTxt}</span>
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
        } else if (msg.type === 'LOG_UPDATED') {
            loadState(false);
        }
    });
}

if (messenger.storage && messenger.storage.onChanged) {
    messenger.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.diagnosticLog) {
            fullDiagnosticLog = Array.isArray(changes.diagnosticLog.newValue) ? changes.diagnosticLog.newValue : [];
            renderDiagnosticTable();
        }
    });
}

// Initial load
loadState(true);
loadFoldersDropdown();
