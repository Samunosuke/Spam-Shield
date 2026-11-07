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

let currentSettings = null;

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

function showStatus(text, isError = false) {
    statusMsg.style.display = 'block';
    statusMsg.style.color = isError ? 'var(--danger)' : 'var(--text-muted)';
    statusMsg.textContent = text;
}

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
    scanText.textContent = `${scanState.sourceName}: ${scanState.processed}/${scanState.total} (Spam: ${scanState.spamCount})`;
    scanProgressFill.style.width = `${pct}%`;
}

function renderCheckPills(checks) {
    if (!checks) return '';
    const labels = [
        ['domainExists', 'DNS'],
        ['dnssec', 'DNSSEC'],
        ['mx', 'MX'],
        ['spf', 'SPF'],
        ['dkim', 'DKIM'],
        ['dmarc', 'DMARC'],
        ['domainAge', 'Alter'],
        ['dnsbl', 'DNSBL'],
        ['spfIpMatch', 'SPF-IP']
    ];
    return labels.map(([key, label]) => {
        const c = checks[key];
        if (!c || !c.enabled) {
            return `<span class="check-pill off" title="${label}: deaktiviert">${label}</span>`;
        }
        const cls = c.passed ? 'pass' : 'fail';
        const deltaStr = c.scoreDelta ? ` (${c.scoreDelta})` : '';
        const info = (c.info || '').replace(/"/g, '&quot;');
        return `<span class="check-pill ${cls}" title="${label}: ${info}${deltaStr}">${label}${deltaStr}</span>`;
    }).join('');
}

function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function renderPopupLog(log) {
    if (!Array.isArray(log) || log.length === 0) {
        popupLogList.innerHTML = '<div class="muted" style="padding:16px; text-align:center;">Noch keine E-Mails in dieser Sitzung bewertet.</div>';
        logSummary.textContent = '0 Einträge';
        return;
    }

    const spamTotal = log.filter(e => e.isSpam).length;
    logSummary.textContent = `${log.length} geprüft · ${spamTotal} Spam`;

    const recent = log.slice(0, 12);
    popupLogList.innerHTML = recent.map(entry => {
        const timeStr = new Date(entry.timestamp).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        let badgeClass = 'badge-ok';
        let badgeText = `OK (${entry.score})`;
        if (entry.actionTaken === 'moved') {
            badgeClass = 'badge-spam';
            badgeText = `SPAM (${entry.score})`;
        } else if (entry.actionTaken === 'dry-run') {
            badgeClass = 'badge-warn';
            badgeText = `DRY-RUN (${entry.score})`;
        } else if (entry.actionTaken === 'error') {
            badgeClass = 'badge-neutral';
            badgeText = 'Fehler';
        }

        return `
          <div class="popup-log-item">
            <div class="popup-log-item-header">
              <strong class="truncate" title="${escapeHtml(entry.author)}">${escapeHtml(entry.domain)}</strong>
              <span class="badge ${badgeClass}" title="${escapeHtml(entry.actionLabel)}">${badgeText}</span>
            </div>
            <div class="truncate muted" style="font-size:11.5px;" title="${escapeHtml(entry.subject)}">${escapeHtml(entry.subject)}</div>
            <div style="display:flex; justify-content:space-between; align-items:center; gap:6px; margin-top:2px;">
              <div class="check-pills">${renderCheckPills(entry.checks)}</div>
              <span class="muted" style="font-size:10.5px; white-space:nowrap;">${escapeHtml(entry.folderName)} · ${timeStr}</span>
            </div>
          </div>
        `;
    }).join('');
}

async function refreshState() {
    try {
        let localData = {};
        if (messenger.storage && messenger.storage.local) {
            localData = await messenger.storage.local.get(['settings', 'diagnosticLog']);
        }
        const state = await sendToBackground({ action: 'GET_STATE' });
        currentSettings = (state && state.settings) || localData.settings || { spamThreshold: -50, dryRun: false };
        quickDryRunToggle.checked = Boolean(currentSettings.dryRun);
        modeIndicator.textContent = currentSettings.dryRun
            ? `Schwellenwert: < ${currentSettings.spamThreshold} · Evaluierungsmodus (Dry-Run)`
            : `Schwellenwert: < ${currentSettings.spamThreshold} · Aktiv (Verschieben nach Junk)`;
        updateScanBanner(state ? state.scanState : null);
        renderPopupLog((state && state.diagnosticLog) || localData.diagnosticLog || []);
    } catch (err) {
        showStatus(`Fehler beim Laden: ${err.message || err}`, true);
    }
}

openOptionsBtn.addEventListener('click', () => {
    messenger.runtime.openOptionsPage();
    window.close();
});

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

scanFolderBtn.addEventListener('click', async () => {
    showStatus('Prüfe aktuellen Ordner…');
    const res = await sendToBackground({ action: 'SCAN_ACTIVE_FOLDER' });
    if (!res || res.error) {
        showStatus(`Ordnerprüfung fehlgeschlagen: ${(res && res.error) || 'Verbindungsfehler'}`, true);
        return;
    }
    showStatus(`Ordner geprüft: ${res.processed} E-Mails (${res.spamCount} Spam).`);
    await refreshState();
});

scanSelectedBtn.addEventListener('click', async () => {
    showStatus('Prüfe ausgewählte E-Mails…');
    const res = await sendToBackground({ action: 'SCAN_SELECTED_MESSAGES' });
    if (!res || res.error) {
        showStatus(`Auswahlprüfung fehlgeschlagen: ${(res && res.error) || 'Verbindungsfehler'}`, true);
        return;
    }
    showStatus(`Auswahl geprüft: ${res.processed} E-Mails (${res.spamCount} Spam).`);
    await refreshState();
});

if (messenger.runtime && messenger.runtime.onMessage) {
    messenger.runtime.onMessage.addListener((msg) => {
        if (!msg) return;
        if (msg.type === 'SCAN_PROGRESS' || msg.type === 'SCAN_COMPLETE') {
            updateScanBanner(msg.scanState);
            if (msg.type === 'SCAN_COMPLETE') {
                refreshState();
            }
        } else if (msg.type === 'LOG_UPDATED') {
            refreshState();
        }
    });
}

refreshState();
