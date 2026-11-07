// Listener für den Empfang von Nachrichten
messenger.messages.onNewMailReceived.addListener(handleMessages, true); // monitorAllFolders = true

/**
 * Defines the Domain DNS checkup service URL (currently we are using hardcoded cloudflare for this)
 */
const g_DOH_SERVICE_URL = 'https://cloudflare-dns.com/dns-query';

/**
 * Defines the IANA RDAP bootstrap URL to resolve authoritative RDAP servers per TLD directly
 */
const g_IANA_RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
let g_RDAP_TLD_MAP = null;
let g_RDAP_BOOTSTRAP_PROMISE = null;

/**
 * Simple in-memory caches for DoH DNS and RDAP responses to avoid redundant network requests
 */
const g_DNS_CACHE = new Map();
const g_DNS_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

const g_RDAP_CACHE = new Map();
const g_RDAP_CACHE_TTL_MS = 60 * 60 * 1000; // 60 minutes

/**
 * Folder types that should be ignored when monitoring all folders automatically
 */
const g_IGNORED_FOLDER_TYPES = new Set(['junk', 'trash', 'sent', 'drafts', 'templates', 'outbox', 'archives']);

/**
 * Default configuration for checks, scores, and behavior
 */
const DEFAULT_SETTINGS = {
    spamThreshold: -50,
    dryRun: false,
    monitorAllFolders: true,
    maxLogEntries: 100,
    whitelist: [],
    blacklist: [],
    checks: {
        domainExists: {
            enabled: true,
            score: -100,
            stopOnFail: true
        },
        dnssec: {
            enabled: true,
            score: -10
        },
        mx: {
            enabled: true,
            score: -20
        },
        spf: {
            enabled: true,
            score: -50
        },
        dkim: {
            enabled: true,
            score: -20
        },
        dmarc: {
            enabled: true,
            score: -20,
            penalizeNone: true
        },
        domainAge: {
            enabled: true,
            score: -40,
            minAgeDays: 90
        },
        dnsbl: {
            enabled: true,
            score: -80
        },
        spfIpMatch: {
            enabled: true,
            score: -40
        },
        spamKitFingerprint: {
            enabled: true,
            score: -80
        }
    }
};

/**
 * Tracks the progress of manual folder/message scans for live UI feedback
 */
let g_SCAN_STATE = {
    running: false,
    sourceName: '',
    processed: 0,
    total: 0,
    spamCount: 0,
    startedAt: null
};

// Initialize context menus on startup/install
initExtension();

async function initExtension() {
    try {
        const stored = await getSettings();
        if (messenger.storage && messenger.storage.local) {
            await messenger.storage.local.set({ settings: stored });
        }
    } catch (err) {
        console.warn('Could not initialize settings in storage:', err);
    }

    setupContextMenus();
}

/**
 * Registers context menu entries for folders and message lists in Thunderbird
 */
function setupContextMenus() {
    if (!messenger.menus) {
        return;
    }

    messenger.menus.removeAll().then(() => {
        messenger.menus.create({
            id: 'suke-validate-folder',
            title: 'Ordner auf Spam-Domains prüfen (Suke)',
            contexts: ['folder_pane']
        });

        messenger.menus.create({
            id: 'suke-validate-messages',
            title: 'Ausgewählte E-Mail(s) auf Spam-Domain prüfen (Suke)',
            contexts: ['message_list']
        });

        messenger.menus.create({
            id: 'suke-whitelist-email',
            title: 'Absender-E-Mail zur Whitelist hinzufügen (Suke)',
            contexts: ['message_list']
        });

        messenger.menus.create({
            id: 'suke-whitelist-domain',
            title: 'Absender-Domain (*.domain) zur Whitelist hinzufügen (Suke)',
            contexts: ['message_list']
        });

        messenger.menus.create({
            id: 'suke-blacklist-email',
            title: 'Absender-E-Mail zur Blacklist hinzufügen & als Spam behandeln (Suke)',
            contexts: ['message_list']
        });

        messenger.menus.create({
            id: 'suke-blacklist-domain',
            title: 'Absender-Domain (*.domain) zur Blacklist hinzufügen & als Spam behandeln (Suke)',
            contexts: ['message_list']
        });
    }).catch(err => console.warn('Failed to create context menus:', err));
}

async function addPatternsToList(listType, patterns) {
    const current = await getSettings();
    const list = Array.isArray(current[listType]) ? [...current[listType]] : [];
    for (const raw of patterns) {
        const p = String(raw || '').trim().toLowerCase();
        if (p && !list.some(item => String(item).toLowerCase() === p)) {
            list.unshift(p);
        }
    }
    current[listType] = list;
    if (messenger.storage && messenger.storage.local) {
        await messenger.storage.local.set({ settings: current });
    }
    notifyUI({ type: 'SETTINGS_UPDATED', settings: current });
    return current;
}

if (messenger.menus && messenger.menus.onClicked) {
    messenger.menus.onClicked.addListener(async (info, tab) => {
        if (info.menuItemId === 'suke-validate-folder') {
            let folders = [];
            if (Array.isArray(info.selectedFolders) && info.selectedFolders.length > 0) {
                folders = info.selectedFolders;
            } else if (info.selectedFolder) {
                folders = [info.selectedFolder];
            } else if (messenger.mailTabs && tab) {
                const mailTab = await messenger.mailTabs.get(tab.id).catch(() => null);
                if (mailTab && mailTab.displayedFolder) {
                    folders = [mailTab.displayedFolder];
                }
            }
            for (const folder of folders) {
                await scanFolder(folder, 'context-folder');
            }
            return;
        }

        let msgList = info.selectedMessages;
        if (!msgList && messenger.mailTabs && tab) {
            msgList = await messenger.mailTabs.getSelectedMessages(tab.id);
        }
        let fallbackFolder = info.displayedFolder || null;
        if (!fallbackFolder && messenger.mailTabs && tab) {
            const mailTab = await messenger.mailTabs.get(tab.id).catch(() => null);
            if (mailTab && mailTab.displayedFolder) {
                fallbackFolder = mailTab.displayedFolder;
            }
        }

        if (info.menuItemId === 'suke-validate-messages') {
            if (msgList) {
                await scanMessageList(msgList, fallbackFolder, 'context-messages');
            }
        } else if (
            info.menuItemId === 'suke-whitelist-email' ||
            info.menuItemId === 'suke-whitelist-domain' ||
            info.menuItemId === 'suke-blacklist-email' ||
            info.menuItemId === 'suke-blacklist-domain'
        ) {
            if (!msgList) return;
            const isWhitelist = info.menuItemId.startsWith('suke-whitelist');
            const isDomainMode = info.menuItemId.endsWith('-domain');
            const patterns = [];

            for await (const msg of iterateMessagePages(msgList)) {
                if (isDomainMode) {
                    const dom = await extractDomainFromAuthor(msg.author || '');
                    const rootDom = getRegistrableDomain(dom) || dom;
                    if (rootDom) patterns.push(`*.${rootDom}`);
                } else {
                    const email = await extractEmailFromAuthor(msg.author || '');
                    if (email) patterns.push(email);
                }
            }

            if (patterns.length > 0) {
                await addPatternsToList(isWhitelist ? 'whitelist' : 'blacklist', patterns);
                await scanMessageList(msgList, fallbackFolder, 'context-messages');
            }
        }
    });
}

function cloneDefaults() {
    return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
}

/**
 * Loads current settings merged with DEFAULT_SETTINGS
 * @returns {Promise<typeof DEFAULT_SETTINGS>}
 */
async function getSettings() {
    if (!messenger.storage || !messenger.storage.local) {
        return cloneDefaults();
    }
    try {
        const data = await messenger.storage.local.get('settings');
        const saved = data && data.settings ? data.settings : {};
        const mergedChecks = {};
        for (const [key, defVal] of Object.entries(DEFAULT_SETTINGS.checks)) {
            mergedChecks[key] = Object.assign({}, defVal, saved.checks && saved.checks[key] ? saved.checks[key] : {});
        }
        const whitelist = Array.isArray(saved.whitelist) ? saved.whitelist : [];
        const blacklist = Array.isArray(saved.blacklist) ? saved.blacklist : [];
        return Object.assign({}, cloneDefaults(), saved, { checks: mergedChecks, whitelist, blacklist });
    } catch (err) {
        console.warn('Failed to load settings from storage, using defaults:', err);
        return cloneDefaults();
    }
}

/**
 * Appends a diagnostic entry to the log in storage.local (trimmed to maxLogEntries)
 * and notifies any open UI views.
 * @param {object} entry
 * @param {number} maxEntries
 */
async function appendDiagnosticLog(entry, maxEntries = 100) {
    if (!messenger.storage || !messenger.storage.local) {
        return;
    }
    try {
        const data = await messenger.storage.local.get('diagnosticLog');
        const log = Array.isArray(data.diagnosticLog) ? data.diagnosticLog : [];
        log.unshift(entry);
        const limit = Math.max(10, Number(maxEntries) || 100);
        if (log.length > limit) {
            log.length = limit;
        }
        await messenger.storage.local.set({ diagnosticLog: log });
        notifyUI({ type: 'LOG_UPDATED', entry, scanState: g_SCAN_STATE });
    } catch (err) {
        console.warn('Failed to write diagnostic log:', err);
    }
}

/**
 * Sends a non-blocking runtime message to open extension pages (Popup / Options)
 * @param {object} payload
 */
function notifyUI(payload) {
    if (messenger.runtime && typeof messenger.runtime.sendMessage === 'function') {
        messenger.runtime.sendMessage(payload).catch(() => {
            // Ignore errors when no popup/options page is currently listening
        });
    }
}

/**
 * Helper generator to iterate over all pages of a Thunderbird MessageList
 * @param {object} messageList the initial MessageList object
 */
async function* iterateMessagePages(messageList) {
    let currentPage = messageList;
    while (currentPage) {
        if (currentPage.messages && currentPage.messages.length > 0) {
            for (const message of currentPage.messages) {
                yield message;
            }
        }
        if (!currentPage.id) {
            break;
        }
        currentPage = await messenger.messages.continueList(currentPage.id);
    }
}

/**
 * Handles all incoming messages from onNewMailReceived
 * @param {*} folder the folder where the messages belong to
 * @param {*} msgList the list of message headers (see https://webextension-api.thunderbird.net/en/mv3/messages.html#messagelist)
 */
async function handleMessages(folder, msgList) {
    const settings = await getSettings();

    if (folder && Array.isArray(folder.specialUse)) {
        // Always ignore Junk, Trash, Sent, Drafts, etc. on automatic incoming events
        if (folder.specialUse.some(use => g_IGNORED_FOLDER_TYPES.has(use))) {
            console.log(`Skipping folder ${folder.name} (specialUse: ${folder.specialUse.join(', ')})`);
            return;
        }
        // If monitorAllFolders is disabled in settings, only process inbox folders
        if (!settings.monitorAllFolders && !folder.specialUse.includes('inbox')) {
            console.log(`Skipping non-inbox folder ${folder.name} because monitorAllFolders is false`);
            return;
        }
    }

    console.log(`Handling incoming messages in folder: ${folder ? folder.name : 'unknown'}`);

    try {
        for await (const message of iterateMessagePages(msgList)) {
            await evaluateAndProcessMessage(message, folder, settings, 'auto');
        }
    } catch (ex) {
        console.error('ERROR failed to iterate over messages:', ex);
    }
}

/**
 * Resolves a human-readable folder name from folder object or message.folder
 */
function resolveFolderName(folder, message) {
    if (folder && typeof folder === 'object' && folder.name) {
        return folder.name;
    }
    if (message && message.folder && message.folder.name) {
        return message.folder.name;
    }
    if (folder && typeof folder === 'object' && folder.path) {
        return folder.path;
    }
    return 'Postfach';
}

/**
 * Evaluates a single message, records the result in the live diagnostic log,
 * and moves/marks it as spam if below threshold (unless dryRun is enabled).
 * @param {object} message Thunderbird MessageHeader
 * @param {object|null} folder Thunderbird MailFolder
 * @param {object} settings Current addon settings
 * @param {string} source 'auto' | 'folder-scan' | 'context-folder' | 'context-messages' | 'selected-messages'
 * @returns {Promise<{ isSpam: boolean, score: number }>}
 */
async function evaluateAndProcessMessage(message, folder, settings, source = 'auto') {
    const targetFolder = (folder && typeof folder === 'object') ? folder : (message.folder || null);
    const folderName = resolveFolderName(targetFolder, message);
    console.log(`Validating ${message.author}:[${message.subject}] (messageID: ${message.id}...)`);

    try {
        const senderAddress = message.author || '';
        const senderEmail = await extractEmailFromAuthor(senderAddress);
        const domain = senderEmail ? getDomainFromAddress(senderEmail) : await extractDomainFromAuthor(senderAddress);
        if (!domain) {
            console.warn(`Could not extract domain from sender address: ${senderAddress}`);
            await appendDiagnosticLog({
                id: `${Date.now()}-${message.id}`,
                timestamp: Date.now(),
                messageId: message.id,
                author: senderAddress,
                senderEmail: senderEmail || '',
                domain: '(unbekannt)',
                subject: message.subject || '(Kein Betreff)',
                folderName,
                source,
                score: 0,
                threshold: settings.spamThreshold,
                isSpam: false,
                actionTaken: 'error',
                actionLabel: 'Keine Domain erkannt',
                checks: {}
            }, settings.maxLogEntries);
            return { isSpam: false, score: 0 };
        }

        // Use getHeaders() instead of getFull() to avoid parsing the full MIME body
        const headers = messenger.messages.getHeaders
            ? await messenger.messages.getHeaders(message.id)
            : (await messenger.messages.getFull(message.id)).headers;
        const dkimSig = headers ? headers['dkim-signature'] : null;

        // Perform detailed domain validation (passing full headers and senderEmail for Whitelist/Blacklist & SPF-IP)
        const result = await validateDomainDetailed(domain, dkimSig, settings, headers, senderEmail);
        const { score, isSpam, checks } = result;
        console.log(`Validation score for ${domain} (messageID: ${message.id}): ${score} (threshold: ${settings.spamThreshold})`);

        let actionTaken = 'passed';
        let actionLabel = result.whitelisted ? `Whitelist (${result.matchedRule})` : 'OK';

        if (isSpam) {
            if (settings.dryRun) {
                console.log(`[DRY-RUN SPAM] Would mark message from ${message.author} (score: ${score}) as Junk.`);
                actionTaken = 'dry-run';
                actionLabel = result.blacklisted
                    ? `Blacklist (${result.matchedRule}) · Dry-Run`
                    : 'Spam (Dry-Run – nicht verschoben)';
            } else {
                console.log(`[SPAM] Marking message from ${message.author} (score: ${score}) as Junk and moving to Spam folder.`);
                await markAndMoveToSpam(message, targetFolder);
                actionTaken = 'moved';
                actionLabel = result.blacklisted
                    ? `Blacklist (${result.matchedRule}) · Verschoben`
                    : 'Als Spam markiert & verschoben';
            }
        }

        await appendDiagnosticLog({
            id: `${Date.now()}-${message.id}-${Math.random().toString(36).slice(2, 6)}`,
            timestamp: Date.now(),
            messageId: message.id,
            author: senderAddress,
            senderEmail: senderEmail || '',
            domain,
            subject: message.subject || '(Kein Betreff)',
            folderName,
            source,
            score,
            threshold: settings.spamThreshold,
            isSpam,
            actionTaken,
            actionLabel,
            checks
        }, settings.maxLogEntries);

        return { isSpam, score };
    } catch (error) {
        console.error(`ERROR Validating ${message.author}:[${message.subject}] (messageID: ${message.id}...):`, error);
        await appendDiagnosticLog({
            id: `${Date.now()}-${message.id}`,
            timestamp: Date.now(),
            messageId: message.id,
            author: message.author || '',
            domain: '-',
            subject: message.subject || '(Kein Betreff)',
            folderName,
            source,
            score: 0,
            threshold: settings.spamThreshold,
            isSpam: false,
            actionTaken: 'error',
            actionLabel: `Fehler: ${error.message || error}`,
            checks: {}
        }, settings.maxLogEntries);
        return { isSpam: false, score: 0 };
    }
}

/**
 * Scans all messages in a given folder (triggered via context menu, popup, or options page)
 * @param {object|string} folder MailFolder object or folderId string
 * @param {string} source label for diagnostic log
 */
async function scanFolder(folder, source = 'folder-scan') {
    if (!folder) {
        return { processed: 0, spamCount: 0 };
    }

    let folderObj = folder;
    if (typeof folder === 'string' && messenger.folders && messenger.folders.get) {
        try {
            folderObj = await messenger.folders.get(folder);
        } catch {
            folderObj = { id: folder, name: folder };
        }
    } else if (typeof folder === 'object' && !folder.name && folder.id && messenger.folders && messenger.folders.get) {
        try {
            folderObj = await messenger.folders.get(folder.id);
        } catch {
            folderObj = folder;
        }
    }

    const folderId = typeof folderObj === 'object' ? (folderObj.id || folderObj) : folderObj;
    const msgList = await messenger.messages.list(folderId);
    return await scanMessageList(msgList, folderObj, source);
}

/**
 * Scans all messages in a MessageList and updates live progress state
 * @param {object} msgList Thunderbird MessageList
 * @param {object|null} folder optional MailFolder
 * @param {string} source label for diagnostic log
 */
async function scanMessageList(msgList, folder = null, source = 'message-scan') {
    const settings = await getSettings();

    // Collect all messages across pages first so we have an accurate total count
    // and so moving messages to Junk during iteration does not invalidate the cursor
    const allMessages = [];
    for await (const msg of iterateMessagePages(msgList)) {
        allMessages.push(msg);
    }

    const firstMsgFolder = allMessages.length > 0 ? allMessages[0].folder : null;
    const effectiveFolder = (folder && folder.name) ? folder : (firstMsgFolder || folder);

    g_SCAN_STATE = {
        running: true,
        sourceName: effectiveFolder && effectiveFolder.name ? effectiveFolder.name : 'Auswahl',
        processed: 0,
        total: allMessages.length,
        spamCount: 0,
        startedAt: Date.now()
    };
    notifyUI({ type: 'SCAN_PROGRESS', scanState: g_SCAN_STATE });

    try {
        for (const message of allMessages) {
            const res = await evaluateAndProcessMessage(message, effectiveFolder || message.folder, settings, source);
            g_SCAN_STATE.processed += 1;
            if (res && res.isSpam) {
                g_SCAN_STATE.spamCount += 1;
            }
            notifyUI({ type: 'SCAN_PROGRESS', scanState: g_SCAN_STATE });
        }
    } finally {
        g_SCAN_STATE.running = false;
        notifyUI({ type: 'SCAN_COMPLETE', scanState: g_SCAN_STATE });
    }

    return {
        processed: g_SCAN_STATE.processed,
        spamCount: g_SCAN_STATE.spamCount,
        total: g_SCAN_STATE.total
    };
}

/**
 * Marks a message as junk and moves it to the account's Junk/Spam folder if available
 * @param {object} message the MessageHeader object
 * @param {object} sourceFolder the MailFolder where the message is currently located
 */
async function markAndMoveToSpam(message, sourceFolder) {
    // 1. Mark message as Junk via messages.update
    try {
        await messenger.messages.update(message.id, { junk: true });
    } catch (err) {
        console.warn(`Could not update junk flag on message ${message.id}:`, err);
    }

    // 2. Find the Junk folder for this account and move the message
    try {
        const accountId = (sourceFolder && sourceFolder.accountId) || (message.folder && message.folder.accountId);
        if (!accountId) {
            return;
        }
        const junkFolders = await messenger.folders.query({
            accountId: accountId,
            specialUse: ['junk']
        });

        if (junkFolders && junkFolders.length > 0) {
            const targetFolderId = junkFolders[0].id;
            if (!sourceFolder || sourceFolder.id !== targetFolderId) {
                await messenger.messages.move([message.id], targetFolderId);
            }
        } else {
            console.warn(`No Junk folder found for account ${accountId}. Message was marked as junk in place.`);
        }
    } catch (err) {
        console.error(`Failed to move message ${message.id} to Junk folder:`, err);
    }
}

/**
 * Extracts the clean email address (e.g. "user@domain.tld") from a sender string
 * @param {string} senderAddress
 * @returns {Promise<string|null>}
 */
async function extractEmailFromAuthor(senderAddress) {
    if (!senderAddress || typeof senderAddress !== 'string') {
        return null;
    }

    if (messenger.messengerUtilities && typeof messenger.messengerUtilities.parseMailboxString === 'function') {
        try {
            const parsed = await messenger.messengerUtilities.parseMailboxString(senderAddress);
            if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].email) {
                return getEmailFromAddress(parsed[0].email);
            }
        } catch (err) {
            console.warn('parseMailboxString failed, falling back to manual email parsing:', err);
        }
    }

    return getEmailFromAddress(senderAddress);
}

/**
 * Synchronous helper to extract clean email address from RFC 5322 author string
 * @param {string} senderAddress
 * @returns {string|null}
 */
function getEmailFromAddress(senderAddress) {
    if (!senderAddress || typeof senderAddress !== 'string') {
        return null;
    }
    const angleMatch = senderAddress.match(/<([^<>]+)>/);
    const addressPart = (angleMatch ? angleMatch[1] : senderAddress).trim();
    if (!addressPart.includes('@')) {
        return null;
    }
    return addressPart.replace(/^[<"'\s]+|[>"'\s]+$/g, '').toLowerCase() || null;
}

/**
 * Checks whether a sender email or domain matches any pattern in the given list (Whitelist / Blacklist).
 * Supports:
 * - Exact email addresses (e.g. "info@example.com")
 * - Wildcard email addresses (e.g. "*@*.relusnelar.org")
 * - Wildcard domains (e.g. "*.relusnelar.org" -> matches "relusnelar.org" and "sub.relusnelar.org")
 * - Plain domains (e.g. "relusnelar.org" -> matches "relusnelar.org" and "*.relusnelar.org")
 * @param {string|null} email
 * @param {string|null} domain
 * @param {string[]} list
 * @returns {string|null} the matched rule or null
 */
function matchListRule(email, domain, list) {
    if (!Array.isArray(list) || list.length === 0) {
        return null;
    }

    const cleanEmail = (email || '').trim().toLowerCase();
    const cleanDomain = (domain || getDomainFromAddress(cleanEmail) || '').trim().toLowerCase();

    function wildcardToRegExp(pattern) {
        const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
        return new RegExp(`^${escaped}$`, 'i');
    }

    for (const rawRule of list) {
        if (!rawRule || typeof rawRule !== 'string') continue;
        const rule = rawRule.trim().toLowerCase();
        if (!rule) continue;

        if (rule.includes('@')) {
            if (!cleanEmail) continue;
            if (rule === cleanEmail) {
                return rawRule.trim();
            }
            if (rule.includes('*') && wildcardToRegExp(rule).test(cleanEmail)) {
                return rawRule.trim();
            }
        } else {
            if (!cleanDomain) continue;
            if (rule.startsWith('*.')) {
                const baseDom = rule.slice(2);
                if (baseDom && (cleanDomain === baseDom || cleanDomain.endsWith(`.${baseDom}`))) {
                    return rawRule.trim();
                }
            } else if (rule.includes('*')) {
                if (wildcardToRegExp(rule).test(cleanDomain)) {
                    return rawRule.trim();
                }
            } else {
                if (cleanDomain === rule || cleanDomain.endsWith(`.${rule}`)) {
                    return rawRule.trim();
                }
            }
        }
    }

    return null;
}

/**
 * Extracts the sender domain using Thunderbird's RFC 5322 parser (messengerUtilities.parseMailboxString)
 * with a fallback to manual string parsing.
 * @param {string} senderAddress 
 * @returns {Promise<string|null>}
 */
async function extractDomainFromAuthor(senderAddress) {
    if (!senderAddress || typeof senderAddress !== 'string') {
        return null;
    }

    if (messenger.messengerUtilities && typeof messenger.messengerUtilities.parseMailboxString === 'function') {
        try {
            const parsed = await messenger.messengerUtilities.parseMailboxString(senderAddress);
            if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].email) {
                return getDomainFromAddress(parsed[0].email);
            }
        } catch (err) {
            console.warn('parseMailboxString failed, falling back to manual parsing:', err);
        }
    }

    return getDomainFromAddress(senderAddress);
}

/**
 * Parses the given sender address (or plain domain) and returns just the domain
 * @param {string} senderAddress 
 */
function getDomainFromAddress(senderAddress) {
    if (!senderAddress || typeof senderAddress !== 'string') {
        return null;
    }

    // Falls eine Adresse in spitzen Klammern steht (z.B. "Name <user@domain.tld>"), extrahiere den Teil darin
    const angleMatch = senderAddress.match(/<([^<>]+)>/);
    const addressPart = angleMatch ? angleMatch[1] : senderAddress;

    const atIndex = addressPart.lastIndexOf('@');
    if (atIndex === -1) {
        return null;
    }

    let domain = addressPart.slice(atIndex + 1).trim();
    // Entfernt eventuelle Restzeichen wie ">", Anführungszeichen oder Leerzeichen
    domain = domain.replace(/[>"'\s]+$/g, '').toLowerCase();

    return domain || null;
}

/**
 * Extracts the registrable root domain (e.g. "mail.sub.example.com" -> "example.com")
 * for RDAP and organizational DMARC lookups.
 * @param {string} domain
 * @returns {string}
 */
function getRegistrableDomain(domain) {
    if (!domain) return '';
    const parts = domain.toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) {
        return parts.join('.');
    }
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
 * Validates a domain and returns both the total score and a detailed breakdown of each check.
 * @param {string} domain the sender domain
 * @param {string[]|null} dkimSig the dkim-signature header array
 * @param {object} [customSettings] optional settings object (loaded from storage if omitted)
 * @param {object|null} [headers] optional full message headers dictionary (for Received / SPF-IP verification)
 * @param {string|null} [senderEmail] optional full sender email address for Whitelist / Blacklist matching
 * @returns {Promise<{ score: number, isSpam: boolean, checks: object, whitelisted?: boolean, blacklisted?: boolean, matchedRule?: string }>}
 */
async function validateDomainDetailed(domain, dkimSig, customSettings = null, headers = null, senderEmail = null) {
    const settings = customSettings || await getSettings();
    const cfg = settings.checks || DEFAULT_SETTINGS.checks;
    const checks = {};
    let score = 0;

    // 0a. Whitelist check (Whitelist always takes precedence over Blacklist and all DNS checks)
    const whiteMatch = matchListRule(senderEmail, domain, settings.whitelist);
    if (whiteMatch) {
        console.log(`Sender ${senderEmail || domain} matched Whitelist rule: ${whiteMatch}`);
        checks.whitelist = {
            enabled: true,
            passed: true,
            scoreDelta: 0,
            info: `Freigegeben durch Whitelist-Regel: ${whiteMatch}`
        };
        return {
            score: 0,
            isSpam: false,
            whitelisted: true,
            matchedRule: whiteMatch,
            checks
        };
    }

    // 0b. Blacklist check
    const blackMatch = matchListRule(senderEmail, domain, settings.blacklist);
    if (blackMatch) {
        console.log(`Sender ${senderEmail || domain} matched Blacklist rule: ${blackMatch}`);
        checks.blacklist = {
            enabled: true,
            passed: false,
            scoreDelta: -1000,
            info: `Gesperrt durch Blacklist-Regel: ${blackMatch}`
        };
        return {
            score: -1000,
            isSpam: true,
            blacklisted: true,
            matchedRule: blackMatch,
            checks
        };
    }

    // Perform A and MX record lookups in parallel
    const [aRecordData, mxRecordData] = await Promise.all([
        getDNSEntry(domain, 'A', true),
        getDNSEntry(domain, 'MX', true)
    ]);

    const isNxDomain = (aRecordData && aRecordData.Status === 3) || (mxRecordData && mxRecordData.Status === 3);
    const hasARecord = Boolean(aRecordData && aRecordData.Status === 0 && Array.isArray(aRecordData.Answer) && aRecordData.Answer.length > 0);
    const hasMXRecord = Boolean(mxRecordData && mxRecordData.Status === 0 && Array.isArray(mxRecordData.Answer) && mxRecordData.Answer.length > 0);

    let hasAAAARecord = false;
    if (!isNxDomain && !hasARecord && !hasMXRecord) {
        const aaaaRecordData = await getDNSEntry(domain, 'AAAA', true);
        hasAAAARecord = Boolean(aaaaRecordData && aaaaRecordData.Status === 0 && Array.isArray(aaaaRecordData.Answer) && aaaaRecordData.Answer.length > 0);
    }

    const domainExists = !isNxDomain && (hasARecord || hasMXRecord || hasAAAARecord);

    // 1. Domain existence check
    if (cfg.domainExists && cfg.domainExists.enabled) {
        const delta = domainExists ? 0 : Number(cfg.domainExists.score ?? -100);
        score += delta;
        checks.domainExists = {
            enabled: true,
            passed: domainExists,
            scoreDelta: delta,
            info: domainExists
                ? `DNS aktiv (${[hasARecord ? 'A' : null, hasAAAARecord ? 'AAAA' : null, hasMXRecord ? 'MX' : null].filter(Boolean).join('/')})`
                : (isNxDomain ? 'NXDOMAIN (existiert nicht)' : 'Keine A/AAAA/MX Records')
        };

        if (!domainExists && cfg.domainExists.stopOnFail !== false) {
            console.log('The domain has no A/AAAA/MX record or does not exist:', domain);
            return {
                score,
                isSpam: score < settings.spamThreshold,
                checks
            };
        }
    } else {
        checks.domainExists = { enabled: false, passed: domainExists, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 2. DNSSEC check
    const hasDNSSEC = Boolean((aRecordData && aRecordData.AD === true) || (mxRecordData && mxRecordData.AD === true));
    if (cfg.dnssec && cfg.dnssec.enabled) {
        const delta = hasDNSSEC ? 0 : Number(cfg.dnssec.score ?? -10);
        score += delta;
        if (!hasDNSSEC) {
            console.log('The domain has no valid DNSSEC signature:', domain);
        }
        checks.dnssec = {
            enabled: true,
            passed: hasDNSSEC,
            scoreDelta: delta,
            info: hasDNSSEC ? 'DNSSEC gültig (AD=true)' : 'Keine DNSSEC-Signatur'
        };
    } else {
        checks.dnssec = { enabled: false, passed: hasDNSSEC, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 3. MX record check
    if (cfg.mx && cfg.mx.enabled) {
        const delta = hasMXRecord ? 0 : Number(cfg.mx.score ?? -20);
        score += delta;
        if (!hasMXRecord) {
            console.log('The domain has no MX record:', domain);
        }
        checks.mx = {
            enabled: true,
            passed: hasMXRecord,
            scoreDelta: delta,
            info: hasMXRecord ? `MX vorhanden (${mxRecordData.Answer.length})` : 'Kein MX-Record'
        };
    } else {
        checks.mx = { enabled: false, passed: hasMXRecord, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 4. SPF record check
    let spfRecord = null;
    if ((cfg.spf && cfg.spf.enabled) || (cfg.spfIpMatch && cfg.spfIpMatch.enabled) || (cfg.spamKitFingerprint && cfg.spamKitFingerprint.enabled)) {
        spfRecord = await getSPFRecord(domain);
    }

    if (cfg.spf && cfg.spf.enabled) {
        const hasSPF = spfRecord != null;
        const delta = hasSPF ? 0 : Number(cfg.spf.score ?? -50);
        score += delta;
        if (!hasSPF) {
            console.log('Invalid/NO SPF record for the domain:', domain);
        }
        checks.spf = {
            enabled: true,
            passed: hasSPF,
            scoreDelta: delta,
            info: hasSPF ? spfRecord.replace(/"/g, '') : 'Kein SPF-Record (v=spf1)'
        };
    } else {
        checks.spf = { enabled: false, passed: null, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 5. DKIM record check
    if (cfg.dkim && cfg.dkim.enabled) {
        const dkimInfo = getDKIMInfo(dkimSig);
        if (!dkimInfo || !dkimInfo.selector) {
            console.log('Missing DKIM signature or selector for the domain:', domain);
            const delta = Number(cfg.dkim.score ?? -20);
            score += delta;
            checks.dkim = {
                enabled: true,
                passed: false,
                scoreDelta: delta,
                info: 'Kein DKIM-Signature Header in E-Mail'
            };
        } else {
            const dkimDomain = dkimInfo.domain || domain;
            const dkimRecord = await getDKIMRecord(dkimDomain, dkimInfo.selector);
            const hasDKIM = dkimRecord != null;
            const delta = hasDKIM ? 0 : Number(cfg.dkim.score ?? -20);
            score += delta;
            if (!hasDKIM) {
                console.log('Invalid/NO DKIM record for the domain:', dkimDomain);
            }
            checks.dkim = {
                enabled: true,
                passed: hasDKIM,
                scoreDelta: delta,
                info: hasDKIM
                    ? `DKIM Schlüssel gefunden (${dkimInfo.selector}._domainkey.${dkimDomain})`
                    : `Kein DNS-Eintrag für ${dkimInfo.selector}._domainkey.${dkimDomain}`
            };
        }
    } else {
        checks.dkim = { enabled: false, passed: null, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 6. DMARC record & policy check (_dmarc.<domain>)
    let dmarcRes = null;
    if ((cfg.dmarc && cfg.dmarc.enabled) || (cfg.spamKitFingerprint && cfg.spamKitFingerprint.enabled)) {
        dmarcRes = await getDMARCRecord(domain);
    }

    if (cfg.dmarc && cfg.dmarc.enabled) {
        const penalizeNone = cfg.dmarc.penalizeNone !== false;
        let passed = false;
        let info = 'Kein DMARC-Record (_dmarc)';

        if (dmarcRes && dmarcRes.record) {
            if (dmarcRes.policy === 'reject' || dmarcRes.policy === 'quarantine') {
                passed = true;
                info = `DMARC aktiv (p=${dmarcRes.policy})`;
            } else if (dmarcRes.policy === 'none') {
                passed = !penalizeNone;
                info = penalizeNone
                    ? 'DMARC hat nur p=none (keine Durchsetzung / typisch für Spam-Domains)'
                    : 'DMARC vorhanden (p=none)';
            } else {
                passed = true;
                info = `DMARC vorhanden (${dmarcRes.record})`;
            }
        }

        const delta = passed ? 0 : Number(cfg.dmarc.score ?? -20);
        score += delta;
        checks.dmarc = {
            enabled: true,
            passed,
            scoreDelta: delta,
            info
        };
    } else {
        checks.dmarc = { enabled: false, passed: null, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 7. Domain Registration Age (RDAP check for Newly Registered Domains)
    if (cfg.domainAge && cfg.domainAge.enabled) {
        const minAgeDays = Math.max(1, Number(cfg.domainAge.minAgeDays) || 90);
        const ageRes = await getDomainAgeRDAP(domain);

        if (!ageRes.available) {
            // Do not penalize TLDs that do not offer public RDAP (e.g. .de)
            checks.domainAge = {
                enabled: true,
                passed: true,
                scoreDelta: 0,
                info: `RDAP für TLD nicht verfügbar (${ageRes.reason || 'übersprungen'})`
            };
        } else {
            const isOldEnough = ageRes.ageDays >= minAgeDays;
            const delta = isOldEnough ? 0 : Number(cfg.domainAge.score ?? -40);
            score += delta;
            const regDateShort = ageRes.regDate ? ageRes.regDate.slice(0, 10) : '';
            checks.domainAge = {
                enabled: true,
                passed: isOldEnough,
                scoreDelta: delta,
                info: isOldEnough
                    ? `Alter: ${ageRes.ageDays} Tage (registriert ${regDateShort}, >= ${minAgeDays}d)`
                    : `Frisch registriert: erst ${ageRes.ageDays} Tage alt (${regDateShort}, < ${minAgeDays}d)`
            };
        }
    } else {
        checks.domainAge = { enabled: false, passed: null, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // Extract IPv4 from A record or Received header for DNSBL & SPF-IP checks
    const aRecordIps = (hasARecord && Array.isArray(aRecordData.Answer))
        ? aRecordData.Answer.filter(r => r.type === 1 && typeof r.data === 'string').map(r => r.data.trim())
        : [];
    const senderIp = extractSenderIPFromHeaders(headers);

    // 8. DNSBL (Domain & IP Blacklist check via DoH)
    if (cfg.dnsbl && cfg.dnsbl.enabled) {
        const ipToCheck = senderIp || (aRecordIps.length > 0 ? aRecordIps[0] : null);
        const blRes = await checkDNSBL(domain, ipToCheck);
        const passed = !blRes.listed;
        const delta = passed ? 0 : Number(cfg.dnsbl.score ?? -80);
        score += delta;
        checks.dnsbl = {
            enabled: true,
            passed,
            scoreDelta: delta,
            info: passed
                ? `Nicht gelistet (${ipToCheck ? `Domain + IP ${ipToCheck}` : 'Domain'})`
                : `Gelistet auf Blacklist: ${blRes.lists.join(', ')}`
        };
    } else {
        checks.dnsbl = { enabled: false, passed: null, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 9. SPF Sender-IP / Authentication-Results Verification
    if (cfg.spfIpMatch && cfg.spfIpMatch.enabled) {
        const spfEval = evaluateSenderSPFFromHeadersAndDNS(headers, spfRecord, aRecordIps);
        const passed = spfEval.passed;
        const delta = passed ? 0 : Number(cfg.spfIpMatch.score ?? -40);
        score += delta;
        checks.spfIpMatch = {
            enabled: true,
            passed,
            scoreDelta: delta,
            info: spfEval.info
        };
    } else {
        checks.spfIpMatch = { enabled: false, passed: null, scoreDelta: 0, info: 'Deaktiviert' };
    }

    // 10. Spam-Kit DNS Generator Fingerprint check (purely DNS-based, zero direct HTTP calls to unknown servers)
    if (cfg.spamKitFingerprint && cfg.spamKitFingerprint.enabled) {
        const kitEval = evaluateSpamKitFingerprint(domain, aRecordIps, mxRecordData, spfRecord, dmarcRes);
        const passed = !kitEval.detected;
        const delta = passed ? 0 : Number(cfg.spamKitFingerprint.score ?? -80);
        score += delta;
        checks.spamKitFingerprint = {
            enabled: true,
            passed,
            scoreDelta: delta,
            info: kitEval.info
        };
    } else {
        checks.spamKitFingerprint = { enabled: false, passed: null, scoreDelta: 0, info: 'Deaktiviert' };
    }

    return {
        score,
        isSpam: score < settings.spamThreshold,
        checks
    };
}

/**
 * Validate the given domain, of its existence, by the SPF record and the DKIM signature of the EMAIL header.
 * It will return a score based on the criticality of its checks. A negative score means that it fails some checks.
 * @param {string} domain the domain read from the original (sender) address
 * @param {string[]} dkimSig the DKIM signature read from the email header "message.headers['dkim-signature']"
 * @returns {Promise<number>} the score of the validation.
 */
async function validateDomain(domain, dkimSig) {
    const result = await validateDomainDetailed(domain, dkimSig);
    return result.score;
}

/**
 * Fetches the DMARC record (_dmarc.<domain>, with fallback to organizational domain)
 * and extracts the policy (p=none | quarantine | reject).
 * @param {string} domain
 * @returns {Promise<{ record: string, policy: string|null } | null>}
 */
async function getDMARCRecord(domain) {
    if (!domain) return null;

    async function queryDmarcFor(target) {
        const data = await getDNSEntry(`_dmarc.${target}`, 'TXT');
        if (!data || data.Status !== 0 || !Array.isArray(data.Answer)) {
            return null;
        }
        const rec = data.Answer.find(r => {
            if (typeof r.data !== 'string') return false;
            return r.data.replace(/"/g, '').trim().toUpperCase().startsWith('V=DMARC1');
        });
        if (!rec) return null;
        const clean = rec.data.replace(/"/g, '').trim();
        const policyMatch = clean.match(/(?:^|;)\s*p\s*=\s*([a-zA-Z]+)/i);
        return {
            record: clean,
            policy: policyMatch ? policyMatch[1].toLowerCase() : null
        };
    }

    let res = await queryDmarcFor(domain);
    if (!res) {
        const rootDomain = getRegistrableDomain(domain);
        if (rootDomain && rootDomain !== domain) {
            res = await queryDmarcFor(rootDomain);
        }
    }
    return res;
}

/**
 * Loads the official IANA RDAP bootstrap table once and maps each TLD to its HTTPS RDAP base URL.
 * This avoids cross-origin 302 redirects (via rdap.org) and prevents unnecessary requests for TLDs without RDAP (like .de).
 * @returns {Promise<Map<string, string>>}
 */
async function getRdapTldMap() {
    if (g_RDAP_TLD_MAP) {
        return g_RDAP_TLD_MAP;
    }
    if (g_RDAP_BOOTSTRAP_PROMISE) {
        return g_RDAP_BOOTSTRAP_PROMISE;
    }

    g_RDAP_BOOTSTRAP_PROMISE = (async () => {
        try {
            const response = await fetch(g_IANA_RDAP_BOOTSTRAP_URL);
            if (!response.ok) {
                return new Map();
            }
            const data = await response.json();
            const map = new Map();
            if (data && Array.isArray(data.services)) {
                for (const entry of data.services) {
                    const tlds = entry[0];
                    const urls = entry[1];
                    if (!Array.isArray(tlds) || !Array.isArray(urls) || urls.length === 0) continue;
                    const httpsUrl = urls.find(u => typeof u === 'string' && u.startsWith('https://')) || urls[0];
                    if (!httpsUrl) continue;
                    const normalizedBase = httpsUrl.endsWith('/') ? httpsUrl : `${httpsUrl}/`;
                    for (const tld of tlds) {
                        map.set(String(tld).toLowerCase(), normalizedBase);
                    }
                }
            }
            g_RDAP_TLD_MAP = map;
            return map;
        } catch (err) {
            console.warn('Could not load IANA RDAP bootstrap table:', err);
            return new Map();
        } finally {
            g_RDAP_BOOTSTRAP_PROMISE = null;
        }
    })();

    return g_RDAP_BOOTSTRAP_PROMISE;
}

/**
 * Queries the authoritative RDAP server for the domain's TLD to determine registration age in days.
 * Results are cached in memory for 60 minutes.
 * @param {string} domain
 * @returns {Promise<{ available: boolean, ageDays?: number, regDate?: string, reason?: string }>}
 */
async function getDomainAgeRDAP(domain) {
    const rootDomain = getRegistrableDomain(domain);
    if (!rootDomain || !rootDomain.includes('.')) {
        return { available: false, reason: 'Ungültige Domain' };
    }

    const now = Date.now();
    const cached = g_RDAP_CACHE.get(rootDomain);
    if (cached && (now - cached.timestamp) < g_RDAP_CACHE_TTL_MS) {
        return cached.result;
    }

    const tld = rootDomain.split('.').pop().toLowerCase();
    const tldMap = await getRdapTldMap();
    const rdapBaseUrl = tldMap.get(tld);

    if (!rdapBaseUrl) {
        const result = { available: false, reason: `Kein RDAP für .${tld}` };
        g_RDAP_CACHE.set(rootDomain, { timestamp: now, result });
        return result;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
        const url = `${rdapBaseUrl}domain/${encodeURIComponent(rootDomain)}`;
        const response = await fetch(url, {
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            const result = { available: false, reason: `HTTP ${response.status}` };
            g_RDAP_CACHE.set(rootDomain, { timestamp: now, result });
            return result;
        }

        const data = await response.json();
        const events = Array.isArray(data.events) ? data.events : [];
        const regEvent = events.find(e => e && (e.eventAction === 'registration' || e.eventAction === 'registered'));
        if (!regEvent || !regEvent.eventDate) {
            const result = { available: false, reason: 'Kein Registrierungsdatum im RDAP' };
            g_RDAP_CACHE.set(rootDomain, { timestamp: now, result });
            return result;
        }

        const regTime = new Date(regEvent.eventDate).getTime();
        if (Number.isNaN(regTime)) {
            return { available: false, reason: 'Ungültiges Datum' };
        }

        const ageDays = Math.max(0, Math.floor((now - regTime) / (1000 * 60 * 60 * 24)));
        const result = {
            available: true,
            ageDays,
            regDate: regEvent.eventDate
        };
        g_RDAP_CACHE.set(rootDomain, { timestamp: now, result });
        return result;
    } catch (err) {
        clearTimeout(timeoutId);
        const result = { available: false, reason: err.name === 'AbortError' ? 'Timeout' : 'RDAP-Server nicht erreichbar' };
        g_RDAP_CACHE.set(rootDomain, { timestamp: now, result });
        return result;
    }
}

/**
 * Checks domain and optional IPv4 address against DNS-based blacklists via DoH.
 * Ignores public-resolver policy/error return codes in 127.255.255.0/24.
 * @param {string} domain
 * @param {string|null} ipv4
 * @returns {Promise<{ listed: boolean, lists: string[] }>}
 */
async function checkDNSBL(domain, ipv4 = null) {
    const rootDomain = getRegistrableDomain(domain) || domain;
    const queries = [
        { label: 'Nordspam DBL', host: `${rootDomain}.dbl.nordspam.com` },
        { label: 'Spamhaus DBL', host: `${rootDomain}.dbl.spamhaus.org` }
    ];

    if (ipv4 && /^\d{1,3}(\.\d{1,3}){3}$/.test(ipv4)) {
        const reversedIp = ipv4.split('.').reverse().join('.');
        queries.push(
            { label: 'Nordspam IP-BL', host: `${reversedIp}.bl.nordspam.com` },
            { label: 'SpamCop BL', host: `${reversedIp}.bl.spamcop.net` },
            { label: '0spam BL', host: `${reversedIp}.bl.0spam.org` }
        );
    }

    const results = await Promise.all(
        queries.map(async (q) => {
            const data = await getDNSEntry(q.host, 'A', true);
            if (!data || data.Status !== 0 || !Array.isArray(data.Answer) || data.Answer.length === 0) {
                return null;
            }
            // Valid DNSBL positive hits return 127.0.x.x (ignore 127.255.255.* open-resolver error codes)
            const validHit = data.Answer.find(a =>
                a.type === 1 &&
                typeof a.data === 'string' &&
                a.data.startsWith('127.0.') &&
                !a.data.startsWith('127.255.')
            );
            return validHit ? `${q.label} (${validHit.data})` : null;
        })
    );

    const lists = results.filter(Boolean);
    return {
        listed: lists.length > 0,
        lists
    };
}

/**
 * Extracts the external sender IPv4 address from message 'received' headers
 * @param {object|null} headers
 * @returns {string|null}
 */
function extractSenderIPFromHeaders(headers) {
    if (!headers || typeof headers !== 'object') {
        return null;
    }
    const received = headers['received'];
    if (!Array.isArray(received) || received.length === 0) {
        return null;
    }

    function isPublicIPv4(ip) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false;
        if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return false;
        if (parts[0] === 192 && parts[1] === 168) return false;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
        return true;
    }

    for (const line of received) {
        if (typeof line !== 'string') continue;
        const matches = line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g);
        if (matches) {
            const pub = matches.find(isPublicIPv4);
            if (pub) return pub;
        }
    }
    return null;
}

/**
 * Evaluates whether the message's headers or sender IP violate the domain's SPF policy
 * @param {object|null} headers
 * @param {string|null} spfRecord
 * @param {string[]} aRecordIps
 * @returns {{ passed: boolean, info: string }}
 */
function evaluateSenderSPFFromHeadersAndDNS(headers, spfRecord, aRecordIps = []) {
    if (!headers || typeof headers !== 'object') {
        return {
            passed: true,
            info: 'Keine E-Mail-Header (Manueller Domain-Test)'
        };
    }

    // 1. Check Authentication-Results or Received-SPF header if added by receiving mail server
    const authResults = [].concat(headers['authentication-results'] || [], headers['received-spf'] || []).join(' \n ');
    if (authResults) {
        if (/\bspf\s*=\s*(fail|softfail|permerror)\b/i.test(authResults) || /^fail\b/i.test(authResults.trim())) {
            return {
                passed: false,
                info: 'Laut Mailserver-Header ist SPF fehlgeschlagen (spf=fail/softfail)'
            };
        }
        if (/\bspf\s*=\s*pass\b/i.test(authResults) || /^pass\b/i.test(authResults.trim())) {
            return {
                passed: true,
                info: 'SPF-IP laut Mailserver-Header autorisiert (spf=pass)'
            };
        }
    }

    // 2. Fallback: compare sender IP from Received header against explicit ip4: / a mechanisms when "-all" or "~all" is used
    const senderIp = extractSenderIPFromHeaders(headers);
    if (!senderIp || !spfRecord) {
        return {
            passed: true,
            info: senderIp ? `Einlieferungs-IP: ${senderIp}` : 'Keine externe Einlieferungs-IP im Header'
        };
    }

    const cleanSpf = spfRecord.replace(/"/g, '').trim();
    const hasIncludeOrRedirect = /\b(include:|redirect=|exists:)/i.test(cleanSpf);
    const isStrictAll = /\s[-~]all\b/i.test(cleanSpf);

    if (!hasIncludeOrRedirect && isStrictAll) {
        const allowedIps = new Set(aRecordIps);
        const ip4Matches = cleanSpf.match(/\bip4:(\d{1,3}(?:\.\d{1,3}){3})(?:\/\d+)?\b/gi) || [];
        for (const m of ip4Matches) {
            const ip = m.replace(/^ip4:/i, '').split('/')[0];
            allowedIps.add(ip);
        }

        if (allowedIps.size > 0 && !allowedIps.has(senderIp)) {
            return {
                passed: false,
                info: `Einlieferungs-IP (${senderIp}) stimmt nicht mit SPF (${Array.from(allowedIps).join(', ')}) überein`
            };
        }
    }

    return {
        passed: true,
        info: `Einlieferungs-IP (${senderIp}) plausibel`
    };
}

/**
 * Evaluates whether a domain exhibits the DNS provisioning fingerprint of automated bulk-spam
 * domain generators (e.g. esourl.org, gottlieb.relusnelar.org, logicvanta.info,
 * denesik.heatrica.shop, initives.org, snismirpel.com).
 * Operates purely on already-queried DoH DNS records (0 extra network calls, never triggers CORS/NetworkError).
 * @param {string} domain
 * @param {string[]} aRecordIps
 * @param {object|null} mxRecordData
 * @param {string|null} spfRecord
 * @param {{ record: string, policy: string|null }|null} dmarcRes
 * @returns {{ detected: boolean, info: string, indicators: string[] }}
 */
function evaluateSpamKitFingerprint(domain, aRecordIps, mxRecordData, spfRecord, dmarcRes) {
    const cleanDom = (domain || '').toLowerCase().trim();
    const rootDom = getRegistrableDomain(cleanDom) || cleanDom;
    const dnsIndicators = [];

    // Indicator 1: Automated DMARC generator string:
    // "v=DMARC1; p=none; rua=mailto:postmaster@<domain>; ruf=mailto:dmarc@<domain>"
    if (dmarcRes && dmarcRes.record && dmarcRes.policy === 'none') {
        const dmarcClean = dmarcRes.record.toLowerCase();
        if (dmarcClean.includes(`rua=mailto:postmaster@${cleanDom}`) && dmarcClean.includes(`ruf=mailto:dmarc@${cleanDom}`)) {
            dnsIndicators.push('Generator-DMARC (p=none + postmaster/dmarc)');
        }
    }

    // Indicator 2: Self-referential MX ("10 <domain>.") combined with raw IP-only SPF ("v=spf1 a mx ip4:... -all")
    const mxAnswers = (mxRecordData && Array.isArray(mxRecordData.Answer)) ? mxRecordData.Answer : [];
    const hasSelfMx10 = mxAnswers.length === 1 &&
        typeof mxAnswers[0].data === 'string' &&
        mxAnswers[0].data.trim().toLowerCase().replace(/\.$/, '') === `10 ${cleanDom}`;

    const cleanSpf = spfRecord ? spfRecord.replace(/"/g, '').trim().toLowerCase() : '';
    const isRawIpSpfTemplate = /^v=spf1\s+a\s+mx(?:\s+ip4:[0-9./]+)+\s+-all$/i.test(cleanSpf);

    if (hasSelfMx10 && isRawIpSpfTemplate) {
        dnsIndicators.push('Spam-Kit MX/SPF-Muster (10 <domain> + v=spf1 a mx ip4 -all)');
    }

    // Indicator 3: Redundant A-record IP explicitly duplicated inside "v=spf1 a mx ip4:<A-IP> -all"
    if (isRawIpSpfTemplate && Array.isArray(aRecordIps) && aRecordIps.length > 0) {
        const spfIps = (cleanSpf.match(/\bip4:(\d{1,3}(?:\.\d{1,3}){3})\b/g) || []).map(s => s.replace(/^ip4:/, ''));
        const duplicateAIp = aRecordIps.find(ip => spfIps.includes(ip));
        if (duplicateAIp) {
            dnsIndicators.push(`Redundante A-Record-IP im Baukasten-SPF (${duplicateAIp})`);
        }
    }

    // Indicator 4: Snowshoe multi-IP same /24 subnet in SPF (e.g. 3 IPs from same /24 subnet)
    if (cleanSpf) {
        const ipMatches = cleanSpf.match(/\bip4:(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b/g) || [];
        const prefixes = ipMatches.map(m => m.replace(/^ip4:/, '').split('.').slice(0, 3).join('.'));
        const prefixCounts = {};
        for (const p of prefixes) {
            prefixCounts[p] = (prefixCounts[p] || 0) + 1;
        }
        const snowshoePrefix = Object.keys(prefixCounts).find(p => prefixCounts[p] >= 2);
        if (snowshoePrefix && isRawIpSpfTemplate) {
            dnsIndicators.push(`Snowshoe-SPF (${prefixCounts[snowshoePrefix]} IPs im Netz ${snowshoePrefix}.0/24)`);
        }
    }

    // Indicator 5: Disposable random subdomain with its own self-MX (e.g. gottlieb.relusnelar.org, denesik.heatrica.shop)
    const commonSubdomains = new Set(['mail', 'www', 'smtp', 'mx', 'newsletter', 'news', 'info', 'service', 'support', 'shop', 'billing', 'noreply', 'no-reply', 'bounce', 'em', 'email', 'mta']);
    if (cleanDom !== rootDom) {
        const subPrefix = cleanDom.slice(0, cleanDom.length - rootDom.length - 1);
        if (subPrefix && !commonSubdomains.has(subPrefix) && hasSelfMx10) {
            dnsIndicators.push(`Wegwerf-Subdomain mit eigenem Self-MX (${subPrefix}.*)`);
        }
    }

    // Flag as spam-kit when at least 2 generator indicators match simultaneously
    const detected = dnsIndicators.length >= 2;

    if (detected) {
        return {
            detected: true,
            indicators: dnsIndicators,
            info: `Spam-Baukasten erkannt: ${dnsIndicators.join(' + ')}`
        };
    }

    return {
        detected: false,
        indicators: dnsIndicators,
        info: dnsIndicators.length > 0
            ? `Unauffällig (1 Einzelmerkmal: ${dnsIndicators[0]})`
            : 'Kein bekannter Spam-Baukasten-Fingerabdruck'
    };
}

/**
 * Fetches the SPF record from the given domain by using cloudflare as DoH service
 * @param {string} domain the domain to read the SPF record from
 * @returns {Promise<string|null>} the SPF result if available, otherwise it will return null
 */
async function getSPFRecord(domain) {
    const data = await getDNSEntry(domain, 'TXT');
    if (!data || data.Status !== 0 || !Array.isArray(data.Answer) || data.Answer.length === 0) {
        console.warn(`Keine TXT-Einträge für ${domain} gefunden.`);
        return null;
    }

    // Filtern Sie nach SPF-Einträgen (z.B. "v=spf1 ...")
    const spfRecord = data.Answer.find(rec => {
        if (typeof rec.data !== 'string') return false;
        const recordData = rec.data.replace(/"/g, '').trim();
        return recordData.toLowerCase().startsWith('v=spf1');
    });

    return spfRecord ? spfRecord.data : null;
}

/**
 * Reads the DKIM record via cloudflare (DoH service) and returns it, or null if the entry could not be found.
 * @param {string} domain the domain to check
 * @param {string} selector DKIM selector read from the Email header ([Selektor]._domainkey.[Domäne])
 * @returns {Promise<object|null>}
 */
async function getDKIMRecord(domain, selector) {
    if (!domain || !selector) {
        return null;
    }

    // Der DoH-Endpunkt und die spezifische DNS-Anfrage für den DKIM-Eintrag.
    const query = `${selector}._domainkey.${domain}`;
    const data = await getDNSEntry(query, 'TXT');

    // Suchen nach dem DKIM-TXT-Eintrag, der den öffentlichen Schlüssel enthält.
    if (data && Array.isArray(data.Answer) && data.Answer.length > 0) {
        const dkimEntry = data.Answer.find(rec => {
            if (typeof rec.data !== 'string') return false;
            const normalized = rec.data.replace(/"\s*"/g, '').replace(/"/g, '');
            return normalized.includes('p=') || normalized.includes('v=DKIM1') || normalized.includes('k=rsa');
        });
        if (dkimEntry != null) {
            return dkimEntry;
        }
    }

    console.log(`Kein DKIM-Eintrag gefunden für: ${query}`);
    return null;
}

/**
 * Extracts both the DKIM selector (s=) and signing domain (d=) from the first DKIM-Signature header.
 * @param {string[]} dkimHeaders usually the result from message.headers['dkim-signature']
 * @returns {{ selector: string|null, domain: string|null } | null}
 */
function getDKIMInfo(dkimHeaders) {
    if (!Array.isArray(dkimHeaders) || dkimHeaders.length === 0 || !dkimHeaders[0]) {
        console.log('Keine DKIM-Header in der Nachricht gefunden.');
        return null;
    }

    const dkimHeaderString = dkimHeaders[0];
    const parts = dkimHeaderString.split(';');
    let selector = null;
    let domain = null;

    for (const part of parts) {
        const trimmedPart = part.replace(/\s+/g, '');
        if (trimmedPart.startsWith('s=')) {
            selector = trimmedPart.substring(2);
        } else if (trimmedPart.startsWith('d=')) {
            domain = trimmedPart.substring(2).toLowerCase();
        }
    }

    if (!selector) {
        console.log('Kein Selektor im ersten DKIM-Header gefunden.', dkimHeaderString);
        return null;
    }

    return { selector, domain };
}

/**
 * Read the DKIM selector part from the first DKIM header and return it.
 * @param {string[]} dkimHeaders usually the result from the message.headers['dkim-signature'];
 * @returns {string|null} the found DKIM selector or null
 */
function getDKIMSelector(dkimHeaders) {
    const info = getDKIMInfo(dkimHeaders);
    return info ? info.selector : null;
}

/**
 * Checks if the given domain has a matching A record
 * @param {string} domain the domain of which to read the A record from
 * @returns {Promise<boolean>}
 */
async function doesDomainExist(domain) {
    const answer = await getDNSEntry(domain, 'A');
    return (answer != null);
}

/**
 * Checks if the given domain has a matching A record and DNSSEC-Signature
 * @param {string} domain the domain of which to read the A record from
 * @returns {Promise<boolean>}
 */
async function hasValidDNSSEC(domain) {
    const answer = await getDNSEntry(domain, 'A');
    return (answer != null && answer.AD === true);
}

/**
 * Checks if the given domain has a matching MX record
 * @param {string} domain the domain of which to read the MX record from
 * @returns {Promise<boolean>}
 */
async function hasDomainMXRecord(domain) {
    const answer = await getDNSEntry(domain, 'MX');
    return answer != null;
}

/**
 * Fetches the given DNS type entry of the given domain by using cloudflare as DoH service.
 * Returns the answer if it was available, otherwise it will return null (unless returnRawStatus is true).
 * @param {string} domain the domain name to check
 * @param {string} type the type of record to request (e.g. A, AAAA, MX, TXT)
 * @param {boolean} [returnRawStatus=false] if true, returns the parsed JSON even when Answer is empty (to inspect Status like NXDOMAIN)
 * @returns {Promise<object|null>} the result data (response.json()) of the response of the fetch request
 */
async function getDNSEntry(domain, type, returnRawStatus = false) {
    if (!domain) {
        return null;
    }

    const cacheKey = `${domain.toLowerCase()}:${type.toUpperCase()}`;
    const now = Date.now();
    const cached = g_DNS_CACHE.get(cacheKey);

    let data = null;
    if (cached && (now - cached.timestamp) < g_DNS_CACHE_TTL_MS) {
        data = cached.data;
    } else {
        const url = `${g_DOH_SERVICE_URL}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
        const headers = { 'accept': 'application/dns-json' };

        try {
            const response = await fetch(url, { headers });
            if (!response.ok) {
                console.warn(`DoH HTTP-Fehler (${response.status}) für ${domain} (${type}).`);
                return null;
            }
            data = await response.json();
            g_DNS_CACHE.set(cacheKey, { timestamp: now, data });
        } catch (error) {
            console.error('Fehler bei der DNS-Abfrage:', error);
            return null;
        }
    }

    if (returnRawStatus) {
        return data;
    }

    // Wenn die "Answer"-Sektion leer ist, hat die Domäne keinen entsprechenden Record.
    if (!data || data.Status !== 0 || !Array.isArray(data.Answer) || data.Answer.length === 0) {
        console.warn(`Domäne '${domain}' scheint nicht zu existieren oder hat keinen ${type}-Record.`);
        return null;
    }

    return data; // Es wurden DNS-Einträge gefunden.
}

/**
 * Performs a fetch operation for the given url with an optional timeout and measures the latency
 * @param {string} url the url to fetch
 * @param {number} [timeout=5000] optional timeout in ms
 * @returns {Promise<{ success: boolean, latency: number }>} the time in milliseconds or -1 if it resulted in an error
 */
async function measureLatency(url, timeout = 5000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    const startTime = performance.now();

    try {
        const response = await fetch(url, {
            method: 'HEAD', // HEAD ist schneller als GET
            signal: controller.signal
        });
        clearTimeout(id);
        const endTime = performance.now();
        const latency = endTime - startTime;
        return { success: response.ok, latency: latency };
    } catch (error) {
        clearTimeout(id);
        if (error.name === 'AbortError') {
            console.error('Anfrage wegen Timeout abgebrochen.');
        } else {
            console.error('Fetch-Anfrage fehlgeschlagen:', error);
        }
        return { success: false, latency: -1 };
    }
}

/**
 * Collects all folders across all accounts in a flat list for UI folder selection
 */
async function getAllFoldersList() {
    if (!messenger.accounts || !messenger.accounts.list) {
        return [];
    }
    const accounts = await messenger.accounts.list(true);
    const result = [];

    function walkFolders(folders, accountName, prefix = '') {
        if (!Array.isArray(folders)) return;
        for (const f of folders) {
            const displayPath = prefix ? `${prefix} / ${f.name}` : f.name;
            result.push({
                id: f.id,
                name: f.name,
                accountId: f.accountId,
                accountName,
                displayPath: `${accountName}: ${displayPath}`,
                specialUse: f.specialUse || []
            });
            if (Array.isArray(f.subFolders) && f.subFolders.length > 0) {
                walkFolders(f.subFolders, accountName, displayPath);
            }
        }
    }

    for (const acc of accounts) {
        walkFolders(acc.folders, acc.name);
    }
    return result;
}

/**
 * Handles messages from Popup and Options/Diagnostics pages
 */
if (messenger.runtime && messenger.runtime.onMessage) {
    messenger.runtime.onMessage.addListener(async (request) => {
        if (!request || !request.action) {
            return null;
        }

        try {
            switch (request.action) {
                case 'GET_STATE': {
                    const settings = await getSettings();
                    const logData = messenger.storage ? await messenger.storage.local.get('diagnosticLog') : {};
                    return {
                        settings: JSON.parse(JSON.stringify(settings)),
                        defaultSettings: cloneDefaults(),
                        diagnosticLog: Array.isArray(logData.diagnosticLog) ? logData.diagnosticLog : [],
                        scanState: Object.assign({}, g_SCAN_STATE),
                        cacheSize: g_DNS_CACHE.size + g_RDAP_CACHE.size
                    };
                }

                case 'SAVE_SETTINGS': {
                    const current = await getSettings();
                    const nextSettings = Object.assign({}, current, request.settings || {});
                    await messenger.storage.local.set({ settings: nextSettings });
                    return { success: true, settings: JSON.parse(JSON.stringify(nextSettings)) };
                }

                case 'RESET_SETTINGS': {
                    const defaults = cloneDefaults();
                    await messenger.storage.local.set({ settings: defaults });
                    return { success: true, settings: defaults };
                }

                case 'CLEAR_LOG': {
                    await messenger.storage.local.set({ diagnosticLog: [] });
                    notifyUI({ type: 'LOG_UPDATED', entry: null, scanState: g_SCAN_STATE });
                    return { success: true };
                }

                case 'CLEAR_DNS_CACHE': {
                    g_DNS_CACHE.clear();
                    g_RDAP_CACHE.clear();
                    return { success: true, cacheSize: 0 };
                }

                case 'GET_ALL_FOLDERS': {
                    const folders = await getAllFoldersList();
                    return { folders };
                }

                case 'SCAN_ACTIVE_FOLDER': {
                    if (!messenger.mailTabs) {
                        return { error: 'mailTabs API nicht verfügbar.' };
                    }
                    const tabs = await messenger.mailTabs.query({ active: true, currentWindow: true });
                    const activeTab = tabs && tabs.length > 0 ? tabs[0] : await messenger.mailTabs.getCurrent();
                    if (!activeTab || !activeTab.displayedFolder) {
                        return { error: 'Kein aktiver Ordner in Thunderbird ausgewählt.' };
                    }
                    return await scanFolder(activeTab.displayedFolder, 'folder-scan');
                }

                case 'SCAN_SELECTED_MESSAGES': {
                    if (!messenger.mailTabs) {
                        return { error: 'mailTabs API nicht verfügbar.' };
                    }
                    const tabs = await messenger.mailTabs.query({ active: true, currentWindow: true });
                    const activeTab = tabs && tabs.length > 0 ? tabs[0] : await messenger.mailTabs.getCurrent();
                    const msgList = await messenger.mailTabs.getSelectedMessages();
                    if (!msgList || !msgList.messages || msgList.messages.length === 0) {
                        return { error: 'Keine E-Mails in der aktuellen Ansicht ausgewählt.' };
                    }
                    return await scanMessageList(msgList, activeTab ? activeTab.displayedFolder : null, 'selected-messages');
                }

                case 'SCAN_FOLDER_BY_ID': {
                    if (!request.folderId) {
                        return { error: 'Keine Ordner-ID angegeben.' };
                    }
                    const allFolders = await getAllFoldersList();
                    const found = allFolders.find(f => f.id === request.folderId) || { id: request.folderId, name: request.folderName || request.folderId };
                    return await scanFolder(found, 'folder-scan');
                }

                case 'TEST_DOMAIN': {
                    const rawInput = (request.input || '').trim();
                    const senderEmail = rawInput.includes('@') ? await extractEmailFromAuthor(rawInput) : null;
                    const domain = rawInput.includes('@') ? await extractDomainFromAuthor(rawInput) : rawInput.toLowerCase();
                    if (!domain) {
                        return { error: 'Bitte eine gültige Domain oder E-Mail-Adresse eingeben.' };
                    }
                    const dkimHeaders = request.dkimHeader ? [request.dkimHeader] : null;
                    const result = await validateDomainDetailed(domain, dkimHeaders, null, null, senderEmail);
                    return { domain, senderEmail, ...result };
                }

                case 'MODIFY_LIST': {
                    const listType = request.listType === 'whitelist' ? 'whitelist' : 'blacklist';
                    const op = request.op || 'add'; // 'add' | 'remove'
                    const pattern = String(request.pattern || '').trim().toLowerCase();
                    if (!pattern) {
                        return { error: 'Kein gültiger Eintrag angegeben.' };
                    }

                    const current = await getSettings();
                    const list = Array.isArray(current[listType]) ? [...current[listType]] : [];

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

                    current[listType] = list;
                    await messenger.storage.local.set({ settings: current });
                    notifyUI({ type: 'SETTINGS_UPDATED', settings: current });
                    return { success: true, settings: JSON.parse(JSON.stringify(current)) };
                }

                default:
                    return null;
            }
        } catch (err) {
            console.error(`Error handling runtime action ${request.action}:`, err);
            return { error: err && err.message ? err.message : String(err) };
        }
    });
}
