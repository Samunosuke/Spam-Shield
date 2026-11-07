// Listener für den Empfang von Nachrichten
messenger.messages.onNewMailReceived.addListener(handleMessages, true); // monitorAllFolders = true

/**
 * Defines the Domain DNS checkup service URL (currently we are using hardcoded cloudflare for this)
 */
const g_DOH_SERVICE_URL = 'https://cloudflare-dns.com/dns-query';

/**
 * Simple in-memory cache for DoH DNS responses to avoid redundant network requests
 * Key: `${domain}:${type}`, Value: { timestamp: number, data: object | null }
 */
const g_DNS_CACHE = new Map();
const g_DNS_CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

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
    // Ensure default settings exist in storage
    try {
        const stored = await getSettings();
        await messenger.storage.local.set({ settings: stored });
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
    }).catch(err => console.warn('Failed to create context menus:', err));
}

if (messenger.menus && messenger.menus.onClicked) {
    messenger.menus.onClicked.addListener(async (info, tab) => {
        if (info.menuItemId === 'suke-validate-folder') {
            const folders = info.selectedFolders || (info.selectedFolder ? [info.selectedFolder] : []);
            for (const folder of folders) {
                await scanFolder(folder, 'context-folder');
            }
        } else if (info.menuItemId === 'suke-validate-messages') {
            let msgList = info.selectedMessages;
            if (!msgList && messenger.mailTabs && tab) {
                msgList = await messenger.mailTabs.getSelectedMessages(tab.id);
            }
            if (msgList) {
                await scanMessageList(msgList, null, 'context-messages');
            }
        }
    });
}

/**
 * Loads current settings merged with DEFAULT_SETTINGS
 * @returns {Promise<typeof DEFAULT_SETTINGS>}
 */
async function getSettings() {
    if (!messenger.storage || !messenger.storage.local) {
        return structuredClone(DEFAULT_SETTINGS);
    }
    try {
        const data = await messenger.storage.local.get('settings');
        const saved = data && data.settings ? data.settings : {};
        const mergedChecks = {};
        for (const [key, defVal] of Object.entries(DEFAULT_SETTINGS.checks)) {
            mergedChecks[key] = Object.assign({}, defVal, saved.checks && saved.checks[key] ? saved.checks[key] : {});
        }
        return Object.assign({}, DEFAULT_SETTINGS, saved, { checks: mergedChecks });
    } catch (err) {
        console.warn('Failed to load settings from storage, using defaults:', err);
        return structuredClone(DEFAULT_SETTINGS);
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
    // Ignore messages arriving directly in Junk, Trash, Sent, Drafts, etc.
    if (folder && Array.isArray(folder.specialUse)) {
        if (folder.specialUse.some(use => g_IGNORED_FOLDER_TYPES.has(use))) {
            console.log(`Skipping folder ${folder.name} (specialUse: ${folder.specialUse.join(', ')})`);
            return;
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
             * Evaluates a single message, records the result in the live diagnostic log,
             * and moves/marks it as spam if below threshold (unless dryRun is enabled).
             * @param {object} message Thunderbird MessageHeader
             * @param {object|null} folder Thunderbird MailFolder
             * @param {object} settings Current addon settings
             * @param {string} source 'auto' | 'folder-scan' | 'context-folder' | 'context-messages' | 'selected-messages'
             * @returns {Promise<{ isSpam: boolean, score: number }>}
             */
            async function evaluateAndProcessMessage(message, folder, settings, source = 'auto') {
                const targetFolder = folder || message.folder || null;
                const folderName = targetFolder ? targetFolder.name : 'Unbekannt';
                console.log(`Validating ${message.author}:[${message.subject}] (messageID: ${message.id}...)`);

                try {
                    const senderAddress = message.author || '';
                    const domain = await extractDomainFromAuthor(senderAddress);
                    if (!domain) {
                        console.warn(`Could not extract domain from sender address: ${senderAddress}`);
                        await appendDiagnosticLog({
                            id: `${Date.now()}-${message.id}`,
                            timestamp: Date.now(),
                            messageId: message.id,
                            author: senderAddress,
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

                    // Perform detailed domain validation
                    const result = await validateDomainDetailed(domain, dkimSig, settings);
                    const { score, isSpam, checks } = result;
                    console.log(`Validation score for ${domain} (messageID: ${message.id}): ${score} (threshold: ${settings.spamThreshold})`);

                    let actionTaken = 'passed';
                    let actionLabel = 'OK';

                    if (isSpam) {
                        if (settings.dryRun) {
                            console.log(`[DRY-RUN SPAM] Would mark message from ${message.author} (score: ${score}) as Junk.`);
                            actionTaken = 'dry-run';
                            actionLabel = 'Spam (Dry-Run – nicht verschoben)';
                        } else {
                            console.log(`[SPAM] Marking message from ${message.author} (score: ${score}) as Junk and moving to Spam folder.`);
                            await markAndMoveToSpam(message, targetFolder);
                            actionTaken = 'moved';
                            actionLabel = 'Als Spam markiert & verschoben';
                        }
                    }

                    console.log(`Handling incoming messages in folder: ${folder ? folder.name : 'unknown'}`);
                    await appendDiagnosticLog({
                        id: `${Date.now()}-${message.id}-${Math.random().toString(36).slice(2, 6)}`,
                        timestamp: Date.now(),
                        messageId: message.id,
                        author: senderAddress,
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

                    try {
                        // Iterate over all pages of messages (headers)
                        for await (const message of iterateMessagePages(msgList)) {
                            // see message header https://webextension-api.thunderbird.net/en/mv3/messages.html#messageheader
                            console.log(`Validating ${message.author}:[${message.subject}] (messageID: ${message.id}...)`);
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

                        try {
                        const senderAddress = message.author;
                        const domain = await extractDomainFromAuthor(senderAddress);
                        if (!domain) {
                            console.warn(`Could not extract domain from sender address: ${senderAddress}`);
                            continue;
                        }
                        /**
                         * Scans all messages in a given folder (triggered via context menu, popup, or options page)
                         * @param {object} folder MailFolder object or folderId string
                         * @param {string} source label for diagnostic log
                         */
                        async function scanFolder(folder, source = 'folder-scan') {
                            if (!folder) {
                                return { processed: 0, spamCount: 0 };
                            }

                            // Use getHeaders() instead of getFull() to avoid parsing the full MIME body
                            const headers = messenger.messages.getHeaders
                                ? await messenger.messages.getHeaders(message.id)
                                : (await messenger.messages.getFull(message.id)).headers;
                            const dkimSig = headers ? headers['dkim-signature'] : null;
                            let folderObj = folder;
                            if (typeof folder === 'string' && messenger.folders && messenger.folders.get) {
                                try {
                                    folderObj = await messenger.folders.get(folder);
                                } catch {
                                    folderObj = { id: folder, name: folder };
                                }
                            }

                            // Führen Sie hier die Validierungsprüfungen durch
                            const score = await validateDomain(domain, dkimSig);
                            console.log(`Validation score for ${domain} (messageID: ${message.id}): ${score}`);
                            const folderId = typeof folderObj === 'object' ? (folderObj.id || folderObj) : folderObj;
                            const msgList = await messenger.messages.list(folderId);
                            return await scanMessageList(msgList, folderObj, source);
                        }

                        if (score < -50) {
                            console.log(`[SPAM] Marking message from ${message.author} (score: ${score}) as Junk and moving to Spam folder.`);
                            await markAndMoveToSpam(message, folder);
                        }
                    } catch (error) {
                        console.error(`ERROR Validating ${message.author}:[${message.subject}] (messageID: ${message.id}...):`, error);
                    }
                }
                } catch (ex) {
                console.error('ERROR failed to iterate over messages:', ex);
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

                g_SCAN_STATE = {
                    running: true,
                    sourceName: folder && folder.name ? folder.name : 'Auswahl',
                    processed: 0,
                    total: allMessages.length,
                    spamCount: 0,
                    startedAt: Date.now()
                };
                notifyUI({ type: 'SCAN_PROGRESS', scanState: g_SCAN_STATE });

                try {
                    for (const message of allMessages) {
                        const res = await evaluateAndProcessMessage(message, folder || message.folder, settings, source);
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
                    return {
                        processed: g_SCAN_STATE.processed,
                        spamCount: g_SCAN_STATE.spamCount,
                        total: g_SCAN_STATE.total
                    };
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
             * Extracts the sender domain using Thunderbird's RFC 5322 parser (messengerUtilities.parseMailboxString)
             * with a fallback to manual string parsing.
             * @param {string} senderAddress 
             * @returns {Promise<string|null>}
             */
                async function extractDomainFromAuthor(senderAddress) {
                    if (!senderAddress || typeof senderAddress !== 'string') {
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
                    return getDomainFromAddress(senderAddress);
                }

                /**
                 * Parses the given sender address and returns just the domain
                 * @param {string} senderAddress 
                 */
                function getDomainFromAddress(senderAddress) {
                    if (!senderAddress || typeof senderAddress !== 'string') {
                        return null;
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
                        // Falls eine Adresse in spitzen Klammern steht (z.B. "Name <user@domain.tld>"), extrahiere den Teil darin
                        const angleMatch = senderAddress.match(/<([^<>]+)>/);
                        const addressPart = angleMatch ? angleMatch[1] : senderAddress;

                        const atIndex = addressPart.lastIndexOf('@');
                        if (atIndex === -1) {
                            return null;
                        }
                        const atIndex = addressPart.lastIndexOf('@');
                        if (atIndex === -1) {
                            return null;
                        }

                        let domain = addressPart.slice(atIndex + 1).trim();
                        // Entfernt eventuelle Restzeichen wie ">", Anführungszeichen oder Leerzeichen
                        domain = domain.replace(/[>"'\s]+$/g, '').toLowerCase();
                        let domain = addressPart.slice(atIndex + 1).trim();
                        // Entfernt eventuelle Restzeichen wie ">", Anführungszeichen oder Leerzeichen
                        domain = domain.replace(/[>"'\s]+$/g, '').toLowerCase();

                        return domain || null;
                    }
                    return domain || null;
                }

                /**
                 * Validate the given domain, of its existence, by the SPF record and the DKIM signature of the EMAIL header.
                 * It will return a score based on the criticality of its checks. A negative score means that it fails some checks.
                 * @param {string} domain the domain read from the original (sender) address
                 * @param {string[]} dkimSig the DKIM signature read from the email header "message.headers['dkim-signature']"
                 * @returns {Promise<number>} the score of the validation. If the domain does not exist it returns a score of -100. The lower the score the more checks have been failed.
                 */
                async function validateDomain(domain, dkimSig) {
                    // Perform A and MX record lookups in parallel
                    const [aRecordData, mxRecordData] = await Promise.all([
                        getDNSEntry(domain, 'A', true),
                        getDNSEntry(domain, 'MX', true)
                    ]);
                    /**
                     * Validates a domain and returns both the total score and a detailed breakdown of each check.
                     * @param {string} domain the sender domain
                     * @param {string[]|null} dkimSig the dkim-signature header array
                     * @param {object} [customSettings] optional settings object (loaded from storage if omitted)
                     * @returns {Promise<{ score: number, isSpam: boolean, checks: object }>}
                     */
                    async function validateDomainDetailed(domain, dkimSig, customSettings = null) {
                        const settings = customSettings || await getSettings();
                        const cfg = settings.checks || DEFAULT_SETTINGS.checks;
                        const checks = {};
                        let score = 0;

                        // Status === 3 means NXDOMAIN (domain does not exist at all in DNS)
                        const isNxDomain = (aRecordData && aRecordData.Status === 3) || (mxRecordData && mxRecordData.Status === 3);
                        const hasARecord = Boolean(aRecordData && aRecordData.Status === 0 && Array.isArray(aRecordData.Answer) && aRecordData.Answer.length > 0);
                        const hasMXRecord = Boolean(mxRecordData && mxRecordData.Status === 0 && Array.isArray(mxRecordData.Answer) && mxRecordData.Answer.length > 0);
                        // Perform A and MX record lookups in parallel
                        const [aRecordData, mxRecordData] = await Promise.all([
                            getDNSEntry(domain, 'A', true),
                            getDNSEntry(domain, 'MX', true)
                        ]);

                        // If neither A nor MX exists, also check AAAA before declaring the domain dead
                        if (isNxDomain || (!hasARecord && !hasMXRecord)) {
                            const aaaaRecordData = isNxDomain ? null : await getDNSEntry(domain, 'AAAA', true);
                            const hasAAAARecord = Boolean(aaaaRecordData && aaaaRecordData.Status === 0 && Array.isArray(aaaaRecordData.Answer) && aaaaRecordData.Answer.length > 0);
                            const isNxDomain = (aRecordData && aRecordData.Status === 3) || (mxRecordData && mxRecordData.Status === 3);
                            const hasARecord = Boolean(aRecordData && aRecordData.Status === 0 && Array.isArray(aRecordData.Answer) && aRecordData.Answer.length > 0);
                            const hasMXRecord = Boolean(mxRecordData && mxRecordData.Status === 0 && Array.isArray(mxRecordData.Answer) && mxRecordData.Answer.length > 0);

                            if (isNxDomain || !hasAAAARecord) {
                                console.log('The domain has no A/AAAA/MX record or does not exist:', domain);
                                return -100;
                            }
                        }
                        let hasAAAARecord = false;
                        if (!isNxDomain && !hasARecord && !hasMXRecord) {
                            const aaaaRecordData = await getDNSEntry(domain, 'AAAA', true);
                            hasAAAARecord = Boolean(aaaaRecordData && aaaaRecordData.Status === 0 && Array.isArray(aaaaRecordData.Answer) && aaaaRecordData.Answer.length > 0);
                        }

                        let score = 0;
                        const domainExists = !isNxDomain && (hasARecord || hasMXRecord || hasAAAARecord);

                        // Check DNSSEC from the already fetched A or MX response
                        const hasDNSSEC = Boolean((aRecordData && aRecordData.AD === true) || (mxRecordData && mxRecordData.AD === true));
                        if (!hasDNSSEC) {
                            console.log('The domain has no valid DNSSEC signature:', domain);
                            score -= 10;
                        }
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

                            // Check if the domain has an MX record
                            if (!hasMXRecord) {
                                console.log('The domain has no MX record:', domain);
                                score -= 20;
                            }
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

                        // Check the SPF record
                        const spfRecord = await getSPFRecord(domain);
                        if (spfRecord == null) {
                            console.log('Invalid/NO SPF record for the domain:', domain);
                            score -= 50;
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

                        // Check the DKIM record
                        const dkimInfo = getDKIMInfo(dkimSig);
                        if (!dkimInfo || !dkimInfo.selector) {
                            console.log('Missing DKIM signature or selector for the domain:', domain);
                            score -= 20;
                        } else {
                            const dkimDomain = dkimInfo.domain || domain;
                            const dkimRecord = await getDKIMRecord(dkimDomain, dkimInfo.selector);
                            if (dkimRecord == null) {
                                console.log('Invalid/NO DKIM record for the domain:', dkimDomain);
                                score -= 20;
                            }
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

                        return score;
                    }
                    // 4. SPF record check
                    if (cfg.spf && cfg.spf.enabled) {
                        const spfRecord = await getSPFRecord(domain);
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

                        // Filtern Sie nach SPF-Einträgen (z.B. "v=spf1 ...")
                        const spfRecord = data.Answer.find(rec => {
                            if (typeof rec.data !== 'string') return false;
                            const recordData = rec.data.replace(/"/g, '').trim();
                            return recordData.toLowerCase().startsWith('v=spf1');
                        });
                        return {
                            score,
                            isSpam: score < settings.spamThreshold,
                            checks
                        };
                    }

                    return spfRecord ? spfRecord.data : null;
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
                 * Reads the DKIM record via cloudflare (DoH service) and returns it, or null if the entry could not be found.
                 * @param {string} domain the domain to check
                 * @param {string} selector DKIM selector read from the Email header ([Selektor]._domainkey.[Domäne])
                 * @returns {Promise<object|null>}
                 */
                async function getDKIMRecord(domain, selector) {
                    if (!domain || !selector) {
                        return null;
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

                        // Der DoH-Endpunkt und die spezifische DNS-Anfrage für den DKIM-Eintrag.
                        const query = `${selector}._domainkey.${domain}`;
                        const data = await getDNSEntry(query, 'TXT');
                        // Filtern Sie nach SPF-Einträgen (z.B. "v=spf1 ...")
                        const spfRecord = data.Answer.find(rec => {
                            if (typeof rec.data !== 'string') return false;
                            const recordData = rec.data.replace(/"/g, '').trim();
                            return recordData.toLowerCase().startsWith('v=spf1');
                        });

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
                        return spfRecord ? spfRecord.data : null;
                    }

                    console.log(`Kein DKIM-Eintrag gefunden für: ${query}`);
                    return null;
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
                        // Der DoH-Endpunkt und die spezifische DNS-Anfrage für den DKIM-Eintrag.
                        const query = `${selector}._domainkey.${domain}`;
                        const data = await getDNSEntry(query, 'TXT');

                        const dkimHeaderString = dkimHeaders[0];
                        const parts = dkimHeaderString.split(';');
                        let selector = null;
                        let domain = null;
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

                        for (const part of parts) {
                            const trimmedPart = part.replace(/\s+/g, '');
                            if (trimmedPart.startsWith('s=')) {
                                selector = trimmedPart.substring(2);
                            } else if (trimmedPart.startsWith('d=')) {
                                domain = trimmedPart.substring(2).toLowerCase();
                            }
                        }
                        console.log(`Kein DKIM-Eintrag gefunden für: ${query}`);
                        return null;
                    }

                    if (!selector) {
                        console.log('Kein Selektor im ersten DKIM-Header gefunden.', dkimHeaderString);
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

                        return { selector, domain };
                    }
                    const dkimHeaderString = dkimHeaders[0];
                    const parts = dkimHeaderString.split(';');
                    let selector = null;
                    let domain = null;

                    /**
                     * Read the DKIM selector part from the first DKIM header and return it.
                     * @param {string[]} dkimHeaders usually the result from the message.headers['dkim-signature'];
                     * @returns {string|null} the found DKIM selector or null
                     */
                    function getDKIMSelector(dkimHeaders) {
                        const info = getDKIMInfo(dkimHeaders);
                        return info ? info.selector : null;
                    }
                    for (const part of parts) {
                        const trimmedPart = part.replace(/\s+/g, '');
                        if (trimmedPart.startsWith('s=')) {
                            selector = trimmedPart.substring(2);
                        } else if (trimmedPart.startsWith('d=')) {
                            domain = trimmedPart.substring(2).toLowerCase();
                        }
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
                    if (!selector) {
                        console.log('Kein Selektor im ersten DKIM-Header gefunden.', dkimHeaderString);
                        return null;
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
                    return { selector, domain };
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
                 * Read the DKIM selector part from the first DKIM header and return it.
                 * @param {string[]} dkimHeaders usually the result from the message.headers['dkim-signature'];
                 * @returns {string|null} the found DKIM selector or null
                 */
                function getDKIMSelector(dkimHeaders) {
                    const info = getDKIMInfo(dkimHeaders);
                    return info ? info.selector : null;
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
                    /**
                     * Checks if the given domain has a matching A record
                     * @param {string} domain the domain of which to read the A record from
                     * @returns {Promise<boolean>}
                     */
                    async function doesDomainExist(domain) {
                        const answer = await getDNSEntry(domain, 'A');
                        return (answer != null);
                    }

                    const cacheKey = `${domain.toLowerCase()}:${type.toUpperCase()}`;
                    const now = Date.now();
                    const cached = g_DNS_CACHE.get(cacheKey);
                    /**
                     * Checks if the given domain has a matching A record and DNSSEC-Signature
                     * @param {string} domain the domain of which to read the A record from
                     * @returns {Promise<boolean>}
                     */
                    async function hasValidDNSSEC(domain) {
                        const answer = await getDNSEntry(domain, 'A');
                        return (answer != null && answer.AD === true);
                    }

                    let data = null;
                    if (cached && (now - cached.timestamp) < g_DNS_CACHE_TTL_MS) {
                        data = cached.data;
                    } else {
                        const url = `${g_DOH_SERVICE_URL}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
                        const headers = { 'accept': 'application/dns-json' };
                        /**
                         * Checks if the given domain has a matching MX record
                         * @param {string} domain the domain of which to read the MX record from
                         * @returns {Promise<boolean>}
                         */
                        async function hasDomainMXRecord(domain) {
                            const answer = await getDNSEntry(domain, 'MX');
                            return answer != null;
                        }

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

                        if (returnRawStatus) {
                            return data;
                        }
                        const cacheKey = `${domain.toLowerCase()}:${type.toUpperCase()}`;
                        const now = Date.now();
                        const cached = g_DNS_CACHE.get(cacheKey);

                        // Wenn die "Answer"-Sektion leer ist, hat die Domäne keinen entsprechenden Record.
                        if (!data || data.Status !== 0 || !Array.isArray(data.Answer) || data.Answer.length === 0) {
                            console.warn(`Domäne '${domain}' scheint nicht zu existieren oder hat keinen ${type}-Record.`);
                            return null;
                        }
                        let data = null;
                        if (cached && (now - cached.timestamp) < g_DNS_CACHE_TTL_MS) {
                            data = cached.data;
                        } else {
                            const url = `${g_DOH_SERVICE_URL}?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`;
                            const headers = { 'accept': 'application/dns-json' };

                            return data; // Es wurden DNS-Einträge gefunden.
                        }
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
                        if (returnRawStatus) {
                            return data;
                        }

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
                            return;
                        }

                        switch (request.action) {
                            case 'GET_STATE': {
                                const settings = await getSettings();
                                const logData = messenger.storage ? await messenger.storage.local.get('diagnosticLog') : {};
                                return {
                                    settings,
                                    defaultSettings: DEFAULT_SETTINGS,
                                    diagnosticLog: Array.isArray(logData.diagnosticLog) ? logData.diagnosticLog : [],
                                    scanState: g_SCAN_STATE,
                                    cacheSize: g_DNS_CACHE.size
                                };
                            }

                            case 'SAVE_SETTINGS': {
                                const current = await getSettings();
                                const nextSettings = Object.assign({}, current, request.settings || {});
                                await messenger.storage.local.set({ settings: nextSettings });
                                return { success: true, settings: nextSettings };
                            }

                            case 'RESET_SETTINGS': {
                                const defaults = structuredClone(DEFAULT_SETTINGS);
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
                                return { success: true, cacheSize: 0 };
                            }

                            case 'GET_ALL_FOLDERS': {
                                const folders = await getAllFoldersList();
                                return { folders };
                            }

                            case 'SCAN_ACTIVE_FOLDER': {
                                if (!messenger.mailTabs) {
                                    throw new Error('mailTabs API nicht verfügbar.');
                                }
                                const tabs = await messenger.mailTabs.query({ active: true, currentWindow: true });
                                const activeTab = tabs && tabs.length > 0 ? tabs[0] : await messenger.mailTabs.getCurrent();
                                if (!activeTab || !activeTab.displayedFolder) {
                                    throw new Error('Kein aktiver Ordner in Thunderbird ausgewählt.');
                                }
                                return await scanFolder(activeTab.displayedFolder, 'folder-scan');
                            }

                            case 'SCAN_SELECTED_MESSAGES': {
                                if (!messenger.mailTabs) {
                                    throw new Error('mailTabs API nicht verfügbar.');
                                }
                                const msgList = await messenger.mailTabs.getSelectedMessages();
                                if (!msgList || !msgList.messages || msgList.messages.length === 0) {
                                    throw new Error('Keine E-Mails in der aktuellen Ansicht ausgewählt.');
                                }
                                return await scanMessageList(msgList, null, 'selected-messages');
                            }

                            case 'SCAN_FOLDER_BY_ID': {
                                if (!request.folderId) {
                                    throw new Error('Keine Ordner-ID angegeben.');
                                }
                                const allFolders = await getAllFoldersList();
                                const found = allFolders.find(f => f.id === request.folderId) || { id: request.folderId, name: request.folderName || request.folderId };
                                return await scanFolder(found, 'folder-scan');
                            }

                            case 'TEST_DOMAIN': {
                                const rawInput = (request.input || '').trim();
                                const domain = rawInput.includes('@') ? await extractDomainFromAuthor(rawInput) : rawInput.toLowerCase();
                                if (!domain) {
                                    throw new Error('Bitte eine gültige Domain oder E-Mail-Adresse eingeben.');
                                }
                                const dkimHeaders = request.dkimHeader ? [request.dkimHeader] : null;
                                const result = await validateDomainDetailed(domain, dkimHeaders);
                                return { domain, ...result };
                            }

                            default:
                                return null;
                        }
                    });
                }