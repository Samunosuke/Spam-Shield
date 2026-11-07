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
 * Folder types that should be ignored when monitoring all folders
 */
const g_IGNORED_FOLDER_TYPES = new Set(['junk', 'trash', 'sent', 'drafts', 'templates', 'outbox', 'archives']);

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
 * Handles all incoming messages
 * @param {*} folder the folder where the messages belong to
 * @param {*} msgList the list of message headers (see https://webextension-api.thunderbird.net/en/mv3/messages.html#messagelist)
 */
    async function handleMessages(folder, msgList) {
        // Ignore messages arriving directly in Junk, Trash, Sent, Drafts, etc.
        if (folder && Array.isArray(folder.specialUse)) {
            if (folder.specialUse.some(use => g_IGNORED_FOLDER_TYPES.has(use))) {
                console.log(`Skipping folder ${folder.name} (specialUse: ${folder.specialUse.join(', ')})`);
                return;
            }
        }

                console.log(`Handling incoming messages in folder: ${folder ? folder.name : 'unknown'}`);

                try {
                    // Iterate over all pages of messages (headers)
                    for await (const message of iterateMessagePages(msgList)) {
                        // see message header https://webextension-api.thunderbird.net/en/mv3/messages.html#messageheader
                        console.log(`Validating ${message.author}:[${message.subject}] (messageID: ${message.id}...)`);

                        try {
                            const senderAddress = message.author;
                            const domain = await extractDomainFromAuthor(senderAddress);
                            if (!domain) {
                                console.warn(`Could not extract domain from sender address: ${senderAddress}`);
                                continue;
                            }

                            // Use getHeaders() instead of getFull() to avoid parsing the full MIME body
                            const headers = messenger.messages.getHeaders
                                ? await messenger.messages.getHeaders(message.id)
                                : (await messenger.messages.getFull(message.id)).headers;
                            const dkimSig = headers ? headers['dkim-signature'] : null;

                            // Führen Sie hier die Validierungsprüfungen durch
                            const score = await validateDomain(domain, dkimSig);
                            console.log(`Validation score for ${domain} (messageID: ${message.id}): ${score}`);

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
                         * Parses the given sender address and returns just the domain
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

                                // Status === 3 means NXDOMAIN (domain does not exist at all in DNS)
                                const isNxDomain = (aRecordData && aRecordData.Status === 3) || (mxRecordData && mxRecordData.Status === 3);
                                const hasARecord = Boolean(aRecordData && aRecordData.Status === 0 && Array.isArray(aRecordData.Answer) && aRecordData.Answer.length > 0);
                                const hasMXRecord = Boolean(mxRecordData && mxRecordData.Status === 0 && Array.isArray(mxRecordData.Answer) && mxRecordData.Answer.length > 0);

                                // If neither A nor MX exists, also check AAAA before declaring the domain dead
                                if (isNxDomain || (!hasARecord && !hasMXRecord)) {
                                    const aaaaRecordData = isNxDomain ? null : await getDNSEntry(domain, 'AAAA', true);
                                    const hasAAAARecord = Boolean(aaaaRecordData && aaaaRecordData.Status === 0 && Array.isArray(aaaaRecordData.Answer) && aaaaRecordData.Answer.length > 0);

                                    if (isNxDomain || !hasAAAARecord) {
                                        console.log('The domain has no A/AAAA/MX record or does not exist:', domain);
                                        return -100;
                                    }
                                }

                                let score = 0;

                                // Check DNSSEC from the already fetched A or MX response
                                const hasDNSSEC = Boolean((aRecordData && aRecordData.AD === true) || (mxRecordData && mxRecordData.AD === true));
                                if (!hasDNSSEC) {
                                    console.log('The domain has no valid DNSSEC signature:', domain);
                                    score -= 10;
                                }

                                // Check if the domain has an MX record
                                if (!hasMXRecord) {
                                    console.log('The domain has no MX record:', domain);
                                    score -= 20;
                                }

                                // Check the SPF record
                                const spfRecord = await getSPFRecord(domain);
                                if (spfRecord == null) {
                                    console.log('Invalid/NO SPF record for the domain:', domain);
                                    score -= 50;
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

                                    return score;
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