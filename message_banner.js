/**
 * Content script injected into Thunderbird's displayed message body (MV3 scripting.messageDisplay).
 * Renders an isolated Shadow DOM header banner showing Spam Shield check badges, score status,
 * quick Whitelist/Blacklist buttons, and a manual "Check" trigger for unscanned emails.
 */
(() => {
    const HOST_ID = 'spam-shield-banner-host';
    const api = (typeof messenger !== 'undefined') ? messenger : browser;

    // Prevent duplicate injection in the same message document
    if (document.getElementById(HOST_ID)) {
        return;
    }

    /** Shadow root reference once mounted */
    let shadowRoot = null;
    /** Cached payload from background.js for re-renders */
    let currentState = null;
    /** Cached CSS string loaded from message_banner.css via background.js */
    let cachedCss = '';
    /** Guard to avoid overlapping evaluations for the same displayed document */
    let isEvaluating = false;

    /**
     * Ensures the Shadow DOM host exists and is attached as the first child of document.body.
     * @returns {ShadowRoot|null}
     */
    function ensureHostMounted() {
        if (!document.body) {
            return null;
        }
        let host = document.getElementById(HOST_ID);
        if (!host) {
            host = document.createElement('div');
            host.id = HOST_ID;
            document.body.prepend(host);
            shadowRoot = host.attachShadow({ mode: 'open' });
        } else if (!shadowRoot) {
            shadowRoot = host.shadowRoot;
        }
        return shadowRoot;
    }

    /**
     * Removes the banner host from the document (used when banner display is disabled in settings).
     */
    function unmountBanner() {
        const host = document.getElementById(HOST_ID);
        if (host) {
            host.remove();
        }
        shadowRoot = null;
    }

    /**
     * Builds the primary status & score pill element (e.g. OK (0), SPAM (-110), Checking…).
     * @param {object|null} evaluation Evaluation record for the displayed email
     * @param {object} strings Localized UI labels
     * @returns {HTMLSpanElement}
     */
    function buildStatusBadge(evaluation, strings) {
        const badge = document.createElement('span');
        if (isEvaluating) {
            badge.className = 'ss-status-badge unchecked';
            badge.textContent = `🛡️ ${strings.checking || 'Checking…'}`;
            return badge;
        }
        if (!evaluation) {
            badge.className = 'ss-status-badge unchecked';
            badge.textContent = `🛡️ ${strings.unchecked || 'Not yet checked'}`;
            return badge;
        }
        if (evaluation.whitelisted) {
            badge.className = 'ss-status-badge wl';
            badge.textContent = `🛡️ ${strings.badgeWl || 'WHITELIST'} (0)`;
            return badge;
        }
        if (evaluation.isSpam) {
            const isDry = evaluation.actionTaken === 'dry-run';
            badge.className = `ss-status-badge ${isDry ? 'dryrun' : 'spam'}`;
            const label = isDry ? (strings.badgeDryrun || 'DRY-RUN') : (strings.badgeSpam || 'SPAM');
            badge.textContent = `🛡️ ${label} (${evaluation.score})`;
            return badge;
        }
        badge.className = 'ss-status-badge ok';
        badge.textContent = `🛡️ ${strings.badgeOk || 'OK'} (${evaluation.score})`;
        return badge;
    }

    /**
     * Builds the manual "Check" button for unscanned emails or a compact "Re-check" button otherwise.
     * @param {object|null} evaluation Evaluation record
     * @param {object} strings Localized UI labels
     * @returns {HTMLButtonElement|null}
     */
    function buildCheckTriggerButton(evaluation, strings) {
        if (isEvaluating) {
            return null;
        }
        const btn = document.createElement('button');
        btn.type = 'button';
        if (!evaluation) {
            btn.className = 'ss-btn primary';
            btn.textContent = strings.checkNow || '🛡️ Check';
            btn.title = strings.checkNowTitle || 'Evaluate this email now';
        } else {
            btn.className = 'ss-btn';
            btn.textContent = '↻';
            btn.title = strings.recheckTitle || 'Re-evaluate email';
        }
        btn.addEventListener('click', () => triggerEvaluation());
        return btn;
    }

    /**
     * Sends a quick Whitelist/Blacklist rule addition from the banner to background.js and re-renders.
     * @param {string} label Button text
     * @param {string} cls CSS modifier ('wl' | 'bl')
     * @param {string} listType Target rule list ('whitelist' | 'blacklist')
     * @param {string} pattern Email or wildcard domain pattern
     * @param {string} title Hover tooltip text
     * @returns {HTMLButtonElement}
     */
    function createRuleActionButton(label, cls, listType, pattern, title) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `ss-btn ${cls}`;
        btn.textContent = label;
        btn.title = title;
        btn.disabled = isEvaluating;
        btn.addEventListener('click', async () => {
            btn.disabled = true;
            try {
                const res = await api.runtime.sendMessage({
                    action: 'HEADER_RULE_ACTION',
                    listType,
                    pattern
                });
                if (res && !res.error) {
                    renderBanner(res);
                } else if (res && res.error) {
                    renderBanner(currentState, res.error);
                }
            } catch (err) {
                renderBanner(currentState, err && err.message ? err.message : String(err));
            }
        });
        return btn;
    }

    /**
     * Builds the container with quick Whitelist/Blacklist buttons for the sender address and domain.
     * @param {string} senderEmail Extracted sender email address
     * @param {string} domain Extracted sender domain
     * @param {object} strings Localized UI labels
     * @returns {HTMLDivElement|null}
     */
    function buildQuickActionsContainer(senderEmail, domain, strings) {
        if (!senderEmail && !domain) {
            return null;
        }
        const actions = document.createElement('div');
        actions.className = 'ss-actions';
        const domPattern = domain ? `*.${domain}` : '';

        const buttonSpecs = [
            {
                pattern: senderEmail,
                label: strings.btnWlMail || '+WL Mail',
                cls: 'wl',
                listType: 'whitelist',
                title: (strings.btnWlMailTitle || 'Whitelist {email}').replace('{email}', senderEmail)
            },
            {
                pattern: domPattern,
                label: strings.btnWlDom || '+WL *.Dom',
                cls: 'wl',
                listType: 'whitelist',
                title: (strings.btnWlDomTitle || 'Whitelist {pattern}').replace('{pattern}', domPattern)
            },
            {
                pattern: senderEmail,
                label: strings.btnBlMail || '⛔BL Mail',
                cls: 'bl',
                listType: 'blacklist',
                title: (strings.btnBlMailTitle || 'Blacklist {email}').replace('{email}', senderEmail)
            },
            {
                pattern: domPattern,
                label: strings.btnBlDom || '⛔BL *.Dom',
                cls: 'bl',
                listType: 'blacklist',
                title: (strings.btnBlDomTitle || 'Blacklist {pattern}').replace('{pattern}', domPattern)
            }
        ];

        for (const spec of buttonSpecs) {
            if (spec.pattern) {
                actions.appendChild(createRuleActionButton(spec.label, spec.cls, spec.listType, spec.pattern, spec.title));
            }
        }
        return actions;
    }

    /**
     * Builds the top row of the banner containing status, sender, check button, and rule actions.
     * @param {object|null} evaluation Evaluation record
     * @param {string} senderEmail Extracted sender email address
     * @param {string} domain Extracted sender domain
     * @param {object} strings Localized UI labels
     * @returns {HTMLDivElement}
     */
    function buildTopRow(evaluation, senderEmail, domain, strings) {
        const topRow = document.createElement('div');
        topRow.className = 'ss-row-top';

        const left = document.createElement('div');
        left.className = 'ss-left';
        left.appendChild(buildStatusBadge(evaluation, strings));

        if (senderEmail || domain) {
            const senderSpan = document.createElement('span');
            senderSpan.className = 'ss-sender';
            senderSpan.textContent = senderEmail || domain;
            senderSpan.title = senderEmail ? `${senderEmail} (${domain})` : domain;
            left.appendChild(senderSpan);
        }

        const checkBtn = buildCheckTriggerButton(evaluation, strings);
        if (checkBtn) {
            left.appendChild(checkBtn);
        }
        topRow.appendChild(left);

        const actions = buildQuickActionsContainer(senderEmail, domain, strings);
        if (actions) {
            topRow.appendChild(actions);
        }
        return topRow;
    }

    /**
     * Builds a single check pill badge (pass, fail with score delta, or disabled).
     * @param {string} label Short check label (e.g. 'DNS', 'DMARC')
     * @param {object} chk Individual check result object
     * @returns {HTMLSpanElement}
     */
    function buildCheckPill(label, chk) {
        const pill = document.createElement('span');
        const isEnabled = chk.enabled !== false;
        const cls = isEnabled ? (chk.passed ? 'pass' : 'fail') : 'off';
        const prefix = isEnabled ? '' : '– ';
        const scoreSuffix = (!chk.passed && chk.scoreDelta) ? ` (${chk.scoreDelta})` : '';
        pill.className = `ss-pill ${cls}`;
        pill.textContent = `${prefix}${label}${scoreSuffix}`;
        pill.title = `${label}: ${chk.info || ''}`;
        return pill;
    }

    /**
     * Builds the second banner row displaying either a Whitelist/Blacklist pill or all check pills.
     * @param {object|null} evaluation Evaluation record
     * @param {object} data Full payload from background.js (contains pillDefs)
     * @param {object} strings Localized UI labels
     * @returns {HTMLDivElement|null}
     */
    function buildBadgesRow(evaluation, data, strings) {
        if (!evaluation || !evaluation.checks || Object.keys(evaluation.checks).length === 0) {
            return null;
        }
        const badgesRow = document.createElement('div');
        badgesRow.className = 'ss-row-badges';
        const checks = evaluation.checks;

        if (checks.whitelist || checks.blacklist) {
            const isWl = Boolean(checks.whitelist);
            const matchChk = isWl ? checks.whitelist : checks.blacklist;
            const pill = document.createElement('span');
            pill.className = `ss-pill ${isWl ? 'pass' : 'fail'}`;
            pill.textContent = isWl
                ? `✓ ${strings.pillWhitelist || 'Whitelist'}`
                : `✗ ${strings.pillBlacklist || 'Blacklist'}`;
            pill.title = matchChk.info || '';
            badgesRow.appendChild(pill);
            return badgesRow;
        }

        const defaultOrder = [
            ['domainExists', 'DNS'],
            ['dnssec', 'DNSSEC'],
            ['mx', 'MX'],
            ['spf', 'SPF'],
            ['dkim', 'DKIM'],
            ['dmarc', 'DMARC'],
            ['domainAge', 'Age'],
            ['dnsbl', 'DNSBL'],
            ['spfIpMatch', 'SPF-IP'],
            ['spamKitFingerprint', 'Spam-Kit']
        ];
        const order = Array.isArray(data.pillDefs) ? data.pillDefs : defaultOrder;
        for (const [key, label] of order) {
            if (checks[key]) {
                badgesRow.appendChild(buildCheckPill(label, checks[key]));
            }
        }
        return badgesRow;
    }

    /**
     * Renders the banner inside the Shadow DOM based on the latest evaluation payload.
     * @param {object} data Response from GET_DISPLAYED_EVALUATION / EVALUATE_DISPLAYED_MESSAGE
     * @param {string|null} [errorMsg] Optional inline error message
     */
    function renderBanner(data, errorMsg = null) {
        if (!data || data.showMessageBanner === false) {
            unmountBanner();
            return;
        }
        const root = ensureHostMounted();
        if (!root) {
            return;
        }
        currentState = data;
        if (typeof data.bannerCss === 'string' && data.bannerCss.length > 0) {
            cachedCss = data.bannerCss;
        }

        const strings = data.strings || {};
        const evaluation = data.evaluation || null;
        const emailInfo = data.emailInfo || {};
        const senderEmail = (evaluation && evaluation.senderEmail) || emailInfo.senderEmail || '';
        const domain = (evaluation && evaluation.domain) || emailInfo.domain || '';

        const styleEl = document.createElement('style');
        styleEl.textContent = cachedCss;

        const card = document.createElement('div');
        card.className = 'ss-card';
        card.appendChild(buildTopRow(evaluation, senderEmail, domain, strings));

        const badgesRow = buildBadgesRow(evaluation, data, strings);
        if (badgesRow) {
            card.appendChild(badgesRow);
        }

        if (errorMsg) {
            const errEl = document.createElement('div');
            errEl.className = 'ss-err';
            errEl.textContent = errorMsg;
            card.appendChild(errEl);
        }

        root.replaceChildren(styleEl, card);
    }

    /**
     * Triggers an on-demand evaluation of the displayed message in background.js
     * and updates the banner with the resulting checks and score.
     */
    async function triggerEvaluation() {
        if (isEvaluating) return;
        isEvaluating = true;
        if (currentState) {
            renderBanner(currentState);
        }
        try {
            const res = await api.runtime.sendMessage({ action: 'EVALUATE_DISPLAYED_MESSAGE' });
            isEvaluating = false;
            if (res && !res.error) {
                renderBanner(res);
            } else {
                renderBanner(currentState, res && res.error ? res.error : 'Evaluation failed');
            }
        } catch (err) {
            isEvaluating = false;
            renderBanner(currentState, err && err.message ? err.message : String(err));
        }
    }

    /**
     * Loads the initial evaluation state for the currently displayed message.
     * Automatically triggers an evaluation if `autoCheckOnDisplay` is enabled and no cached result exists.
     */
    async function initBanner() {
        try {
            const res = await api.runtime.sendMessage({ action: 'GET_DISPLAYED_EVALUATION' });
            if (!res || res.error || res.showMessageBanner === false) {
                unmountBanner();
                return;
            }
            currentState = res;
            if (res.evaluation) {
                isEvaluating = false;
                renderBanner(res);
            } else if (res.autoCheckOnDisplay) {
                await triggerEvaluation();
            } else {
                renderBanner(res);
            }
        } catch (err) {
            console.warn('Spam Shield banner init error:', err);
        }
    }

    // Listen for live updates pushed from background.js (e.g. rule changes or folder scan completion)
    if (api.runtime && api.runtime.onMessage) {
        api.runtime.onMessage.addListener((msg) => {
            if (msg && msg.type === 'BANNER_REFRESH') {
                initBanner();
            }
        });
    }

    if (document.body) {
        initBanner();
    } else {
        document.addEventListener('DOMContentLoaded', initBanner, { once: true });
    }
})();

