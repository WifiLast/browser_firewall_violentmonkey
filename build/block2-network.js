    /* -------------------------------------------------------------------- */
    /*  Watch-tag matching                                                   */
    /* -------------------------------------------------------------------- */
    // Build a haystack from everything we can see about a request. NOT
    // lowercased here — deep-scan decoders (base64/hex) are case-sensitive,
    // so matchTag lowercases per-view instead.
    // True when `url` resolves to the same origin as the page (first-party).
    function isSameOrigin(url) {
        try { return new URL(url, location.href).origin === location.origin; } catch (e) { return false; }
    }

    function buildHaystack(url, body, headerStr) {
        var s = String(url || '');
        if (body != null) {
            try { s += ' ' + (typeof body === 'string' ? body : JSON.stringify(body)); }
            catch (e) { s += ' ' + String(body); }
        }
        if (headerStr) s += ' ' + headerStr;
        try { s += ' ' + document.cookie; } catch (e) { }   // cookies sent with the request
        return s;
    }

    /* --- Deep scan: reveal watch-tags hidden behind common encodings --- */
    var DEEPSCAN_MAX = 200000;   // don't decode absurdly large payloads

    // Decode \uXXXX and \xXX escape sequences.
    function decodeEscapes(s) {
        return s.replace(/\\u([0-9a-fA-F]{4})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); })
                .replace(/\\x([0-9a-fA-F]{2})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); });
    }
    // Decode HTML numeric + a few common named entities.
    function decodeEntities(s) {
        return s.replace(/&#x([0-9a-fA-F]+);/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); })
                .replace(/&#(\d+);/g, function (_, d) { return String.fromCharCode(parseInt(d, 10)); })
                .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
                .replace(/&quot;/g, '"').replace(/&#0*39;/g, "'").replace(/&apos;/g, "'");
    }
    // Decode every base64-looking token (incl. url-safe) and concat readable text.
    function decodeBase64Tokens(s) {
        if (typeof atob !== 'function') return '';
        var out = '', re = /[A-Za-z0-9+/_-]{8,}={0,2}/g, m;
        while ((m = re.exec(s))) {
            var b = m[0].replace(/-/g, '+').replace(/_/g, '/');
            var pad = b.length % 4; if (pad) b += '===='.slice(pad);
            try {
                var dec = atob(b);
                if (/[\x20-\x7e]/.test(dec)) out += ' ' + dec;   // keep only text-ish results
            } catch (e) { }
        }
        return out;
    }
    // Decode long even-length hex runs to characters.
    function decodeHexRuns(s) {
        var out = '', re = /[0-9a-fA-F]{8,}/g, m;
        while ((m = re.exec(s))) {
            var h = m[0]; if (h.length % 2) continue;
            var t = '';
            for (var i = 0; i < h.length; i += 2) t += String.fromCharCode(parseInt(h.substr(i, 2), 16));
            if (/[\x20-\x7e]/.test(t)) out += ' ' + t;
        }
        return out;
    }
    // Strip separators / zero-width chars that split a tag apart ("s-e-s-s-i-o-n").
    function stripObf(s) { return s.replace(/[\s._\-*​-‏⁠﻿]/g, ''); }

    // Produce decoded/normalised views of the haystack, each labelled by how it
    // was revealed. Deduped by content (lowercased) so we never scan the same
    // text twice. The plain view is handled separately in matchTag (fast path).
    function decodedViews(raw) {
        raw = String(raw);
        if (raw.length > DEEPSCAN_MAX) raw = raw.slice(0, DEEPSCAN_MAX);
        var views = [], seen = {};
        function add(via, text) {
            if (text == null) return;
            text = String(text);
            if (!text || text.length > DEEPSCAN_MAX) return;
            var low = text.toLowerCase();
            if (seen[low]) return;
            seen[low] = 1;
            views.push({ via: via, text: low });
        }
        var url1 = raw;
        try { url1 = decodeURIComponent(raw.replace(/\+/g, ' ')); add('url-decoded', url1); } catch (e) { url1 = raw; }
        try { add('doubly url-decoded', decodeURIComponent(url1.replace(/\+/g, ' '))); } catch (e) { }
        add('escape-decoded', decodeEscapes(raw));
        add('entity-decoded', decodeEntities(raw));
        add('base64-decoded', decodeBase64Tokens(raw));
        add('hex-decoded', decodeHexRuns(raw));
        add('de-obfuscated', stripObf(raw));
        return views;
    }

    // Find the first watch-tag present in the request. Returns {tag, via} or
    // null. `via` is '' for a plain match, or a label describing where a hidden
    // tag was revealed (e.g. 'base64-decoded content').
    function matchTag(hay) {
        if (!TAGS.length) return null;
        var raw = String(hay), low = raw.toLowerCase(), i, t;
        // Fast path — plain substring match (original behaviour).
        for (i = 0; i < TAGS.length; i++) {
            t = String(TAGS[i]).trim();
            if (t && low.indexOf(t.toLowerCase()) !== -1) return { tag: t, via: '' };
        }
        if (!DEEPSCAN.enabled) return null;
        // Deep path — scan decoded / de-obfuscated variants.
        var views = decodedViews(raw);
        for (var v = 0; v < views.length; v++) {
            var view = views[v], deobf = view.via === 'de-obfuscated';
            for (i = 0; i < TAGS.length; i++) {
                t = String(TAGS[i]).trim(); if (!t) continue;
                var needle = deobf ? stripObf(t.toLowerCase()) : t.toLowerCase();
                if (needle && view.text.indexOf(needle) !== -1) return { tag: t, via: view.via + ' content' };
            }
        }
        return null;
    }
    function headersToStr(h) {
        if (!h) return '';
        try {
            if (typeof h.forEach === 'function') { var s = ''; h.forEach(function (v, k) { s += ' ' + k + ' ' + v; }); return s; }
            if (Array.isArray(h)) return h.map(function (p) { return p.join(' '); }).join(' ');
            return Object.keys(h).map(function (k) { return k + ' ' + h[k]; }).join(' ');
        } catch (e) { return ''; }
    }

    // Pick the body for a quietly-blocked request. Most blocked endpoints are
    // JSON APIs whose callers do JSON.parse() on the response — an empty string
    // makes that throw ("Unexpected end of JSON input") and can cascade into
    // page breakage. So default to valid empty JSON ('{}') and only fall back to
    // a bare empty string for resources that clearly are not JSON.
    function jsonSafeEmptyBody(responseType, headerStr, url) {
        if (responseType === 'document' || responseType === 'blob' || responseType === 'arraybuffer') return '';
        var u = String(url || '');
        if (/\.(js|mjs|css|html?|png|jpe?g|gif|svg|webp|woff2?|ttf|otf|eot|mp4|webm|mp3|xml|txt)(\?|#|$)/i.test(u)) return '';
        if (/text\/html|text\/css|text\/plain|javascript/i.test(String(headerStr || ''))) return '';
        return '{}';
    }

    function logReq(type, method, url, body, action, ruleName) {
        addLog({
            type: type, method: method || '', url: String(url), action: action,
            ruleName: ruleName || '', body: body != null ? String(body).slice(0, 500) : ''
        });
    }
    function alertLater(rule, type, method, url) {
        setTimeout(function () {
            alert('[Traffic Firewall] ALERT rule "' + (rule.name || rule.pattern) + '"\n\n' +
                type.toUpperCase() + ' ' + (method || '') + '\n' + url);
        }, 0);
    }

    // Classify a request. Returns { action, rule, ruleName } for an immediate
    // decision, or { needsPrompt:true, ctx } when the user must be asked.
    // `canPrompt` is false for callers that cannot wait for an async modal
    // (sendBeacon, WebSocket) — those fall back to the page decision or allow.
    function classify(type, method, url, body, headerStr, canPrompt) {
        // Anti-profiling: deny requests to extension URLs so pages can't probe
        // for installed extensions via their web-accessible resources.
        if (profileBlocksExt(url)) { logProfile('extension-probe', true); return { action: 'block', ruleName: 'anti-profiling (extension)' }; }

        // Explicit rules always win (except in disabled mode).
        if (MODE !== 'disabled') {
            var rule = findRule(type, method, url);
            if (rule) return { action: rule.action, rule: rule, ruleName: rule.name || rule.pattern };
        }

        // First-party traffic (same origin as the page) is trusted by default,
        // so the firewall only polices third-party requests and never blocks the
        // site's own functionality. Explicit rules above still win.
        if (FIRSTPARTY.enabled && isSameOrigin(url)) {
            return { action: 'allow', rule: null, ruleName: '(first-party)' };
        }

        var sig = connSignature(type, method, url);
        var m = TAGS.length ? matchTag(buildHaystack(url, body, headerStr)) : null;

        // A watch-tag match asks the user regardless of operating mode.
        if (m) {
            var tag = m.tag, viaLabel = m.via ? ' (' + m.via + ')' : '';
            // Honor a decision the user already persisted for this connection
            // (the allow/block rule saved when they last answered) so we never
            // re-ask after a reload — even in disabled mode, where the general
            // rule check at the top of classify() is skipped.
            var priorRule = findRule(type, method, url);
            if (priorRule) return { action: priorRule.action, rule: priorRule, ruleName: priorRule.name || priorRule.pattern };
            if (pageDecision) return { action: pageDecision, ruleName: 'tag:' + tag + viaLabel + ' (page)' };
            if (askedSigs[sig]) return { action: askedSigs[sig], ruleName: 'tag:' + tag + viaLabel };
            if (canPrompt) return { needsPrompt: true, ctx: { type: type, method: method, url: url, tag: tag, via: m.via, sig: sig } };
            return { action: pageDecision || 'allow', ruleName: 'tag:' + tag + viaLabel + ' (no-prompt)' };
        }

        if (MODE === 'disabled') return { action: 'allow', ruleName: '(disabled)' };

        if (MODE === 'learning') {
            if (!askedSigs[sig]) { askedSigs[sig] = true; rememberRule(type, url, 'allow', 'learned'); }
            return { action: 'allow', ruleName: 'learned' };
        }

        if (MODE === 'normal') {
            if (pageDecision) return { action: pageDecision, ruleName: '(page)' };
            if (askedSigs[sig]) return { action: askedSigs[sig], ruleName: 'asked' };
            if (canPrompt) return { needsPrompt: true, ctx: { type: type, method: method, url: url, tag: null, sig: sig } };
            return { action: pageDecision || 'allow', ruleName: '(no-prompt)' };
        }

        return { action: 'allow', ruleName: '' };
    }

    // Synchronous decision (beacon / websocket): never prompts.
    function decideSync(type, method, url, body, headerStr) {
        var c = classify(type, method, url, body, headerStr, false);
        logReq(type, method, url, body, c.action, c.ruleName);
        if (c.rule && c.rule.action === 'alert') alertLater(c.rule, type, method, url);
        return c;
    }

    // Asynchronous decision (fetch / XHR): may open the prompt modal.
    var pendingSig = {};   // sig -> Promise<action>, dedupes concurrent prompts
    function decideAsync(type, method, url, body, headerStr) {
        var c = classify(type, method, url, body, headerStr, true);
        if (!c.needsPrompt) {
            logReq(type, method, url, body, c.action, c.ruleName);
            if (c.rule && c.rule.action === 'alert') alertLater(c.rule, type, method, url);
            return Promise.resolve(c);
        }
        var sig = c.ctx.sig, tag = c.ctx.tag;
        if (!pendingSig[sig]) {
            pendingSig[sig] = promptUser(c.ctx).then(function (choice) {
                if (choice.all) pageDecision = choice.action;
                askedSigs[sig] = choice.action;
                rememberRule(type, url, choice.action, tag ? ('tag:' + tag) : 'asked');
                return choice.action;
            });
        }
        return pendingSig[sig].then(function (action) {
            logReq(type, method, url, body, action, tag ? ('tag:' + tag) : 'asked');
            return { action: action, rule: null };
        });
    }

    /* -------------------------------------------------------------------- */
    /*  Ask-the-user prompt modal (replaces native confirm)                  */
    /* -------------------------------------------------------------------- */
    var promptQueue = [];       // [{ ctx, resolve }]
    var promptActive = false;

    function promptUser(ctx) {
        return new Promise(function (resolve) {
            promptQueue.push({ ctx: ctx, resolve: resolve });
            if (!promptActive) nextPrompt();
        });
    }
    function nextPrompt() {
        // If the user already chose "apply to all", flush the queue silently.
        if (pageDecision) {
            while (promptQueue.length) promptQueue.shift().resolve({ action: pageDecision, all: false });
            promptActive = false;
            return;
        }
        if (!promptQueue.length) { promptActive = false; return; }
        promptActive = true;
        var item = promptQueue[0];
        showPromptModal(item.ctx, function (choice) {
            promptQueue.shift();
            if (choice.all) pageDecision = choice.action;
            item.resolve(choice);
            setTimeout(nextPrompt, 0);
        });
    }

    // Small DOM builder — avoids innerHTML entirely so it works even under the
    // strictest Trusted Types policies (where DOMParser is blocked too).
    function mk(tag, opts, children) {
        var e = document.createElement(tag);
        e.__fwUI = true;   // mark as firewall UI so a frozen page never blocks our own build
        opts = opts || {};
        if (opts.cls) e.className = opts.cls;
        if (opts.text != null) e.textContent = opts.text;
        if (opts.id) e.id = opts.id;
        if (opts.type) e.type = opts.type;
        if (opts.style) e.style.cssText = opts.style;
        (children || []).forEach(function (c) { if (c != null) e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
        return e;
    }

    function showPromptModal(ctx, done) {
        var ov = mk('div', { cls: 'fw-ask-ov' });
        ov.__fwUI = true;

        var reason = ctx.tag
            ? mk('div', { cls: 'fw-ask-reason' }, [
                ctx.via ? '⚠ Hidden watch-tag ' : 'Matched watch-tag ',
                mk('b', { text: ctx.tag }),
                ctx.via ? mk('span', { text: ' — revealed in ' + ctx.via }) : null
              ])
            : mk('div', { cls: 'fw-ask-reason', text: 'New connection (normal mode)' });

        var meta = mk('div', { cls: 'fw-ask-meta' }, [
            mk('span', { cls: 'fw-tag block', style: 'text-transform:uppercase', text: ctx.type }),
            ' ' + (ctx.method || 'GET')
        ]);

        var allCb = mk('input', { id: 'fw-ask-all', type: 'checkbox' });
        var allLabel = mk('label', { cls: 'fw-ask-all' }, [allCb, ' Apply to all following requests on this page']);

        var blockBtn = mk('button', { cls: 'fw-btn danger', text: 'Block' });
        var allowBtn = mk('button', { cls: 'fw-btn primary', text: 'Allow' });

        var card = mk('div', { cls: 'fw-ask' }, [
            mk('div', { cls: 'fw-ask-h', text: '🔥 Traffic Firewall — allow this request?' }),
            reason,
            meta,
            mk('div', { cls: 'fw-ask-url', text: String(ctx.url) }),
            allLabel,
            mk('div', { cls: 'fw-ask-btns' }, [blockBtn, allowBtn])
        ]);
        ov.appendChild(card);
        (document.body || document.documentElement).appendChild(ov);

        function finish(action) {
            var all = !!allCb.checked;
            try { ov.remove(); } catch (e) { }
            done({ action: action, all: all });
        }
        allowBtn.addEventListener('click', function () { finish('allow'); });
        blockBtn.addEventListener('click', function () { finish('block'); });
    }

    /* -------------------------------------------------------------------- */
    /*  XMLHttpRequest interception                                          */
    /* -------------------------------------------------------------------- */
    var NativeXHR = unsafeWindow.XMLHttpRequest;
    var xhrOpen = NativeXHR.prototype.open;
    var xhrSend = NativeXHR.prototype.send;
    var xhrSetHeader = NativeXHR.prototype.setRequestHeader;

    NativeXHR.prototype.open = function (method, url) {
        this.__fw = { method: method, url: url };
        return xhrOpen.apply(this, arguments);
    };

    NativeXHR.prototype.setRequestHeader = function (name, value) {
        if (!this.__fwHeaders) this.__fwHeaders = '';
        this.__fwHeaders += ' ' + name + ' ' + value;
        return xhrSetHeader.apply(this, arguments);
    };

    // Apply a resolved decision to an XHR. Deferred so it runs off the send call.
    function applyXhr(xhr, args, outcome) {
        if (outcome.action === 'block') {
            setTimeout(function () {
                if (BLOCK_STYLE === 'empty') {
                    // Deliver a benign empty 200 so the caller's success path runs quietly.
                    var body = jsonSafeEmptyBody(xhr.responseType, xhr.__fwHeaders, xhr.__fw && xhr.__fw.url);
                    // responseType 'json' hands back the parsed value on .response.
                    var resp = xhr.responseType === 'json'
                        ? (function () { try { return JSON.parse(body || '{}'); } catch (e) { return {}; } })()
                        : body;
                    try {
                        Object.defineProperty(xhr, 'readyState',   { value: 4, configurable: true });
                        Object.defineProperty(xhr, 'status',       { value: 200, configurable: true });
                        Object.defineProperty(xhr, 'responseText', { value: body, configurable: true });
                        Object.defineProperty(xhr, 'response',     { value: resp, configurable: true });
                    } catch (e) { }
                    if (typeof xhr.onreadystatechange === 'function') xhr.onreadystatechange();
                    xhr.dispatchEvent(new Event('readystatechange'));
                    xhr.dispatchEvent(new Event('load'));
                    xhr.dispatchEvent(new Event('loadend'));
                } else {
                    // Simulate a network error without touching the server.
                    try {
                        Object.defineProperty(xhr, 'readyState', { value: 4, configurable: true });
                        Object.defineProperty(xhr, 'status', { value: 0, configurable: true });
                    } catch (e) { }
                    if (typeof xhr.onreadystatechange === 'function') xhr.onreadystatechange();
                    xhr.dispatchEvent(new Event('error'));
                    xhr.dispatchEvent(new Event('loadend'));
                }
            }, 0);
            return;
        }

        if (outcome.action === 'replace' && outcome.rule) {
            var rule = outcome.rule;
            setTimeout(function () {
                var status = rule.replaceStatus || 200;
                var text = rule.replaceBody != null ? rule.replaceBody : '';
                try {
                    Object.defineProperty(xhr, 'readyState', { value: 4, configurable: true });
                    Object.defineProperty(xhr, 'status', { value: status, configurable: true });
                    Object.defineProperty(xhr, 'responseText', { value: text, configurable: true });
                    Object.defineProperty(xhr, 'response', { value: text, configurable: true });
                } catch (e) { }
                if (typeof xhr.onreadystatechange === 'function') xhr.onreadystatechange();
                xhr.dispatchEvent(new Event('readystatechange'));
                xhr.dispatchEvent(new Event('load'));
                xhr.dispatchEvent(new Event('loadend'));
            }, 0);
            return;
        }

        xhrSend.apply(xhr, args);
    }

    NativeXHR.prototype.send = function (body) {
        var info = this.__fw || {};
        var self = this, args = arguments;
        decideAsync('xhr', info.method, info.url, body, this.__fwHeaders).then(function (outcome) {
            applyXhr(self, args, outcome);
        });
    };

    /* -------------------------------------------------------------------- */
    /*  fetch interception                                                   */
    /* -------------------------------------------------------------------- */
    var nativeFetch = unsafeWindow.fetch;
    if (nativeFetch) {
        function applyFetch(outcome, thisArg, args, url, headerStr) {
            if (outcome.action === 'block') {
                if (BLOCK_STYLE === 'empty') {
                    // Resolve quietly with an empty body so the caller doesn't throw.
                    // Prefer valid empty JSON so response.json() doesn't reject.
                    var body = jsonSafeEmptyBody(null, headerStr, url);
                    var isJson = body === '{}';
                    return new Response(body, {
                        status: 200, statusText: 'OK',
                        headers: { 'Content-Type': isJson ? 'application/json' : 'text/plain' }
                    });
                }
                throw new TypeError('[Traffic Firewall] request blocked: ' + url);
            }
            if (outcome.action === 'replace' && outcome.rule) {
                var rule = outcome.rule;
                return new Response(rule.replaceBody != null ? rule.replaceBody : '', {
                    status: rule.replaceStatus || 200,
                    statusText: 'OK',
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            return nativeFetch.apply(thisArg, args);
        }

        unsafeWindow.fetch = function (input, init) {
            var thisArg = this, args = arguments;
            var url = (typeof input === 'string') ? input : (input && input.url) || String(input);
            var method = (init && init.method) || (input && input.method) || 'GET';
            var body = init && init.body;
            var headerStr = headersToStr(init && init.headers);
            return decideAsync('fetch', method, url, body, headerStr).then(function (outcome) {
                return applyFetch(outcome, thisArg, args, url, headerStr);
            });
        };
    }

    /* -------------------------------------------------------------------- */
    /*  WebSocket interception                                               */
    /* -------------------------------------------------------------------- */
    var NativeWS = unsafeWindow.WebSocket;
    if (NativeWS) {
        var WSProxy = function (url, protocols) {
            var outcome = decideSync('websocket', 'CONNECT', url, null, null);
            if (outcome.action === 'block') {
                throw new DOMException('[Traffic Firewall] WebSocket blocked: ' + url, 'SecurityError');
            }
            var ws = protocols !== undefined ? new NativeWS(url, protocols) : new NativeWS(url);
            var origSend = ws.send.bind(ws);
            ws.send = function (data) {
                var out = decideSync('websocket', 'SEND', url, data, null);
                if (out.action === 'block') return;               // silently drop
                if (out.action === 'replace' && out.rule && out.rule.replaceBody != null) {
                    return origSend(out.rule.replaceBody);
                }
                return origSend(data);
            };
            return ws;
        };
        WSProxy.prototype = NativeWS.prototype;
        WSProxy.CONNECTING = NativeWS.CONNECTING;
        WSProxy.OPEN = NativeWS.OPEN;
        WSProxy.CLOSING = NativeWS.CLOSING;
        WSProxy.CLOSED = NativeWS.CLOSED;
        unsafeWindow.WebSocket = WSProxy;
    }

    /* -------------------------------------------------------------------- */
    /*  navigator.sendBeacon interception                                    */
    /* -------------------------------------------------------------------- */
    if (unsafeWindow.navigator && typeof unsafeWindow.navigator.sendBeacon === 'function') {
        var nativeBeacon = unsafeWindow.navigator.sendBeacon.bind(unsafeWindow.navigator);
        unsafeWindow.navigator.sendBeacon = function (url, data) {
            var outcome = decideSync('beacon', 'POST', url, data, null);
            if (outcome.action === 'block') return false;
            return nativeBeacon(url, data);
        };
    }

