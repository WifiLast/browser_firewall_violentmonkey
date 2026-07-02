// ==UserScript==
// @name        ThirdPartyFence
// @namespace   Violentmonkey Scripts
// @match       *://*/*
// @grant       GM_setValue
// @grant       GM_getValue
// @grant       GM_registerMenuCommand
// @grant       GM_addStyle
// @version     2.0
// @author      -
// @description Intercept XHR / fetch / WebSocket / sendBeacon traffic and apply firewall rules to block, alert or replace requests.
// @run-at      document-start
// ==/UserScript==

(function () {
    'use strict';

    /* -------------------------------------------------------------------- */
    /*  Storage helpers (fall back to localStorage when GM_* is unavailable) */
    /* -------------------------------------------------------------------- */
    var STORE_KEY = 'traffic_firewall_rules_v2';
    var POLICY_KEY = 'traffic_firewall_jspolicy_v1';
    var HARDEN_KEY = 'traffic_firewall_hardening_v1';
    var MODE_KEY = 'traffic_firewall_mode_v1';
    var BLOCK_KEY = 'traffic_firewall_blockstyle_v1';
    var TAGS_KEY = 'traffic_firewall_tags_v1';
    var DEEPSCAN_KEY = 'traffic_firewall_deepscan_v1';
    var FIRSTPARTY_KEY = 'traffic_firewall_firstparty_v1';
    var FREEZE_KEY = 'traffic_firewall_freeze_v1';
    var LOG_LIMIT = 500;

    var hasGM = typeof GM_getValue === 'function' && typeof GM_setValue === 'function';

    /* ==================================================================== */
    /*  Environment hardening — freeze built-ins BEFORE page scripts run.    */
    /*  Runs first so the page cannot pollute/patch prototypes afterwards.   */
    /* ==================================================================== */
    // The full set of freezable intrinsics offered in the UI. Ordered; the
    // "core" group (enabled by default) matches the classic anti-tampering list.
    var HARDEN_TARGETS = [
        // core
        'Object', 'Object.prototype',
        'Function', 'Function.prototype',
        'Array', 'Array.prototype',
        'String', 'String.prototype',
        'Number', 'Number.prototype',
        'Boolean', 'Boolean.prototype',
        // extended
        'JSON', 'Math',
        'Date', 'Date.prototype',
        'RegExp', 'RegExp.prototype',
        'Symbol', 'Symbol.prototype',
        'Promise', 'Promise.prototype',
        'Map', 'Map.prototype', 'Set', 'Set.prototype',
        'WeakMap', 'WeakMap.prototype', 'WeakSet', 'WeakSet.prototype',
        'Error', 'Error.prototype',
        // DOM (aggressive — may break some sites)
        'EventTarget.prototype', 'Node.prototype', 'Element.prototype',
        'Document.prototype', 'Window.prototype'
    ];
    var HARDEN_CORE = HARDEN_TARGETS.slice(0, 12);

    function defaultHardening() {
        var targets = {};
        HARDEN_CORE.forEach(function (t) { targets[t] = true; });
        return {
            enabled: false,       // opt-in: freezing can break sites, so off by default
            method: 'freeze',     // 'freeze' | 'seal' | 'preventExtensions'
            targets: targets
        };
    }

    function readStore(key, fallbackRaw) {
        try {
            var raw = hasGM ? GM_getValue(key, null) : localStorage.getItem(key);
            return raw == null ? fallbackRaw : raw;
        } catch (e) { return fallbackRaw; }
    }
    function writeStore(key, raw) {
        try {
            if (hasGM) GM_setValue(key, raw); else localStorage.setItem(key, raw);
        } catch (e) { console.warn('[Firewall] store write failed', key, e); }
    }

    function loadHardening() {
        try {
            var raw = readStore(HARDEN_KEY, null);
            if (!raw) return defaultHardening();
            var p = JSON.parse(raw);
            var d = defaultHardening();
            return {
                enabled: !!p.enabled,
                method: (p.method === 'seal' || p.method === 'preventExtensions') ? p.method : 'freeze',
                targets: (p.targets && typeof p.targets === 'object') ? p.targets : d.targets
            };
        } catch (e) {
            console.warn('[Firewall] failed to load hardening config', e);
            return defaultHardening();
        }
    }
    function saveHardening(p) { writeStore(HARDEN_KEY, JSON.stringify(p)); }

    // Resolve a dotted path ("Array.prototype") against the PAGE's realm so we
    // harden the intrinsics the page actually sees (unsafeWindow), not our sandbox.
    var PAGE_WIN = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;
    function resolveTarget(path) {
        var parts = path.split('.');
        var obj = PAGE_WIN[parts[0]];
        for (var i = 1; i < parts.length && obj != null; i++) obj = obj[parts[i]];
        return obj;
    }

    var HARDENING_APPLIED = [];   // for display in the settings tab

    function applyHardening(cfg) {
        if (!cfg.enabled) return;
        var seal =
            cfg.method === 'seal' ? Object.seal :
                cfg.method === 'preventExtensions' ? Object.preventExtensions :
                    Object.freeze;

        HARDEN_TARGETS.forEach(function (path) {
            if (!cfg.targets[path]) return;
            var obj = resolveTarget(path);
            if (obj == null || (typeof obj !== 'object' && typeof obj !== 'function')) return;
            try {
                seal(obj);
                HARDENING_APPLIED.push(path);
            } catch (e) {
                console.warn('[Traffic Firewall] could not ' + cfg.method + ' ' + path, e);
            }
        });

        if (HARDENING_APPLIED.length) {
            console.log('[Traffic Firewall] hardening: ' + cfg.method + ' applied to ' +
                HARDENING_APPLIED.length + ' target(s):', HARDENING_APPLIED.join(', '));
        }
    }

    var HARDENING = loadHardening();
    // Apply as the very first action, before any page/user script executes.
    applyHardening(HARDENING);

    /* ==================================================================== */
    /*  Trusted Types compatibility                                          */
    /*  Sites with `require-trusted-types-for 'script'` (e.g. Google) throw  */
    /*  on any innerHTML = "<string>" assignment, which would break our UI.  */
    /*  Shim: keep the native path (so the page's own TrustedHTML usage and   */
    /*  protection are untouched); only when a *string* assignment throws do  */
    /*  we fall back to DOMParser — which never executes scripts.            */
    /* ==================================================================== */
    var TT_POLICY = null;
    (function installTrustedTypesShim() {
        try {
            if (typeof unsafeWindow.trustedTypes === 'undefined') return;   // no enforcement here
            // A pass-through policy lets us produce TrustedHTML for our own UI.
            // May be blocked by a strict `trusted-types` allow-list — then null.
            try {
                TT_POLICY = unsafeWindow.trustedTypes.createPolicy(
                    'traffic-firewall', { createHTML: function (s) { return s; } });
            } catch (e) { TT_POLICY = null; }

            var proto = unsafeWindow.Element.prototype;
            var desc = Object.getOwnPropertyDescriptor(proto, 'innerHTML');
            if (!desc || !desc.set) return;
            Object.defineProperty(proto, 'innerHTML', {
                configurable: true,
                enumerable: desc.enumerable,
                get: desc.get,
                set: function (value) {
                    if (frozen && this.isConnected && !isFwNode(this)) return;   // page frozen (live DOM only)
                    if (typeof value === 'string') {
                        // Our own UI is trusted markup. Under Trusted Types a raw-string
                        // assignment runs the page's DEFAULT policy — often a sanitizer that
                        // rejects our <select>/<button>/data-* markup — so never let our UI
                        // hit that path. Prefer our pass-through policy; if the page's
                        // trusted-types allow-list blocked it, build the nodes with DOMParser
                        // (not a TT sink) so the UI always renders. Page nodes keep native
                        // behaviour so the site's own protection is untouched.
                        if (isFwNode(this)) {
                            if (TT_POLICY) {
                                try { desc.set.call(this, TT_POLICY.createHTML(value)); return; } catch (e) { }
                            }
                            try {
                                var doc = new DOMParser().parseFromString(value, 'text/html');
                                while (this.firstChild) this.removeChild(this.firstChild);
                                var kids = doc.body ? Array.prototype.slice.call(doc.body.childNodes) : [];
                                for (var i = 0; i < kids.length; i++) this.appendChild(document.importNode(kids[i], true));
                                return;
                            } catch (e) { this.textContent = value; return; }
                        }
                        try {
                            desc.set.call(this, value);   // compliant / non-enforcing page
                            return;
                        } catch (e) {
                            // Blocked by Trusted Types. Use our pass-through policy if we
                            // have one; otherwise degrade to plain text (no HTML sink).
                            if (TT_POLICY) { desc.set.call(this, TT_POLICY.createHTML(value)); return; }
                            this.textContent = value;
                            return;
                        }
                    }
                    return desc.set.call(this, value);    // TrustedHTML object — pass straight through
                }
            });
        } catch (e) {
            console.warn('[Traffic Firewall] Trusted Types shim failed', e);
        }
    })();

    function loadRules() {
        try {
            var raw = hasGM ? GM_getValue(STORE_KEY, null) : localStorage.getItem(STORE_KEY);
            if (!raw) return [];
            return JSON.parse(raw);
        } catch (e) {
            console.warn('[Firewall] failed to load rules', e);
            return [];
        }
    }

    function saveRules(rules) {
        var raw = JSON.stringify(rules);
        try {
            if (hasGM) GM_setValue(STORE_KEY, raw);
            else localStorage.setItem(STORE_KEY, raw);
        } catch (e) {
            console.warn('[Firewall] failed to save rules', e);
        }
    }

    // JS source policy: controls which <script src> origins may execute.
    // { mode: 'off' | 'blacklist' | 'whitelist', trustSelf: bool,
    //   whitelist: [patterns], blacklist: [patterns] }   (patterns are wildcard globs against the full URL)
    function defaultPolicy() {
        return {
            mode: 'off',
            trustSelf: true,
            whitelist: [],
            blacklist: []
        };
    }

    function loadPolicy() {
        try {
            var raw = hasGM ? GM_getValue(POLICY_KEY, null) : localStorage.getItem(POLICY_KEY);
            if (!raw) return defaultPolicy();
            var p = JSON.parse(raw);
            var d = defaultPolicy();
            return {
                mode: p.mode || d.mode,
                trustSelf: p.trustSelf !== false,
                whitelist: Array.isArray(p.whitelist) ? p.whitelist : [],
                blacklist: Array.isArray(p.blacklist) ? p.blacklist : []
            };
        } catch (e) {
            console.warn('[Firewall] failed to load JS policy', e);
            return defaultPolicy();
        }
    }

    function savePolicy(p) {
        try {
            var raw = JSON.stringify(p);
            if (hasGM) GM_setValue(POLICY_KEY, raw);
            else localStorage.setItem(POLICY_KEY, raw);
        } catch (e) {
            console.warn('[Firewall] failed to save JS policy', e);
        }
    }

    var RULES = loadRules();
    var POLICY = loadPolicy();
    var LOG = [];        // in-memory activity log
    var logListeners = [];
    var modeListeners = [];

    // Operating mode for NEW (unmatched) connections:
    //   'disabled' — firewall passive: rules ignored, nothing blocked or asked.
    //   'normal'   — explicit rules apply; unmatched connections prompt the user.
    //   'learning' — explicit rules apply; unmatched connections auto-create an allow-rule.
    // Explicit rules (block/alert/replace) always take effect in normal & learning.
    var VALID_MODES = ['disabled', 'normal', 'learning'];
    function loadMode() {
        var m = readStore(MODE_KEY, 'disabled');
        return VALID_MODES.indexOf(m) !== -1 ? m : 'disabled';
    }
    var MODE = loadMode();
    var askedSigs = {};   // in-memory dedupe of connections already handled this session

    // How a blocked request is delivered to the page:
    //   'empty' — resolve with a benign empty 200 response (quiet; no page errors).
    //   'error' — fail like a network error (fetch rejects, XHR fires 'error').
    var VALID_BLOCK = ['empty', 'error'];
    function loadBlockStyle() {
        var b = readStore(BLOCK_KEY, 'empty');
        return VALID_BLOCK.indexOf(b) !== -1 ? b : 'empty';
    }
    var BLOCK_STYLE = loadBlockStyle();
    function setBlockStyle(b) {
        if (VALID_BLOCK.indexOf(b) === -1) return;
        BLOCK_STYLE = b;
        writeStore(BLOCK_KEY, b);
    }

    // Watch-tags: keywords that, if found anywhere in a request (URL, body,
    // headers, cookies — case-insensitive), trigger an ask-the-user prompt.
    function loadTags() {
        try {
            var raw = readStore(TAGS_KEY, null);
            if (!raw) return [];
            var arr = JSON.parse(raw);
            return Array.isArray(arr) ? arr : [];
        } catch (e) { return []; }
    }
    function saveTags(list) { writeStore(TAGS_KEY, JSON.stringify(list)); }
    var TAGS = loadTags();

    // Deep watch-tag scanning: also look for tags that are *hidden or obscured* —
    // percent/base64/hex/unicode/HTML-entity encoded, or broken apart by
    // separators — by matching against decoded variants of each request.
    // On by default; can be toggled off (it costs a little CPU) on the Tags tab.
    function loadDeepScan() { return readStore(DEEPSCAN_KEY, 'on') !== 'off'; }
    function saveDeepScan(on) { writeStore(DEEPSCAN_KEY, on ? 'on' : 'off'); }
    var DEEPSCAN = { enabled: loadDeepScan() };

    // First-party trust: requests to the page's own origin are allowed by
    // default, so the firewall only polices third-party traffic and can't break
    // the site's own functionality. Explicit rules still take precedence.
    // On by default; toggle in the footer.
    function loadFirstParty() { return readStore(FIRSTPARTY_KEY, 'on') !== 'off'; }
    function saveFirstParty(on) { writeStore(FIRSTPARTY_KEY, on ? 'on' : 'off'); }
    var FIRSTPARTY = { enabled: loadFirstParty() };

    // Page-wide decision from the prompt's "apply to all following" option.
    // Reset on navigation (fresh script load) and when the mode changes.
    var pageDecision = null;   // null | 'block' | 'allow'

    // Page freeze: after `delay` seconds, block all DOM mutations so the page
    // can no longer change (the firewall's own UI stays exempt).
    function loadFreeze() {
        try {
            var raw = readStore(FREEZE_KEY, null);
            if (!raw) return { enabled: false, delay: 5 };
            var p = JSON.parse(raw);
            return { enabled: !!p.enabled, delay: (typeof p.delay === 'number' && p.delay >= 0) ? p.delay : 5 };
        } catch (e) { return { enabled: false, delay: 5 }; }
    }
    function saveFreeze(f) { writeStore(FREEZE_KEY, JSON.stringify(f)); }
    var FREEZE = loadFreeze();
    var frozen = false;

    // Is a node part of our own firewall UI? Such nodes stay mutable when frozen.
    function isFwNode(n) {
        for (var x = n; x; x = x.parentNode || x.host) {
            if (x.__fwUI) return true;
        }
        return false;
    }
    function freezeNow() {
        if (frozen) return;
        frozen = true;
        addLog({ type: 'page', method: 'FREEZE', url: location.href, action: 'block', ruleName: 'page frozen', body: '' });
        console.log('[Traffic Firewall] page frozen — DOM mutations are now blocked.');
    }
    function scheduleFreeze() {
        if (FREEZE.enabled) setTimeout(freezeNow, (FREEZE.delay || 0) * 1000);
    }

    function setMode(m) {
        if (VALID_MODES.indexOf(m) === -1) return;
        MODE = m;
        writeStore(MODE_KEY, m);
        askedSigs = {};
        pageDecision = null;
        modeListeners.forEach(function (fn) { try { fn(m); } catch (e) {} });
        console.log('[Traffic Firewall] mode → ' + m);
    }

    function connSignature(type, method, url) {
        var host = url;
        try { host = new URL(url, location.href).host; } catch (e) {}
        return type + '|' + host;
    }

    function hostOf(url) {
        try { return new URL(url, location.href).host; } catch (e) { return String(url); }
    }

    var logSeq = 0;
    function addLog(entry) {
        entry.time = new Date();
        entry.id = ++logSeq;
        LOG.unshift(entry);
        if (LOG.length > LOG_LIMIT) LOG.length = LOG_LIMIT;
        logListeners.forEach(function (fn) { try { fn(entry); } catch (e) { } });
    }

    /* -------------------------------------------------------------------- */
    /*  Rule engine                                                          */
    /* -------------------------------------------------------------------- */
    // A rule:
    // {
    //   id, enabled, name,
    //   type:   'any' | 'xhr' | 'fetch' | 'websocket' | 'beacon',
    //   method: 'any' | 'GET' | 'POST' | ...,
    //   matchType: 'contains' | 'exact' | 'regex' | 'wildcard',
    //   pattern: string,
    //   action: 'block' | 'alert' | 'replace' | 'log' | 'allow',
    //   replaceBody:   string (for replace action, response body),
    //   replaceStatus: number (for replace action, response status)
    // }

    function wildcardToRegex(glob) {
        var esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
        return new RegExp('^' + esc + '$', 'i');
    }

    function urlMatches(rule, url) {
        if (!rule.pattern) return true;
        var u = String(url);
        try {
            switch (rule.matchType) {
                case 'exact': return u === rule.pattern;
                case 'regex': return new RegExp(rule.pattern, 'i').test(u);
                case 'wildcard': return wildcardToRegex(rule.pattern).test(u);
                case 'contains':
                default: return u.toLowerCase().indexOf(rule.pattern.toLowerCase()) !== -1;
            }
        } catch (e) {
            return false;
        }
    }

    // Return the first enabled rule matching the given request, or null.
    function findRule(type, method, url) {
        for (var i = 0; i < RULES.length; i++) {
            var r = RULES[i];
            if (!r.enabled) continue;
            if (r.type && r.type !== 'any' && r.type !== type) continue;
            if (r.method && r.method !== 'any' && method &&
                r.method.toUpperCase() !== String(method).toUpperCase()) continue;
            if (!urlMatches(r, url)) continue;
            return r;
        }
        return null;
    }

    // Persist a rule generated at runtime (learning mode / normal-mode "always").
    function rememberRule(type, url, action, tag) {
        var host = hostOf(url);
        var rule = {
            id: newId(),
            enabled: true,
            name: '[' + tag + '] ' + host,
            type: type,
            method: 'any',
            matchType: 'contains',
            pattern: host,
            action: action,
            replaceBody: '',
            replaceStatus: 200
        };
        RULES.push(rule);
        saveRules(RULES);
        if (overlay && activeTab === 'rules') renderRules();
        return rule;
    }

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

    /* -------------------------------------------------------------------- */
    /*  Untrusted JS source firewall (white / black lists)                   */
    /* -------------------------------------------------------------------- */
    var PAGE_ORIGIN = location.origin;

    function resolveUrl(src) {
        try { return new URL(src, location.href).href; } catch (e) { return String(src); }
    }

    function matchAny(list, url) {
        for (var i = 0; i < list.length; i++) {
            var pat = String(list[i]).trim();
            if (!pat) continue;
            try {
                if (pat.indexOf('*') === -1 && pat.indexOf('?') === -1) {
                    // plain substring / origin match
                    if (url.toLowerCase().indexOf(pat.toLowerCase()) !== -1) return true;
                } else if (wildcardToRegex(pat).test(url)) {
                    return true;
                }
            } catch (e) { }
        }
        return false;
    }

    /* --- Loaded-script registry + resource redirect ("upgrade / replace") --- */
    // Every external script the firewall observes is recorded here so the
    // JS Sources tab can list what the page loaded and offer per-script rules.
    var JS_SEEN = {};   // resolved url -> { url, action, reason }
    function recordJs(rawUrl, action, reason) {
        var url = resolveUrl(rawUrl);
        if (!url || url.indexOf('data:') === 0 || url.indexOf('blob:') === 0) return;
        var e = JS_SEEN[url];
        if (!e) JS_SEEN[url] = { url: url, action: action || 'allow', reason: reason || '' };
        else if (action && action !== 'allow') { e.action = action; e.reason = reason || e.reason; }
    }
    // Merge firewall-observed scripts with the browser's own view (Resource
    // Timing API + current DOM) into one deduped, sorted list for the UI.
    function collectLoadedJs() {
        var map = {};
        function put(url, action, reason) {
            url = resolveUrl(url);
            if (!url || url.indexOf('data:') === 0 || url.indexOf('blob:') === 0) return;
            if (!map[url]) map[url] = { url: url, action: action || 'allow', reason: reason || '' };
            else if (action && action !== 'allow') { map[url].action = action; map[url].reason = reason || map[url].reason; }
        }
        try {
            var perf = (unsafeWindow.performance && unsafeWindow.performance.getEntriesByType)
                ? unsafeWindow.performance.getEntriesByType('resource') : [];
            for (var i = 0; i < perf.length; i++) if (perf[i].initiatorType === 'script') put(perf[i].name, 'allow', 'loaded');
        } catch (e) { }
        try {
            var els = document.querySelectorAll('script[src]');
            for (var j = 0; j < els.length; j++) { var s = els[j].src || els[j].getAttribute('src'); if (s) put(s, 'allow', 'in DOM'); }
        } catch (e) { }
        for (var k in JS_SEEN) if (Object.prototype.hasOwnProperty.call(JS_SEEN, k)) put(JS_SEEN[k].url, JS_SEEN[k].action, JS_SEEN[k].reason);
        var out = [];
        for (var u in map) if (Object.prototype.hasOwnProperty.call(map, u)) out.push(map[u]);
        out.sort(function (a, b) { return a.url < b.url ? -1 : (a.url > b.url ? 1 : 0); });
        return out;
    }

    // A 'replace' rule on a DOM-loaded resource (script/iframe/img/media/css)
    // whose replacement body is a URL *redirects* the element to that URL —
    // e.g. swap an outdated jQuery for a patched newer build, or point an ad
    // script at a harmless stub — instead of merely blocking it.
    function looksLikeUrl(s) {
        s = String(s || '').trim();
        return s !== '' && (/^(https?:)?\/\//i.test(s) || s.charAt(0) === '/');
    }
    function redirectTargetFor(rule) {
        return (rule && rule.action === 'replace' && looksLikeUrl(rule.replaceBody)) ? resolveUrl(rule.replaceBody) : null;
    }
    // Rewrite a node's src/href to a new URL. Marks the node so our own hooks
    // skip it, and drops any SRI `integrity` (it would not match the new file).
    // Reliable pre-insertion; a <script> already inserted will not re-execute.
    function redirectResource(node, info, toUrl, reason) {
        var attr = info.type === 'stylesheet' ? 'href' : 'src';
        node.__fwChecked = true;
        node.__fwRedirect = true;
        try { node.removeAttribute('integrity'); } catch (e) { }
        try { node.setAttribute(attr, toUrl); } catch (e) { }
        try { if (attr === 'href') node.href = toUrl; else node.src = toUrl; } catch (e) { }
        addLog({ type: info.type, method: 'REDIRECT', url: toUrl, action: 'replace',
                 ruleName: (reason ? reason + ' ' : '') + '→ ' + toUrl, body: '' });
        recordJs(info.url, 'replace', (reason || '') + ' → ' + toUrl);
        console.warn('[Traffic Firewall] redirected ' + info.type + ':', info.url, '→', toUrl, '(' + (reason || '') + ')');
    }
    // Disarm a script element already in the DOM so the original never runs.
    // Removing a pending external <script> before it finishes cancels it, which
    // is why redirect must NOT just rewrite src on a connected node (that leaves
    // the original in flight AND starts a second fetch → both load).
    function disarmScript(node) {
        try { node.type = 'javascript/blocked'; } catch (e) { }
        try { node.removeAttribute('src'); } catch (e) { }
        try { node.remove(); } catch (e) { }
    }
    // Inject a fresh script for the redirect target (used when the original is
    // already inserted / about to run and cannot be rewritten in place).
    // async=false preserves execution order relative to other ordered scripts,
    // which matters for library dependencies (e.g. code that expects jQuery).
    function injectRedirectScript(toUrl, reason) {
        try {
            var s = document.createElement('script');
            s.__fwChecked = true;
            s.__fwRedirect = true;
            s.async = false;
            s.src = toUrl;
            (document.head || document.documentElement).appendChild(s);
            addLog({ type: 'script', method: 'REDIRECT', url: toUrl, action: 'replace',
                     ruleName: (reason ? reason + ' ' : '') + '→ ' + toUrl, body: '' });
        } catch (e) { }
    }

    // Returns true if a script from `src` is permitted to execute.
    function isScriptAllowed(src) {
        if (POLICY.mode === 'off') return true;
        var url = resolveUrl(src);

        if (POLICY.trustSelf) {
            try { if (new URL(url).origin === PAGE_ORIGIN) return true; } catch (e) { }
        }

        if (POLICY.mode === 'blacklist') {
            return !matchAny(POLICY.blacklist, url);
        }
        if (POLICY.mode === 'whitelist') {
            return matchAny(POLICY.whitelist, url);
        }
        return true;
    }

    // Decide what to do with a <script src>. Considers firewall RULES (type
    // 'script'/'any') first, then the JS-source white/black-list policy.
    // Returns { action:'block'|'alert'|'allow', reason, active }.
    function scriptDecision(rawSrc) {
        var url = resolveUrl(rawSrc);
        var rule = findRule('script', 'GET', url);
        if (rule && rule.action === 'replace') {
            var to = redirectTargetFor(rule);
            if (to) return { action: 'redirect', to: to, reason: 'rule: ' + (rule.name || rule.pattern), active: true };
            return { action: 'block', reason: 'rule: ' + (rule.name || rule.pattern), active: true };
        }
        if (rule && rule.action === 'block') {
            return { action: 'block', reason: 'rule: ' + (rule.name || rule.pattern), active: true };
        }
        if (POLICY.mode !== 'off' && !isScriptAllowed(url)) {
            return { action: 'block', reason: POLICY.mode + ' policy', active: true };
        }
        if (rule && rule.action === 'alert') {
            return { action: 'alert', reason: 'rule: ' + (rule.name || rule.pattern), active: true };
        }
        return { action: 'allow', reason: rule ? ('rule: ' + (rule.name || rule.pattern)) : '',
                 active: (POLICY.mode !== 'off') || !!rule };
    }

    // Neutralize a script element so it cannot execute.
    function neuterScript(node, src, reason) {
        try { node.type = 'javascript/blocked'; } catch (e) { }
        try { node.removeAttribute('src'); } catch (e) { }
        try { node.setAttribute('data-fw-blocked', src); } catch (e) { }
        node.remove && node.remove();
        addLog({ type: 'script', method: 'LOAD', url: src, action: 'block', ruleName: reason || '', body: '' });
        console.warn('[Traffic Firewall] blocked script:', src, '(' + (reason || '') + ')');
    }

    // Map a DOM element to the sub-resource it will load, or null.
    // Covers the resource-loading tags a userscript can catch pre-insertion.
    function resourceOf(node) {
        if (!node || !node.tagName || !node.getAttribute) return null;
        var g = function (a) { return node.getAttribute(a); };
        switch (node.tagName) {
            case 'SCRIPT': var s = node.src || g('src'); return s ? { type: 'script', attr: 'src', url: s } : null;
            case 'IFRAME': var f = node.src || g('src'); return f ? { type: 'iframe', attr: 'src', url: f } : null;
            case 'IMG':    var i = node.src || g('src'); return i ? { type: 'image', attr: 'src', url: i } : null;
            case 'LINK':   var h = node.href || g('href'); return h ? { type: 'stylesheet', attr: 'href', url: h } : null;
            case 'VIDEO':
            case 'AUDIO':
            case 'SOURCE': var m = node.src || g('src'); return m ? { type: 'media', attr: 'src', url: m } : null;
            default: return null;
        }
    }

    // Generic resource decision. Scripts also consult the JS-source policy.
    function resourceDecision(type, rawUrl) {
        if (type === 'script') return scriptDecision(rawUrl);
        var url = resolveUrl(rawUrl);
        var rule = findRule(type, 'GET', url);
        if (rule && rule.action === 'replace') {
            var to = redirectTargetFor(rule);
            if (to) return { action: 'redirect', to: to, reason: 'rule: ' + (rule.name || rule.pattern), active: true };
            return { action: 'block', reason: 'rule: ' + (rule.name || rule.pattern), active: true };
        }
        if (rule && rule.action === 'block') {
            return { action: 'block', reason: 'rule: ' + (rule.name || rule.pattern), active: true };
        }
        if (rule && rule.action === 'alert') {
            return { action: 'alert', reason: 'rule: ' + (rule.name || rule.pattern), active: true };
        }
        return { action: 'allow', reason: '', active: !!rule };
    }

    // Neutralize any blocked resource element so it won't load/execute.
    function neuterResource(node, info, reason) {
        if (info.type === 'script') { neuterScript(node, resolveUrl(info.url), reason); return; }
        try { node.removeAttribute(info.attr); } catch (e) { }
        try { node.setAttribute('data-fw-blocked', info.url); } catch (e) { }
        node.remove && node.remove();
        addLog({ type: info.type, method: 'LOAD', url: resolveUrl(info.url), action: 'block', ruleName: reason || '', body: '' });
        console.warn('[Traffic Firewall] blocked ' + info.type + ':', info.url, '(' + (reason || '') + ')');
    }

    function inspectNode(node) {
        if (!node || node.__fwChecked) return;
        var info = resourceOf(node);
        if (!info) return;
        node.__fwChecked = true;
        var d = resourceDecision(info.type, info.url);
        if (info.type === 'script') recordJs(info.url, d.action === 'redirect' ? 'replace' : d.action, d.reason);
        if (d.action === 'block') {
            neuterResource(node, info, d.reason);
        } else if (d.action === 'redirect') {
            if (info.type === 'script' && node.isConnected) {
                // Caught after insertion (e.g. a parser-inserted <script> seen by
                // the observer): the original is already fetching, so rewriting
                // src would load BOTH. Disarm the original and inject the
                // replacement fresh instead.
                disarmScript(node);
                addLog({ type: 'script', method: 'REDIRECT', url: resolveUrl(info.url), action: 'replace',
                         ruleName: (d.reason ? d.reason + ' ' : '') + '→ ' + d.to, body: '' });
                recordJs(info.url, 'replace', (d.reason || '') + ' → ' + d.to);
                injectRedirectScript(d.to, d.reason);
            } else {
                redirectResource(node, info, d.to, d.reason);
            }
        } else if (d.active) {                  // only log when something actually evaluated it
            addLog({ type: info.type, method: 'LOAD', url: resolveUrl(info.url), action: d.action, ruleName: d.reason, body: '' });
            if (d.action === 'alert') {
                var u = resolveUrl(info.url);
                setTimeout(function () { alert('[Traffic Firewall] ALERT ' + info.type + '\n\n' + u); }, 0);
            }
        }
    }

    // Inspect a node and any resource-loading descendants it brought with it.
    var RES_SELECTOR = 'script[src],iframe[src],img[src],link[href],video[src],audio[src],source[src]';
    function inspectTree(root) {
        inspectNode(root);
        if (root && root.querySelectorAll) {
            var kids = root.querySelectorAll(RES_SELECTOR);
            for (var i = 0; i < kids.length; i++) inspectNode(kids[i]);
        }
    }

    // 1) Firefox/Violentmonkey: cancel execution right before it runs.
    document.addEventListener('beforescriptexecute', function (e) {
        var node = e.target;
        if (node && node.__fwRedirect) return;   // our own injected replacement
        var src = node && (node.src || (node.getAttribute && node.getAttribute('src')));
        if (!src) return;
        var d = scriptDecision(src);
        recordJs(src, d.action === 'redirect' ? 'replace' : d.action, d.reason);
        if (d.action === 'block') {
            e.preventDefault();
            neuterScript(node, resolveUrl(src), d.reason);
        } else if (d.action === 'redirect') {
            e.preventDefault();
            neuterScript(node, resolveUrl(src), d.reason);
            injectRedirectScript(d.to, d.reason);
        }
    }, true);

    // 2) Cross-browser: catch resource nodes as they are inserted (before their
    //    external source has finished loading, so removing src prevents the load).
    var scriptObserver = new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
            var added = muts[i].addedNodes;
            for (var j = 0; j < added.length; j++) inspectTree(added[j]);
        }
    });
    try {
        scriptObserver.observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) {
        document.addEventListener('DOMContentLoaded', function () {
            scriptObserver.observe(document.documentElement, { childList: true, subtree: true });
        });
    }

    // 3) Gate resources created imperatively and given a src/href before insertion,
    //    by hooking the property setter on each element prototype.
    function hookSrcSetter(proto, prop, type) {
        try {
            if (!proto) return;
            var desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set) return;
            Object.defineProperty(proto, prop, {
                configurable: true,
                enumerable: desc.enumerable,
                get: desc.get,
                set: function (value) {
                    if (this.__fwRedirect) return desc.set.call(this, value);
                    var d = resourceDecision(type, value);
                    if (type === 'script') recordJs(value, d.action === 'redirect' ? 'replace' : d.action, d.reason);
                    if (d.action === 'block') {
                        this.__fwChecked = true;
                        addLog({ type: type, method: 'SET', url: resolveUrl(value), action: 'block', ruleName: d.reason, body: '' });
                        console.warn('[Traffic Firewall] blocked ' + type + ' (' + prop + '=):', value, '(' + d.reason + ')');
                        return; // drop the assignment entirely
                    }
                    if (d.action === 'redirect') {
                        this.__fwChecked = true;
                        this.__fwRedirect = true;
                        try { this.removeAttribute('integrity'); } catch (e) { }
                        addLog({ type: type, method: 'REDIRECT', url: d.to, action: 'replace', ruleName: (d.reason ? d.reason + ' ' : '') + '→ ' + d.to, body: '' });
                        console.warn('[Traffic Firewall] redirected ' + type + ' (' + prop + '=):', value, '→', d.to);
                        return desc.set.call(this, d.to);
                    }
                    return desc.set.call(this, value);
                }
            });
        } catch (e) {
            console.warn('[Traffic Firewall] could not hook ' + type + '.' + prop + ' setter', e);
        }
    }
    hookSrcSetter(unsafeWindow.HTMLScriptElement && unsafeWindow.HTMLScriptElement.prototype, 'src', 'script');
    hookSrcSetter(unsafeWindow.HTMLIFrameElement && unsafeWindow.HTMLIFrameElement.prototype, 'src', 'iframe');
    hookSrcSetter(unsafeWindow.HTMLImageElement && unsafeWindow.HTMLImageElement.prototype, 'src', 'image');
    hookSrcSetter(unsafeWindow.HTMLMediaElement && unsafeWindow.HTMLMediaElement.prototype, 'src', 'media');

    // 4) Hook setAttribute so `el.setAttribute('src'/'href', ...)` is gated too.
    try {
        var _setAttr = unsafeWindow.Element.prototype.setAttribute;
        unsafeWindow.Element.prototype.setAttribute = function (name, value) {
            if (this && this.__fwRedirect) return _setAttr.apply(this, arguments);   // our redirect target
            if (frozen && this.isConnected && !isFwNode(this)) return;   // page frozen (live DOM only)
            var attr = String(name).toLowerCase();
            // Determine the resource type from the element + attribute being set.
            var type = null;
            if (this && this.tagName) {
                if (this.tagName === 'SCRIPT' && attr === 'src') type = 'script';
                else if (this.tagName === 'IFRAME' && attr === 'src') type = 'iframe';
                else if (this.tagName === 'IMG' && attr === 'src') type = 'image';
                else if (this.tagName === 'LINK' && attr === 'href') type = 'stylesheet';
                else if ((this.tagName === 'VIDEO' || this.tagName === 'AUDIO' || this.tagName === 'SOURCE') && attr === 'src') type = 'media';
            }
            if (type) {
                var d = resourceDecision(type, value);
                if (type === 'script') recordJs(value, d.action === 'redirect' ? 'replace' : d.action, d.reason);
                if (d.action === 'block') {
                    this.__fwChecked = true;
                    addLog({ type: type, method: 'SETATTR', url: resolveUrl(value), action: 'block', ruleName: d.reason, body: '' });
                    console.warn('[Traffic Firewall] blocked ' + type + ' (setAttribute):', value, '(' + d.reason + ')');
                    return; // drop it
                }
                if (d.action === 'redirect') {
                    this.__fwChecked = true;
                    this.__fwRedirect = true;
                    try { this.removeAttribute('integrity'); } catch (e) { }
                    addLog({ type: type, method: 'REDIRECT', url: d.to, action: 'replace', ruleName: (d.reason ? d.reason + ' ' : '') + '→ ' + d.to, body: '' });
                    console.warn('[Traffic Firewall] redirected ' + type + ' (setAttribute):', value, '→', d.to);
                    return _setAttr.call(this, name, d.to);
                }
            }
            return _setAttr.apply(this, arguments);
        };
    } catch (e) {
        console.warn('[Traffic Firewall] could not hook setAttribute', e);
    }

    // 5) Neuter a blocked resource BEFORE it is inserted into the DOM — the
    //    reliable point: once a connected element has a src, removing it
    //    afterwards does not cancel the load. We catch it (and its children) here.
    function preInsertCheck(node) {
        try {
            if (node && node.querySelectorAll) inspectTree(node); else inspectNode(node);
        } catch (e) { }
    }
    // A frozen page blocks changes to the LIVE (connected) DOM only. Off-DOM
    // construction — building detached subtrees, populating <template> content,
    // cloning fragments — is harmless and is what frameworks (Svelte, React …)
    // do constantly, so we must let it through or they crash mid-render.
    function freezeAllows(parent, child) {
        if (!frozen) return true;
        if (parent && !parent.isConnected) return true;   // off-DOM build, not a visible page change
        if (isFwNode(parent)) return true;
        if (child && (child.__fwUI || isFwNode(child))) return true;
        return false;
    }
    try {
        var _appendChild = unsafeWindow.Node.prototype.appendChild;
        unsafeWindow.Node.prototype.appendChild = function (node) {
            if (!freezeAllows(this, node)) return node;
            preInsertCheck(node);
            return _appendChild.apply(this, arguments);
        };
        var _insertBefore = unsafeWindow.Node.prototype.insertBefore;
        unsafeWindow.Node.prototype.insertBefore = function (node) {
            if (!freezeAllows(this, node)) return node;
            preInsertCheck(node);
            return _insertBefore.apply(this, arguments);
        };
        var _removeChild = unsafeWindow.Node.prototype.removeChild;
        unsafeWindow.Node.prototype.removeChild = function (node) {
            if (!freezeAllows(this, node)) return node;
            return _removeChild.apply(this, arguments);
        };
        var _replaceChild = unsafeWindow.Node.prototype.replaceChild;
        unsafeWindow.Node.prototype.replaceChild = function (newNode, oldNode) {
            if (!freezeAllows(this, newNode) && !freezeAllows(this, oldNode)) return oldNode;
            return _replaceChild.apply(this, arguments);
        };
        if (unsafeWindow.Element.prototype.append) {
            var _append = unsafeWindow.Element.prototype.append;
            unsafeWindow.Element.prototype.append = function () {
                if (frozen && this.isConnected && !isFwNode(this)) return;
                for (var i = 0; i < arguments.length; i++) preInsertCheck(arguments[i]);
                return _append.apply(this, arguments);
            };
        }
        var _removeAttr = unsafeWindow.Element.prototype.removeAttribute;
        unsafeWindow.Element.prototype.removeAttribute = function () {
            if (frozen && this.isConnected && !isFwNode(this)) return;
            return _removeAttr.apply(this, arguments);
        };
    } catch (e) {
        console.warn('[Traffic Firewall] could not hook DOM insertion', e);
    }

    /* ==================================================================== */
    /*  UI : firewall rules modal                                            */
    /* ==================================================================== */
    var uid = 0;
    function newId() { return 'r' + (Date.now().toString(36)) + (uid++); }

    if (typeof GM_addStyle === 'function') GM_addStyle(css()); else injectStyle(css());

    function injectStyle(text) {
        var s = document.createElement('style');
        s.textContent = text;
        (document.head || document.documentElement).appendChild(s);
    }

    function css() {
        return [
            '#fw-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:2147483646;display:none;font-family:system-ui,Segoe UI,Arial,sans-serif}',
            '#fw-overlay.open{display:flex;align-items:center;justify-content:center}',
            '#fw-modal{background:#1e2127;color:#e6e6e6;width:min(1100px,96vw);max-width:96vw;max-height:88vh;border-radius:10px;box-shadow:0 12px 48px rgba(0,0,0,.6);display:flex;flex-direction:column;overflow:hidden}',
            '#fw-modal header{display:flex;align-items:center;gap:10px;padding:14px 18px;background:#12151a;border-bottom:1px solid #2c313a}',
            '#fw-modal header h2{margin:0;font-size:16px;font-weight:600;flex:1}',
            '#fw-modal header .fw-badge{font-size:11px;background:#2c313a;padding:2px 8px;border-radius:10px;color:#9aa4b2}',
            '.fw-tabs{display:flex;gap:4px;padding:8px 18px 0;background:#12151a}',
            '.fw-tab{padding:8px 14px;cursor:pointer;border:none;background:none;color:#9aa4b2;font-size:13px;border-bottom:2px solid transparent}',
            '.fw-tab.active{color:#fff;border-bottom-color:#4d8bf0}',
            '.fw-body{padding:16px 18px;overflow-y:auto;overflow-x:hidden}',
            '.fw-body table{width:100%;border-collapse:collapse;font-size:12.5px;table-layout:fixed}',
            '.fw-body th,.fw-body td{text-align:left;padding:6px 8px;border-bottom:1px solid #2c313a;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}',
            '.fw-body th{color:#9aa4b2;font-weight:600;position:sticky;top:0;background:#1e2127}',
            '.fw-input,.fw-select{background:#12151a!important;color:#e6e6e6!important;border:1px solid #2c313a;border-radius:5px;padding:6px 8px;font-size:12.5px;width:100%;box-sizing:border-box}',
            '.fw-select option{color:#000!important;background:#fff!important}',
            '.fw-btn{cursor:pointer;border:none;border-radius:5px;padding:7px 13px;font-size:12.5px;font-weight:600}',
            '.fw-btn.primary{background:#4d8bf0;color:#fff}',
            '.fw-btn.ghost{background:#2c313a;color:#e6e6e6}',
            '.fw-btn.danger{background:#3a2226;color:#ff7b7b}',
            '.fw-btn.mini{padding:3px 8px;font-size:11px}',
            '.fw-row-actions{display:flex;gap:5px}',
            '.fw-tag{font-size:10.5px;padding:2px 7px;border-radius:9px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}',
            '.fw-tag.block{background:#3a2226;color:#ff7b7b}',
            '.fw-tag.alert{background:#3a3322;color:#ffd479}',
            '.fw-tag.replace{background:#22333a;color:#79d4ff}',
            '.fw-tag.log{background:#2a2e36;color:#9aa4b2}',
            '.fw-tag.allow{background:#22331f;color:#8fe08f}',
            '.fw-foot{display:flex;gap:8px;padding:12px 18px;border-top:1px solid #2c313a;background:#12151a}',
            '.fw-foot .spacer{flex:1}',
            '.fw-close{cursor:pointer;font-size:20px;color:#9aa4b2;background:none;border:none;line-height:1}',
            '.fw-empty{color:#6b7480;text-align:center;padding:26px;font-size:13px}',
            '.fw-log{font-family:ui-monospace,Consolas,monospace;font-size:11.5px}',
            '.fw-log .u{color:#9aa4b2;word-break:break-all}',
            '.fw-mode-wrap{display:flex;align-items:center;gap:6px;font-size:11px;color:#9aa4b2}',
            '.fw-mode-sel{width:auto;padding:4px 6px}',
            '.fw-log tr.fw-log-row{cursor:pointer}',
            '.fw-log tr.fw-log-row:hover{background:#232833}',
            '.fw-log .fw-url-short{color:#9aa4b2}',
            '.fw-log .fw-caret{display:inline-block;width:12px;color:#6b7480}',
            '.fw-log tr.fw-log-detail>td{background:#171b21;color:#c7d0da;padding:8px 10px}',
            '.fw-log .fw-detail-url{word-break:break-all;color:#cfe1ff}',
            '.fw-log .fw-detail-body{white-space:pre-wrap;word-break:break-all;margin-top:6px;color:#9aa4b2;max-height:160px;overflow:auto}',
            '#fw-fab{position:fixed;bottom:16px;right:16px;z-index:2147483645;width:44px;height:44px;border-radius:50%;background:#4d8bf0;color:#fff;border:none;cursor:pointer;font-size:20px;box-shadow:0 4px 14px rgba(0,0,0,.4)}',
            '.fw-form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:12px}',
            '.fw-form-grid label{display:flex;flex-direction:column;gap:4px;font-size:11.5px;color:#9aa4b2}',
            '.fw-form-grid .full{grid-column:1/-1}',
            '.fw-ask-ov{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:system-ui,Segoe UI,Arial,sans-serif}',
            '.fw-ask{background:#1e2127;color:#e6e6e6;width:min(520px,92vw);border-radius:10px;box-shadow:0 12px 48px rgba(0,0,0,.6);padding:18px;border:1px solid #2c313a}',
            '.fw-ask-h{font-size:15px;font-weight:600;margin-bottom:10px}',
            '.fw-ask-reason{font-size:12.5px;color:#ffd479;margin-bottom:8px}',
            '.fw-ask-meta{font-size:12px;color:#9aa4b2;margin-bottom:6px}',
            '.fw-ask-url{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#cfe1ff;word-break:break-all;background:#12151a;border:1px solid #2c313a;border-radius:6px;padding:8px;max-height:120px;overflow:auto}',
            '.fw-ask-all{display:flex;align-items:center;gap:8px;font-size:12.5px;color:#c7d0da;margin:12px 0}',
            '.fw-ask-btns{display:flex;gap:10px;justify-content:flex-end}'
        ].join('\n');
    }

    var overlay, activeTab = 'rules';

    function buildModal() {
        overlay = document.createElement('div');
        overlay.id = 'fw-overlay';
        overlay.__fwUI = true;
        overlay.innerHTML =
            '<div id="fw-modal">' +
            '<header>' +
            '<h2>🔥 Traffic Firewall</h2>' +
            '<span class="fw-badge" id="fw-count"></span>' +
            '<label class="fw-mode-wrap" title="How new (unmatched) connections are handled">Mode ' +
                '<select class="fw-select fw-mode-sel" id="fw-mode">' +
                    '<option value="disabled">Disabled</option>' +
                    '<option value="normal">Normal (ask)</option>' +
                    '<option value="learning">Learning (auto-rule)</option>' +
                '</select>' +
            '</label>' +
            '<button class="fw-close" title="Close">×</button>' +
            '</header>' +
            '<div class="fw-tabs">' +
            '<button class="fw-tab active" data-tab="rules">Rules</button>' +
            '<button class="fw-tab" data-tab="tags">Watch Tags</button>' +
            '<button class="fw-tab" data-tab="js">JS Sources</button>' +
            '<button class="fw-tab" data-tab="harden">Hardening</button>' +
            '<button class="fw-tab" data-tab="log">Activity Log</button>' +
            '</div>' +
            '<div class="fw-body" id="fw-body-rules"></div>' +
            '<div class="fw-body" id="fw-body-tags" style="display:none"></div>' +
            '<div class="fw-body" id="fw-body-js" style="display:none"></div>' +
            '<div class="fw-body" id="fw-body-harden" style="display:none"></div>' +
            '<div class="fw-body" id="fw-body-log" style="display:none"></div>' +
            '<div class="fw-foot">' +
            '<button class="fw-btn primary" id="fw-add">+ Add rule</button>' +
            '<button class="fw-btn ghost" id="fw-export">Export</button>' +
            '<button class="fw-btn ghost" id="fw-import">Import</button>' +
            '<label class="fw-mode-wrap" title="How a blocked request is delivered to the page">Blocked → ' +
                '<select class="fw-select fw-mode-sel" id="fw-blockstyle">' +
                    '<option value="empty">Empty response (quiet)</option>' +
                    '<option value="error">Network error</option>' +
                '</select>' +
            '</label>' +
            '<label class="fw-mode-wrap" title="Requests to the page\'s own domain are trusted so the firewall only polices third-party traffic">First-party ' +
                '<select class="fw-select fw-mode-sel" id="fw-firstparty">' +
                    '<option value="on">allow (recommended)</option>' +
                    '<option value="off">apply rules</option>' +
                '</select>' +
            '</label>' +
            '<span class="spacer"></span>' +
            '<button class="fw-btn danger" id="fw-clearlog">Clear log</button>' +
            '</div>' +
            '</div>';

        document.documentElement.appendChild(overlay);

        overlay.addEventListener('click', function (e) {
            if (e.target === overlay) closeModal();
        });
        overlay.querySelector('.fw-close').addEventListener('click', closeModal);
        overlay.querySelectorAll('.fw-tab').forEach(function (t) {
            t.addEventListener('click', function () { switchTab(t.dataset.tab); });
        });
        overlay.querySelector('#fw-add').addEventListener('click', function () { editRule(null); });
        overlay.querySelector('#fw-export').addEventListener('click', exportRules);
        overlay.querySelector('#fw-import').addEventListener('click', importRules);
        overlay.querySelector('#fw-clearlog').addEventListener('click', function () {
            LOG.length = 0; renderLog();
        });

        var modeSel = overlay.querySelector('#fw-mode');
        modeSel.value = MODE;
        modeSel.addEventListener('change', function () { setMode(modeSel.value); });
        modeListeners.push(function (m) { if (modeSel) modeSel.value = m; });

        var blockSel = overlay.querySelector('#fw-blockstyle');
        blockSel.value = BLOCK_STYLE;
        blockSel.addEventListener('change', function () { setBlockStyle(blockSel.value); });

        var fpSel = overlay.querySelector('#fw-firstparty');
        fpSel.value = FIRSTPARTY.enabled ? 'on' : 'off';
        fpSel.addEventListener('change', function () {
            FIRSTPARTY.enabled = fpSel.value === 'on';
            saveFirstParty(FIRSTPARTY.enabled);
        });

        renderRules();
        renderTags();
        renderPolicy();
        renderHardening();
        renderLog();
        logListeners.push(function () { if (activeTab === 'log') renderLog(); });
    }

    function switchTab(tab) {
        activeTab = tab;
        overlay.querySelectorAll('.fw-tab').forEach(function (t) {
            t.classList.toggle('active', t.dataset.tab === tab);
        });
        overlay.querySelector('#fw-body-rules').style.display = tab === 'rules' ? '' : 'none';
        overlay.querySelector('#fw-body-tags').style.display = tab === 'tags' ? '' : 'none';
        overlay.querySelector('#fw-body-js').style.display = tab === 'js' ? '' : 'none';
        overlay.querySelector('#fw-body-harden').style.display = tab === 'harden' ? '' : 'none';
        overlay.querySelector('#fw-body-log').style.display = tab === 'log' ? '' : 'none';
        if (tab === 'log') renderLog();
        if (tab === 'tags') renderTags();
        if (tab === 'js') renderPolicy();
        if (tab === 'harden') renderHardening();
    }

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    function renderRules() {
        var host = overlay.querySelector('#fw-body-rules');
        overlay.querySelector('#fw-count').textContent = RULES.length + ' rule' + (RULES.length === 1 ? '' : 's');

        if (!RULES.length) {
            host.innerHTML = '<div class="fw-empty">No rules yet. Click “+ Add rule” to create one.</div>';
            return;
        }

        var rows = RULES.map(function (r, i) {
            var full = String(r.pattern || '');
            // Show just the base path (drop query/hash); full value on hover.
            var shortPat = full.split('?')[0].split('#')[0];
            if (shortPat.length > 60) shortPat = shortPat.slice(0, 57) + '…';
            else if (shortPat.length !== full.length) shortPat += '…';   // signal trimmed query
            return '<tr data-i="' + i + '">' +
                '<td><input type="checkbox" class="fw-en" ' + (r.enabled ? 'checked' : '') + '></td>' +
                '<td>' + escapeHtml(r.name || '(unnamed)') + '</td>' +
                '<td>' + escapeHtml(r.type || 'any') + '</td>' +
                '<td>' + escapeHtml(r.method || 'any') + '</td>' +
                '<td title="' + escapeHtml(full) + '">' + escapeHtml(r.matchType) + ': <code>' + escapeHtml(shortPat) + '</code></td>' +
                '<td><span class="fw-tag ' + r.action + '">' + escapeHtml(r.action) + '</span></td>' +
                '<td><div class="fw-row-actions">' +
                '<button class="fw-btn ghost mini fw-edit">Edit</button>' +
                '<button class="fw-btn danger mini fw-del">Delete</button>' +
                '</div></td>' +
                '</tr>';
        }).join('');

        host.innerHTML =
            '<table><thead><tr>' +
            '<th>On</th><th>Name</th><th>Type</th><th>Method</th><th>Match</th><th>Action</th><th></th>' +
            '</tr></thead><tbody>' + rows + '</tbody></table>';

        host.querySelectorAll('tr[data-i]').forEach(function (tr) {
            var i = +tr.dataset.i;
            tr.querySelector('.fw-en').addEventListener('change', function (e) {
                RULES[i].enabled = e.target.checked; saveRules(RULES);
            });
            tr.querySelector('.fw-edit').addEventListener('click', function () { editRule(i); });
            tr.querySelector('.fw-del').addEventListener('click', function () {
                if (confirm('Delete this rule?')) { RULES.splice(i, 1); saveRules(RULES); renderRules(); }
            });
        });
    }

    function renderLog() {
        var host = overlay.querySelector('#fw-body-log');
        if (!LOG.length) {
            host.innerHTML = '<div class="fw-empty">No traffic recorded yet.</div>';
            return;
        }
        var rows = LOG.map(function (e) {
            var t = e.time.toLocaleTimeString();
            var full = String(e.url);
            var short = full.length > 60 ? full.slice(0, 57) + '…' : full;
            var main = '<tr class="fw-log-row" data-id="' + e.id + '">' +
                '<td><span class="fw-caret">▸</span>' + t + '</td>' +
                '<td>' + escapeHtml(e.type) + '</td>' +
                '<td>' + escapeHtml(e.method) + '</td>' +
                '<td><span class="fw-tag ' + e.action + '">' + escapeHtml(e.action) + '</span></td>' +
                '<td class="u"><span class="fw-url-short">' + escapeHtml(short) + '</span></td>' +
                '</tr>';
            var detail = '<tr class="fw-log-detail" data-detail="' + e.id + '" style="display:none"><td colspan="5">' +
                '<div class="fw-detail-url">' + escapeHtml(full) + '</div>' +
                (e.ruleName ? '<div style="margin-top:4px;color:#6b7480">rule: ' + escapeHtml(e.ruleName) + '</div>' : '') +
                (e.body ? '<div class="fw-detail-body">' + escapeHtml(e.body) + '</div>' : '') +
                '<div style="margin-top:8px">' +
                    '<button class="fw-btn ghost mini fw-log-rule"' +
                        ' data-type="' + escapeHtml(e.type) + '"' +
                        ' data-method="' + escapeHtml(e.method || 'any') + '"' +
                        ' data-url="' + escapeHtml(full) + '">+ Create rule from this</button>' +
                '</div>' +
                '</td></tr>';
            return main + detail;
        }).join('');
        host.innerHTML =
            '<p style="margin:0 0 10px;color:#6b7480;font-size:11.5px">Click a row to expand the full URL, body and actions.</p>' +
            '<table class="fw-log"><thead><tr>' +
            '<th>Time</th><th>Type</th><th>Method</th><th>Action</th><th>URL</th>' +
            '</tr></thead><tbody>' + rows + '</tbody></table>';

        host.querySelectorAll('tr.fw-log-row').forEach(function (tr) {
            tr.addEventListener('click', function () {
                var d = host.querySelector('tr.fw-log-detail[data-detail="' + tr.dataset.id + '"]');
                if (!d) return;
                var open = d.style.display === 'none';
                d.style.display = open ? '' : 'none';
                var caret = tr.querySelector('.fw-caret');
                if (caret) caret.textContent = open ? '▾' : '▸';
            });
        });
        host.querySelectorAll('.fw-log-rule').forEach(function (btn) {
            btn.addEventListener('click', function (ev) {
                ev.stopPropagation();
                switchTab('rules');
                editRule(null, {
                    type: btn.dataset.type || 'any',
                    method: 'any',
                    matchType: 'contains',
                    pattern: hostOf(btn.dataset.url),
                    action: 'block'
                });
            });
        });
    }

    /* --- Watch tags --- */
    function renderTags() {
        var host = overlay.querySelector('#fw-body-tags');
        host.innerHTML =
            '<p style="margin-top:0;color:#9aa4b2;font-size:12.5px">' +
                'Enter keywords (one per line). If a request contains any of them — anywhere in the ' +
                'URL, POST body, request headers or cookies, case-insensitive — the firewall pops up a ' +
                'prompt asking whether to <b>allow</b> or <b>block</b> it. Works in any mode.' +
            '</p>' +
            '<textarea class="fw-input" id="t-list" rows="10" placeholder="sessionid\ntracking\nfbclid\naffiliate_id">' +
                escapeHtml(TAGS.join('\n')) + '</textarea>' +
            '<label class="fw-ask-all" style="margin:12px 0 4px" title="Also match tags hidden behind common encodings">' +
                '<input type="checkbox" id="t-deep"' + (DEEPSCAN.enabled ? ' checked' : '') + '>' +
                ' <b>Deep scan</b> — also find tags that are <b>hidden or obscured</b> ' +
                '(percent / base64 / hex / unicode / HTML-entity encoded, or split apart by separators)' +
            '</label>' +
            '<div class="fw-row-actions" style="margin-top:10px">' +
                '<button class="fw-btn primary" id="t-save">Save tags</button>' +
                '<span style="align-self:center;color:#6b7480;font-size:11.5px">' + TAGS.length + ' tag(s) active. Per-page "block all" resets on reload.</span>' +
            '</div>';

        host.querySelector('#t-save').addEventListener('click', function () {
            TAGS = host.querySelector('#t-list').value.split('\n')
                .map(function (s) { return s.trim(); })
                .filter(function (s) { return s.length; });
            saveTags(TAGS);
            DEEPSCAN.enabled = host.querySelector('#t-deep').checked;
            saveDeepScan(DEEPSCAN.enabled);
            var b = host.querySelector('#t-save');
            b.textContent = 'Saved ✓';
            setTimeout(function () { var x = host.querySelector('#t-save'); if (x) x.textContent = 'Save tags'; }, 1200);
        });
    }

    /* --- Environment hardening (freeze built-ins) --- */
    function renderHardening() {
        var host = overlay.querySelector('#fw-body-harden');
        var applied = HARDENING_APPLIED.length;

        var status = HARDENING.enabled
            ? (applied
                ? '<span style="color:#8fe08f">● Active this page — ' + HARDENING.method + ' applied to ' + applied + ' target(s).</span>'
                : '<span style="color:#ffd479">● Enabled, but nothing frozen yet (reload the page to apply).</span>')
            : '<span style="color:#9aa4b2">○ Disabled.</span>';

        function group(title, list) {
            var boxes = list.map(function (t) {
                var checked = HARDENING.targets[t] ? ' checked' : '';
                var frozen = HARDENING_APPLIED.indexOf(t) !== -1
                    ? ' <span title="frozen on this page" style="color:#8fe08f">✓</span>' : '';
                return '<label style="display:flex;align-items:center;gap:6px;font-size:12px;color:#e6e6e6;padding:3px 0">' +
                    '<input type="checkbox" class="h-target" data-t="' + escapeHtml(t) + '"' + checked + '>' +
                    '<code>' + escapeHtml(t) + '</code>' + frozen + '</label>';
            }).join('');
            return '<fieldset style="border:1px solid #2c313a;border-radius:6px;padding:8px 12px;margin:0 0 12px">' +
                '<legend style="color:#9aa4b2;font-size:11.5px;padding:0 6px">' + title + '</legend>' +
                '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:2px 16px">' + boxes + '</div>' +
                '</fieldset>';
        }

        host.innerHTML =
            '<p style="margin-top:0;color:#9aa4b2;font-size:12.5px">' +
            'Freeze JavaScript built-ins <b>before the page\'s own scripts run</b>, so malicious or third-party code ' +
            'cannot pollute prototypes or patch native methods (<code>Object.freeze</code>-style tamper protection). ' +
            'Applied at <code>document-start</code>; changes take effect on the next page load.' +
            '</p>' +
            '<div style="margin-bottom:12px;font-size:12.5px">' + status + '</div>' +
            '<div class="fw-form-grid">' +
            '<label>Protection' +
            '<select class="fw-select" id="h-enabled">' +
            '<option value="on"' + (HARDENING.enabled ? ' selected' : '') + '>enabled</option>' +
            '<option value="off"' + (!HARDENING.enabled ? ' selected' : '') + '>disabled</option>' +
            '</select>' +
            '</label>' +
            '<label>Method' + sel('h-method', ['freeze', 'seal', 'preventExtensions'], HARDENING.method) + '</label>' +
            '</div>' +
            '<div style="display:flex;gap:8px;margin-bottom:10px">' +
            '<button class="fw-btn ghost mini" id="h-core">Select core only</button>' +
            '<button class="fw-btn ghost mini" id="h-all">Select all</button>' +
            '<button class="fw-btn ghost mini" id="h-none">Clear all</button>' +
            '</div>' +
            group('Core built-ins (recommended)', HARDEN_TARGETS.slice(0, 12)) +
            group('Extended built-ins', HARDEN_TARGETS.slice(12, 30)) +
            group('DOM prototypes (aggressive — may break sites)', HARDEN_TARGETS.slice(30)) +
            '<div class="fw-row-actions">' +
            '<button class="fw-btn primary" id="h-save">Save hardening</button>' +
            '<span style="align-self:center;color:#6b7480;font-size:11.5px">Reload the page after saving to freeze on load.</span>' +
            '</div>' +
            '<fieldset style="border:1px solid #2c313a;border-radius:6px;padding:8px 12px;margin:16px 0 0">' +
            '<legend style="color:#9aa4b2;font-size:11.5px;padding:0 6px">Page freeze</legend>' +
            '<p style="margin:4px 0 10px;color:#9aa4b2;font-size:12px">' +
            'After the delay, <b>block changes to the live page</b> (add/remove nodes, attribute &amp; innerHTML edits on connected elements) so the visible page can no longer mutate. ' +
            'Off-screen construction (e.g. framework templates) is left alone so pages don\'t crash. ' +
            'The firewall\'s own UI stays usable. ' + (frozen ? '<b style="color:#8fe08f">● Page is currently frozen.</b>' : '') +
            '</p>' +
            '<div class="fw-form-grid">' +
            '<label>Freeze this page' +
            '<select class="fw-select" id="z-enabled">' +
            '<option value="on"' + (FREEZE.enabled ? ' selected' : '') + '>enabled</option>' +
            '<option value="off"' + (!FREEZE.enabled ? ' selected' : '') + '>disabled</option>' +
            '</select>' +
            '</label>' +
            '<label>Delay (seconds)<input class="fw-input" id="z-delay" type="number" min="0" value="' + (FREEZE.delay) + '"></label>' +
            '</div>' +
            '<div class="fw-row-actions">' +
            '<button class="fw-btn primary" id="z-save">Save freeze</button>' +
            '<button class="fw-btn danger" id="z-now">Freeze now</button>' +
            '<span style="align-self:center;color:#6b7480;font-size:11.5px">Applies on next page load (or use “Freeze now”).</span>' +
            '</div>' +
            '</fieldset>';

        function setAll(list, val) {
            host.querySelectorAll('.h-target').forEach(function (cb) {
                if (!list || list.indexOf(cb.dataset.t) !== -1) cb.checked = val;
                else cb.checked = false;
            });
        }
        host.querySelector('#h-core').addEventListener('click', function () { setAll(HARDEN_CORE, true); });
        host.querySelector('#h-all').addEventListener('click', function () { setAll(null, true); });
        host.querySelector('#h-none').addEventListener('click', function () {
            host.querySelectorAll('.h-target').forEach(function (cb) { cb.checked = false; });
        });

        host.querySelector('#h-save').addEventListener('click', function () {
            var targets = {};
            host.querySelectorAll('.h-target').forEach(function (cb) {
                if (cb.checked) targets[cb.dataset.t] = true;
            });
            HARDENING.enabled = host.querySelector('#h-enabled').value === 'on';
            HARDENING.method = host.querySelector('#h-method').value;
            HARDENING.targets = targets;
            saveHardening(HARDENING);
            var b = host.querySelector('#h-save');
            b.textContent = 'Saved ✓ — reload to apply';
            setTimeout(function () { var x = host.querySelector('#h-save'); if (x) x.textContent = 'Save hardening'; }, 1600);
        });

        host.querySelector('#z-save').addEventListener('click', function () {
            FREEZE.enabled = host.querySelector('#z-enabled').value === 'on';
            FREEZE.delay = Math.max(0, parseInt(host.querySelector('#z-delay').value, 10) || 0);
            saveFreeze(FREEZE);
            var b = host.querySelector('#z-save');
            b.textContent = 'Saved ✓';
            setTimeout(function () { var x = host.querySelector('#z-save'); if (x) x.textContent = 'Save freeze'; }, 1200);
        });
        host.querySelector('#z-now').addEventListener('click', function () {
            freezeNow();
            renderHardening();
        });
    }

    /* --- JS source policy (white / black lists) --- */
    function renderPolicy() {
        var host = overlay.querySelector('#fw-body-js');
        host.innerHTML =
            '<p style="margin-top:0;color:#9aa4b2;font-size:12.5px">' +
            'Control which external JavaScript files are allowed to run on this page. ' +
            'One pattern per line — substring match, or use <code>*</code> / <code>?</code> wildcards against the full URL ' +
            '(e.g. <code>https://*.doubleclick.net/*</code>).' +
            '<br><b>Tip:</b> to block a single script, you can also add a rule on the Rules tab with type <code>script</code> — that works even with this policy set to <i>off</i>. ' +
            'The <b>Scripts loaded on this page</b> list below lets you create such rules in one click — including <b>Replace</b>, which loads a patched newer build (or a harmless stub) in place of the original.' +
            '</p>' +
            '<div class="fw-form-grid">' +
            '<label>Enforcement mode' + sel('p-mode', ['off', 'blacklist', 'whitelist'], POLICY.mode) + '</label>' +
            '<label>Trust same-origin scripts' +
            '<select class="fw-select" id="p-self">' +
            '<option value="yes"' + (POLICY.trustSelf ? ' selected' : '') + '>yes (recommended)</option>' +
            '<option value="no"' + (!POLICY.trustSelf ? ' selected' : '') + '>no</option>' +
            '</select>' +
            '</label>' +
            '<label class="full" id="p-wl-wrap">Whitelist — only these sources may run' +
            '<textarea class="fw-input" id="p-wl" rows="6" placeholder="https://code.jquery.com/*\nhttps://cdn.jsdelivr.net/*">' +
            escapeHtml(POLICY.whitelist.join('\n')) + '</textarea></label>' +
            '<label class="full" id="p-bl-wrap">Blacklist — these sources are blocked' +
            '<textarea class="fw-input" id="p-bl" rows="6" placeholder="*.doubleclick.net/*\n*google-analytics.com*">' +
            escapeHtml(POLICY.blacklist.join('\n')) + '</textarea></label>' +
            '</div>' +
            '<div class="fw-row-actions">' +
            '<button class="fw-btn primary" id="p-save">Save policy</button>' +
            '<span style="align-self:center;color:#6b7480;font-size:11.5px">Applies to scripts loaded after saving / reload.</span>' +
            '</div>' +
            '<hr style="border:none;border-top:1px solid #2c313a;margin:16px 0">' +
            '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">' +
            '<b style="font-size:13px">Scripts loaded on this page</b>' +
            '<button class="fw-btn ghost mini" id="p-js-refresh">Refresh</button>' +
            '</div>' +
            '<p style="margin:0 0 10px;color:#6b7480;font-size:11.5px">' +
            '<b>Replace</b> loads a patched/newer build (or a stub for ad scripts) in place of the original; ' +
            '<b>Block</b> stops it. Redirect works reliably for scripts inserted after page load — reload after saving the rule.' +
            '</p>' +
            '<div id="p-js-list"></div>';

        function toggleLists() {
            var mode = host.querySelector('#p-mode').value;
            host.querySelector('#p-wl-wrap').style.display = mode === 'whitelist' ? '' : 'none';
            host.querySelector('#p-bl-wrap').style.display = mode === 'blacklist' ? '' : 'none';
        }
        host.querySelector('#p-mode').addEventListener('change', toggleLists);
        toggleLists();

        host.querySelector('#p-save').addEventListener('click', function () {
            function lines(id) {
                return host.querySelector(id).value.split('\n')
                    .map(function (s) { return s.trim(); })
                    .filter(function (s) { return s.length; });
            }
            POLICY.mode = host.querySelector('#p-mode').value;
            POLICY.trustSelf = host.querySelector('#p-self').value === 'yes';
            POLICY.whitelist = lines('#p-wl');
            POLICY.blacklist = lines('#p-bl');
            savePolicy(POLICY);
            host.querySelector('#p-save').textContent = 'Saved ✓';
            setTimeout(function () {
                var b = host.querySelector('#p-save');
                if (b) b.textContent = 'Save policy';
            }, 1200);
        });

        // --- Loaded-scripts list: create block / replace(redirect) rules ---
        function renderList() {
            var listHost = host.querySelector('#p-js-list');
            if (!listHost) return;
            var list = collectLoadedJs();
            if (!list.length) {
                listHost.innerHTML = '<div class="fw-empty">No external scripts detected yet. Reload the page, then Refresh.</div>';
                return;
            }
            var rows = list.map(function (e) {
                var short = e.url.length > 78 ? e.url.slice(0, 75) + '…' : e.url;
                var badge = e.action === 'block' ? '<span class="fw-tag block">blocked</span>'
                    : e.action === 'replace' ? '<span class="fw-tag replace">redirected</span>'
                        : '<span class="fw-tag allow">loaded</span>';
                return '<tr>' +
                    '<td>' + badge + '</td>' +
                    '<td class="u" title="' + escapeHtml(e.url) + '"><span class="fw-url-short">' + escapeHtml(short) + '</span></td>' +
                    '<td><div class="fw-row-actions">' +
                    '<button class="fw-btn ghost mini js-replace" data-url="' + escapeHtml(e.url) + '">Replace…</button>' +
                    '<button class="fw-btn danger mini js-block" data-url="' + escapeHtml(e.url) + '">Block</button>' +
                    '</div></td>' +
                    '</tr>';
            }).join('');
            listHost.innerHTML =
                '<table class="fw-log"><thead><tr>' +
                '<th>Status</th><th>Script URL (' + list.length + ')</th><th></th>' +
                '</tr></thead><tbody>' + rows + '</tbody></table>';

            listHost.querySelectorAll('.js-block').forEach(function (b) {
                b.addEventListener('click', function () {
                    switchTab('rules');
                    editRule(null, { type: 'script', method: 'GET', matchType: 'exact', pattern: b.dataset.url, action: 'block' });
                });
            });
            listHost.querySelectorAll('.js-replace').forEach(function (b) {
                b.addEventListener('click', function () {
                    var to = window.prompt(
                        'Redirect this script to a new URL —\ne.g. a patched newer library build, or a harmless stub.\n\nOriginal:\n' +
                        b.dataset.url + '\n\nNew URL:', b.dataset.url);
                    if (!to || !to.trim()) return;
                    switchTab('rules');
                    editRule(null, {
                        type: 'script', method: 'GET', matchType: 'exact',
                        pattern: b.dataset.url, action: 'replace', replaceBody: to.trim()
                    });
                });
            });
        }
        host.querySelector('#p-js-refresh').addEventListener('click', renderList);
        renderList();
    }

    /* --- rule create / edit form --- */
    function editRule(index, seed) {
        var isNew = index == null;
        var r = isNew
            ? {
                id: newId(), enabled: true, name: (seed && seed.pattern) ? seed.pattern : '',
                type: (seed && seed.type) || 'any', method: (seed && seed.method) || 'any',
                matchType: (seed && seed.matchType) || 'contains', pattern: (seed && seed.pattern) || '',
                action: (seed && seed.action) || 'block',
                replaceBody: (seed && seed.replaceBody) || '', replaceStatus: 200
            }
            : JSON.parse(JSON.stringify(RULES[index]));

        var host = overlay.querySelector('#fw-body-rules');
        host.innerHTML =
            '<h3 style="margin-top:0">' + (isNew ? 'New rule' : 'Edit rule') + '</h3>' +
            '<div class="fw-form-grid">' +
            '<label class="full">Name<input class="fw-input" id="f-name" value="' + escapeHtml(r.name) + '"></label>' +
            '<label>Traffic type' + sel('f-type', ['any', 'xhr', 'fetch', 'script', 'iframe', 'image', 'media', 'stylesheet', 'websocket', 'beacon'], r.type) + '</label>' +
            '<label>Method' + sel('f-method', ['any', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'CONNECT', 'SEND'], r.method) + '</label>' +
            '<label>Match by' + sel('f-matchType', ['contains', 'exact', 'wildcard', 'regex'], r.matchType) + '</label>' +
            '<label>Action' + sel('f-action', ['block', 'alert', 'replace', 'log', 'allow'], r.action) + '</label>' +
            '<label class="full">URL pattern<input class="fw-input" id="f-pattern" placeholder="e.g. /api/track or *.doubleclick.net/*" value="' + escapeHtml(r.pattern) + '"></label>' +
            '<label class="full" id="f-replace-wrap"><span class="f-rep-label">Replacement response body</span><textarea class="fw-input" id="f-body" rows="4">' + escapeHtml(r.replaceBody || '') + '</textarea></label>' +
            '<label id="f-status-wrap">Replacement status<input class="fw-input" id="f-status" type="number" value="' + (r.replaceStatus || 200) + '"></label>' +
            '</div>' +
            '<div class="fw-row-actions">' +
            '<button class="fw-btn primary" id="f-save">Save rule</button>' +
            '<button class="fw-btn ghost" id="f-cancel">Cancel</button>' +
            '</div>';

        // For DOM-loaded resources a 'replace' rule redirects to a URL (newer
        // library build / stub); for xhr/fetch it synthesizes a response body.
        var RESOURCE_TYPES = ['script', 'iframe', 'image', 'media', 'stylesheet'];
        function toggleReplace() {
            var show = host.querySelector('#f-action').value === 'replace';
            var isResource = RESOURCE_TYPES.indexOf(host.querySelector('#f-type').value) !== -1;
            host.querySelector('#f-replace-wrap').style.display = show ? '' : 'none';
            host.querySelector('#f-status-wrap').style.display = (show && !isResource) ? '' : 'none';
            var lbl = host.querySelector('.f-rep-label');
            if (lbl) lbl.textContent = isResource
                ? 'Redirect to URL (blank = block) — e.g. a patched newer library build'
                : 'Replacement response body';
            var body = host.querySelector('#f-body');
            if (body) body.placeholder = isResource ? 'https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js' : '';
        }
        host.querySelector('#f-action').addEventListener('change', toggleReplace);
        host.querySelector('#f-type').addEventListener('change', toggleReplace);
        toggleReplace();

        host.querySelector('#f-cancel').addEventListener('click', renderRules);
        host.querySelector('#f-save').addEventListener('click', function () {
            r.name = host.querySelector('#f-name').value.trim();
            r.type = host.querySelector('#f-type').value;
            r.method = host.querySelector('#f-method').value;
            r.matchType = host.querySelector('#f-matchType').value;
            r.action = host.querySelector('#f-action').value;
            r.pattern = host.querySelector('#f-pattern').value;
            r.replaceBody = host.querySelector('#f-body').value;
            r.replaceStatus = parseInt(host.querySelector('#f-status').value, 10) || 200;

            if (!r.pattern && r.matchType !== 'regex') {
                alert('Please enter a URL pattern.');
                return;
            }
            if (isNew) RULES.push(r); else RULES[index] = r;
            saveRules(RULES);
            renderRules();
        });
    }

    function sel(id, opts, current) {
        return '<select class="fw-select" id="' + id + '">' + opts.map(function (o) {
            return '<option value="' + o + '"' + (o === current ? ' selected' : '') + '>' + o + '</option>';
        }).join('') + '</select>';
    }

    // Download the current rules as a .json file.
    function exportRules() {
        var data = JSON.stringify(RULES, null, 2);
        try {
            var d = new Date();
            var pad = function (n) { return (n < 10 ? '0' : '') + n; };
            var stamp = d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) +
                '-' + pad(d.getHours()) + pad(d.getMinutes());
            var blob = new Blob([data], { type: 'application/json' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.__fwUI = true;
            a.href = url;
            a.download = 'traffic-firewall-rules-' + stamp + '.json';
            (document.body || document.documentElement).appendChild(a);
            a.click();
            setTimeout(function () { try { a.remove(); } catch (e) { } URL.revokeObjectURL(url); }, 0);
        } catch (e) {
            // Fallback if Blob/download is unavailable: copy + prompt.
            try { navigator.clipboard && navigator.clipboard.writeText(data); } catch (e2) { }
            window.prompt('Copy your rules JSON:', data);
        }
    }

    // Import rules from a chosen .json file (replaces the current rules).
    function importRules() {
        var input = document.createElement('input');
        input.type = 'file';
        input.accept = 'application/json,.json';
        input.__fwUI = true;
        input.style.cssText = 'position:fixed;left:-9999px;top:0';
        input.addEventListener('change', function () {
            var file = input.files && input.files[0];
            if (!file) { try { input.remove(); } catch (e) { } return; }
            var reader = new FileReader();
            reader.onload = function () {
                try {
                    var parsed = JSON.parse(String(reader.result));
                    if (!Array.isArray(parsed)) throw new Error('expected an array of rules');
                    if (RULES.length && !confirm('Replace your ' + RULES.length +
                        ' current rule(s) with ' + parsed.length + ' imported rule(s)?')) {
                        return;
                    }
                    RULES = parsed;
                    saveRules(RULES);
                    switchTab('rules');
                    renderRules();
                } catch (e) {
                    alert('Invalid rules file: ' + e.message);
                } finally {
                    try { input.remove(); } catch (e) { }
                }
            };
            reader.onerror = function () { alert('Could not read the file.'); try { input.remove(); } catch (e) { } };
            reader.readAsText(file);
        });
        (document.body || document.documentElement).appendChild(input);
        input.click();
    }

    /* -------------------------------------------------------------------- */
    /*  Open / close + launchers                                             */
    /* -------------------------------------------------------------------- */
    function openModal() {
        if (!overlay) buildModal();
        overlay.classList.add('open');
        switchTab('rules');
        renderRules();
    }
    function closeModal() { if (overlay) overlay.classList.remove('open'); }

    function addFab() {
        var fab = document.createElement('button');
        fab.id = 'fw-fab';
        fab.__fwUI = true;
        fab.title = 'Traffic Firewall';
        fab.textContent = '🔥';
        fab.addEventListener('click', openModal);
        document.documentElement.appendChild(fab);
    }

    function boot() {
        addFab();
        scheduleFreeze();
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }

    if (typeof GM_registerMenuCommand === 'function') {
        GM_registerMenuCommand('Open Traffic Firewall', openModal);
        GM_registerMenuCommand('Mode: Disabled', function () { setMode('disabled'); });
        GM_registerMenuCommand('Mode: Normal (ask)', function () { setMode('normal'); });
        GM_registerMenuCommand('Mode: Learning (auto-rule)', function () { setMode('learning'); });
    }

    // Keyboard shortcut: Ctrl+Shift+F
    window.addEventListener('keydown', function (e) {
        if (e.ctrlKey && e.shiftKey && (e.key === 'F' || e.key === 'f')) {
            e.preventDefault();
            overlay && overlay.classList.contains('open') ? closeModal() : openModal();
        }
    });

    console.log('[Traffic Firewall] active — ' + RULES.length + ' rule(s). Ctrl+Shift+F or 🔥 button to configure.');
})();
