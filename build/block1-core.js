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

    // Anti-profiling: detect and (optionally) spoof common browser-fingerprinting
    // surfaces — language/locale, CPU/RAM, platform, screen, plugins, canvas,
    // WebGL, time zone, WebRTC local IPs, and third-party extension probing.
    // Opt-in (off by default) since spoofing can subtly change site behaviour.
    var PROFILE_KEY = 'traffic_firewall_profile_v1';
    function defaultProfile() {
        return {
            enabled: false,
            mode: 'protect',   // 'protect' (spoof / block) | 'detect' (log only)
            vectors: {
                languages: true, hardware: true, platform: true, screen: true,
                plugins: true, canvas: true, webgl: true,
                timezone: false, webrtc: false, extensions: true
            }
        };
    }
    function loadProfile() {
        try {
            var raw = readStore(PROFILE_KEY, null);
            if (!raw) return defaultProfile();
            var p = JSON.parse(raw), d = defaultProfile(), v = {};
            for (var k in d.vectors) v[k] = (p.vectors && k in p.vectors) ? !!p.vectors[k] : d.vectors[k];
            return { enabled: !!p.enabled, mode: p.mode === 'detect' ? 'detect' : 'protect', vectors: v };
        } catch (e) { return defaultProfile(); }
    }
    function saveProfile(p) { writeStore(PROFILE_KEY, JSON.stringify(p)); }
    var PROFILE = loadProfile();
    var PROFILE_APPLIED = [];   // surfaces actually shielded this page (for the UI)
    var PROFILE_SEEN = {};      // dedupe so each surface is logged once per session

    // Log a fingerprinting-surface access. `spoofed` = we returned a fake value.
    function logProfile(vector, spoofed) {
        if (PROFILE_SEEN[vector]) return;
        PROFILE_SEEN[vector] = true;
        addLog({ type: 'profile', method: spoofed ? 'SPOOF' : 'READ', url: vector,
                 action: spoofed ? 'replace' : 'alert', ruleName: 'anti-profiling', body: '' });
    }
    function isExtScheme(url) {
        return /^\s*(chrome-extension|moz-extension|safari-web-extension):/i.test(String(url || ''));
    }
    // True when a request to an extension URL should be blocked to defeat
    // web-accessible-resource probing (a common extension-detection trick).
    function profileBlocksExt(url) {
        return PROFILE.enabled && PROFILE.mode === 'protect' && PROFILE.vectors.extensions && isExtScheme(url);
    }

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

