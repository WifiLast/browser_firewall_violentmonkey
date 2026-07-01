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

