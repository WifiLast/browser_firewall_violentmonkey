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
            '#fw-modal{background:#1e2127!important;color:#e6e6e6!important;width:min(1100px,96vw);max-width:96vw;max-height:88vh;border-radius:10px;box-shadow:0 12px 48px rgba(0,0,0,.6);display:flex;flex-direction:column;overflow:hidden}',
            '#fw-modal header{display:flex;align-items:center;gap:10px;padding:14px 18px;background:#12151a;border-bottom:1px solid #2c313a}',
            '#fw-modal header h2{margin:0;font-size:16px;font-weight:600;flex:1}',
            '#fw-modal header .fw-badge{font-size:11px;background:#2c313a;padding:2px 8px;border-radius:10px;color:#9aa4b2}',
            '.fw-tabs{display:flex;gap:4px;padding:8px 18px 0;background:#12151a}',
            '.fw-tab{padding:8px 14px;cursor:pointer;border:none;background:none;color:#9aa4b2;font-size:13px;border-bottom:2px solid transparent}',
            '.fw-tab.active{color:#fff;border-bottom-color:#4d8bf0}',
            '.fw-body{padding:16px 18px;overflow-y:auto;overflow-x:hidden;background:#1e2127!important;color:#e6e6e6!important}',
            '.fw-body table{width:100%;border-collapse:collapse;font-size:12.5px;table-layout:fixed;background:transparent!important}',
            '.fw-body th,.fw-body td{text-align:left;padding:6px 8px;border-bottom:1px solid #2c313a;vertical-align:top;overflow-wrap:anywhere;word-break:break-word;background:transparent!important;color:#e6e6e6!important}',
            '.fw-body th{color:#9aa4b2!important;font-weight:600;position:sticky;top:0;background:#1e2127!important}',
            '.fw-body code{background:#12151a!important;color:#cfe1ff!important;padding:1px 4px;border-radius:3px}',
            '.fw-input,.fw-select{background:#12151a!important;color:#e6e6e6!important;border:1px solid #2c313a;border-radius:5px;padding:6px 8px;font-size:12.5px;width:100%;box-sizing:border-box}',
            '.fw-select option{color:#e6e6e6!important;background:#1e2127!important}',
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
            '.fw-log tr.fw-log-detail>td{background:#171b21!important;color:#c7d0da!important;padding:8px 10px}',
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
            '<button class="fw-tab" data-tab="profile">Anti-Profiling</button>' +
            '<button class="fw-tab" data-tab="log">Activity Log</button>' +
            '</div>' +
            '<div class="fw-body" id="fw-body-rules"></div>' +
            '<div class="fw-body" id="fw-body-tags" style="display:none"></div>' +
            '<div class="fw-body" id="fw-body-js" style="display:none"></div>' +
            '<div class="fw-body" id="fw-body-harden" style="display:none"></div>' +
            '<div class="fw-body" id="fw-body-profile" style="display:none"></div>' +
            '<div class="fw-body" id="fw-body-log" style="display:none"></div>' +
            '<div class="fw-foot">' +
            '<button class="fw-btn primary" id="fw-add">+ Add rule</button>' +
            '<button class="fw-btn ghost" id="fw-export">Export</button>' +
            '<button class="fw-btn ghost" id="fw-import">Import</button>' +
            '<button class="fw-btn danger" id="fw-clearrules">Clear all rules</button>' +
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
        overlay.querySelector('#fw-clearrules').addEventListener('click', function () {
            if (RULES.length && confirm('Delete all ' + RULES.length + ' rule(s)? This cannot be undone.')) {
                RULES = [];
                saveRules(RULES);
                renderRules();
            }
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
        renderProfile();
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
        overlay.querySelector('#fw-body-profile').style.display = tab === 'profile' ? '' : 'none';
        overlay.querySelector('#fw-body-log').style.display = tab === 'log' ? '' : 'none';
        if (tab === 'log') renderLog();
        if (tab === 'tags') renderTags();
        if (tab === 'js') renderPolicy();
        if (tab === 'harden') renderHardening();
        if (tab === 'profile') renderProfile();
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
            '<div style="margin:10px 0 4px;display:flex;justify-content:space-between;align-items:center">' +
            '<span style="font-weight:600;font-size:13px">Parameter modifications</span>' +
            '<button class="fw-btn ghost" id="f-params-add" type="button">+ Add param</button>' +
            '</div>' +
            '<div id="f-params-list"></div>' +
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

        // --- Parameter modifications list ---
        var paramsList = (r.params || []).map(function (p) {
            return { name: p.name || '', op: p.op || 'remove', value: p.value || '' };
        });

        function renderParamRows() {
            var list = host.querySelector('#f-params-list');
            list.innerHTML = '';
            paramsList.forEach(function (p, i) {
                var row = document.createElement('div');
                row.style.cssText = 'display:flex;gap:4px;margin-bottom:4px;align-items:center';

                var nameIn = document.createElement('input');
                nameIn.className = 'fw-input';
                nameIn.style.flex = '1';
                nameIn.placeholder = 'param name';
                nameIn.value = p.name;
                nameIn.addEventListener('input', function () { paramsList[i].name = nameIn.value; });

                var opSel = document.createElement('select');
                opSel.className = 'fw-select';
                ['remove', 'set', 'add'].forEach(function (op) {
                    var opt = document.createElement('option');
                    opt.value = op; opt.textContent = op;
                    if (op === p.op) opt.selected = true;
                    opSel.appendChild(opt);
                });

                var valIn = document.createElement('input');
                valIn.className = 'fw-input';
                valIn.style.flex = '1';
                valIn.placeholder = 'value';
                valIn.value = p.value;
                valIn.style.display = p.op === 'remove' ? 'none' : '';
                valIn.addEventListener('input', function () { paramsList[i].value = valIn.value; });

                opSel.addEventListener('change', function () {
                    paramsList[i].op = opSel.value;
                    valIn.style.display = opSel.value === 'remove' ? 'none' : '';
                });

                var delBtn = document.createElement('button');
                delBtn.className = 'fw-btn danger';
                delBtn.textContent = '✕';
                delBtn.type = 'button';
                delBtn.addEventListener('click', function () { paramsList.splice(i, 1); renderParamRows(); });

                row.appendChild(nameIn);
                row.appendChild(opSel);
                row.appendChild(valIn);
                row.appendChild(delBtn);
                list.appendChild(row);
            });
        }

        renderParamRows();
        host.querySelector('#f-params-add').addEventListener('click', function () {
            paramsList.push({ name: '', op: 'remove', value: '' });
            renderParamRows();
        });
        // ------------------------------------

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
            r.params = paramsList.filter(function (p) { return p.name.trim(); });

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
