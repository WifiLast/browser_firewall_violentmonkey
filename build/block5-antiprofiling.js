    /* ==================================================================== */
    /*  Anti-profiling — detect & (optionally) spoof fingerprinting surfaces */
    /*  Runs at document-start, before the page's own scripts, so the values  */
    /*  it shields are already in place the first time the page reads them.   */
    /* ==================================================================== */

    // Add tiny random noise to a canvas' pixels so its fingerprint differs on
    // every read (defeats stable canvas fingerprinting) without visibly changing
    // the image. Uses the ORIGINAL getImageData/putImageData captured before we
    // hook them.
    function fwCanvasNoise(canvas, origGID, origPID) {
        try {
            var ctx = canvas.getContext && canvas.getContext('2d');
            if (!ctx || !canvas.width || !canvas.height) return;
            var img = origGID.call(ctx, 0, 0, canvas.width, canvas.height);
            var d = img.data, n = Math.min(24, (d.length / 4) | 0);
            for (var i = 0; i < n; i++) {
                var p = ((Math.random() * (d.length / 4)) | 0) * 4;
                d[p] = d[p] ^ 1;   // flip the low bit of one channel
            }
            origPID.call(ctx, img, 0, 0);
        } catch (e) { }
    }

    function fwHookCanvas(win, protect) {
        var CE = win.HTMLCanvasElement, CTX = win.CanvasRenderingContext2D;
        var origGID = CTX && CTX.prototype.getImageData;
        var origPID = CTX && CTX.prototype.putImageData;
        if (CE) {
            ['toDataURL', 'toBlob'].forEach(function (m) {
                var orig = CE.prototype[m];
                if (typeof orig !== 'function') return;
                CE.prototype[m] = function () {
                    logProfile('canvas.' + m, protect);
                    if (protect && origGID && origPID) fwCanvasNoise(this, origGID, origPID);
                    return orig.apply(this, arguments);
                };
            });
            PROFILE_APPLIED.push('canvas');
        }
        if (CTX && origGID) {
            CTX.prototype.getImageData = function () {
                logProfile('canvas.getImageData', protect);
                var r = origGID.apply(this, arguments);
                if (protect && r && r.data) {
                    var d = r.data, n = Math.min(24, (d.length / 4) | 0);
                    for (var i = 0; i < n; i++) { var p = ((Math.random() * (d.length / 4)) | 0) * 4; d[p] = d[p] ^ 1; }
                }
                return r;
            };
        }
    }

    function fwHookWebGL(win, protect) {
        [win.WebGLRenderingContext, win.WebGL2RenderingContext].forEach(function (GL) {
            if (!GL || !GL.prototype || typeof GL.prototype.getParameter !== 'function') return;
            var gp = GL.prototype.getParameter;
            GL.prototype.getParameter = function (p) {
                if (p === 37445) { logProfile('webgl.vendor', protect); if (protect) return 'Google Inc.'; }        // UNMASKED_VENDOR_WEBGL
                if (p === 37446) { logProfile('webgl.renderer', protect); if (protect) return 'ANGLE (Generic, Generic, OpenGL)'; } // UNMASKED_RENDERER_WEBGL
                return gp.apply(this, arguments);
            };
            PROFILE_APPLIED.push('webgl');
        });
    }

    // Filter ICE candidates that expose private / host IPs, so WebRTC can't leak
    // the machine's local addresses. Media/data channels still work.
    function fwHookWebRTC(win, protect) {
        var RTC = win.RTCPeerConnection || win.webkitRTCPeerConnection;
        if (!RTC || !RTC.prototype || !protect) return;
        var priv = /(\b10\.\d+\.\d+\.\d+|\b127\.\d+\.\d+\.\d+|\b192\.168\.\d+\.\d+|\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|\b169\.254\.\d+\.\d+|[a-z0-9-]+\.local\b)/i;
        function isPrivate(cand) { return cand && priv.test(cand.candidate || ''); }
        function wrap(fn) {
            return function (ev) {
                if (ev && ev.candidate && isPrivate(ev.candidate)) { logProfile('webrtc.candidate', true); return; }
                return fn.apply(this, arguments);
            };
        }
        try {
            var _add = RTC.prototype.addEventListener;
            RTC.prototype.addEventListener = function (type, listener, opts) {
                if (type === 'icecandidate' && typeof listener === 'function') return _add.call(this, type, wrap(listener), opts);
                return _add.apply(this, arguments);
            };
            var desc = Object.getOwnPropertyDescriptor(RTC.prototype, 'onicecandidate');
            if (desc && desc.set) {
                Object.defineProperty(RTC.prototype, 'onicecandidate', {
                    configurable: true, enumerable: desc.enumerable, get: desc.get,
                    set: function (fn) { return desc.set.call(this, typeof fn === 'function' ? wrap(fn) : fn); }
                });
            }
            PROFILE_APPLIED.push('webrtc');
        } catch (e) { }
    }

    (function applyAntiProfiling() {
        if (!PROFILE.enabled) return;
        var protect = PROFILE.mode === 'protect';
        var V = PROFILE.vectors;
        var win = PAGE_WIN, nav = win.navigator, scr = win.screen;

        function mark(name) { if (PROFILE_APPLIED.indexOf(name) === -1) PROFILE_APPLIED.push(name); }
        // Install a logging getter that returns a spoofed value in protect mode.
        function shield(obj, prop, vector, spoofed) {
            if (!obj) return;
            var orig; try { orig = obj[prop]; } catch (e) { }
            try {
                Object.defineProperty(obj, prop, {
                    configurable: true,
                    get: function () {
                        logProfile(vector, protect);
                        if (!protect) return orig;
                        return typeof spoofed === 'function' ? spoofed() : spoofed;
                    }
                });
                mark(vector);
            } catch (e) { }
        }

        try {
            if (V.languages) {
                shield(nav, 'language', 'navigator.language', 'en-US');
                shield(nav, 'languages', 'navigator.languages', function () { return ['en-US', 'en']; });
            }
            if (V.hardware) {
                shield(nav, 'hardwareConcurrency', 'navigator.hardwareConcurrency', 4);
                if ('deviceMemory' in nav) shield(nav, 'deviceMemory', 'navigator.deviceMemory', 8);
            }
            if (V.platform) {
                shield(nav, 'platform', 'navigator.platform', 'Win32');
                shield(nav, 'vendor', 'navigator.vendor', '');
                if ('oscpu' in nav) shield(nav, 'oscpu', 'navigator.oscpu', 'Windows NT 10.0; Win64; x64');
            }
            if (V.screen && scr) {
                shield(scr, 'width', 'screen.width', 1920);
                shield(scr, 'height', 'screen.height', 1080);
                shield(scr, 'availWidth', 'screen.availWidth', 1920);
                shield(scr, 'availHeight', 'screen.availHeight', 1040);
                shield(scr, 'colorDepth', 'screen.colorDepth', 24);
                shield(scr, 'pixelDepth', 'screen.pixelDepth', 24);
                shield(win, 'devicePixelRatio', 'window.devicePixelRatio', 1);
            }
            if (V.plugins) {
                shield(nav, 'plugins', 'navigator.plugins',
                    { length: 0, item: function () { return null; }, namedItem: function () { return null; }, refresh: function () { } });
                shield(nav, 'mimeTypes', 'navigator.mimeTypes',
                    { length: 0, item: function () { return null; }, namedItem: function () { return null; } });
            }
            if (V.timezone) {
                try {
                    var RO = win.Intl && win.Intl.DateTimeFormat && win.Intl.DateTimeFormat.prototype.resolvedOptions;
                    if (RO) {
                        win.Intl.DateTimeFormat.prototype.resolvedOptions = function () {
                            var o = RO.apply(this, arguments);
                            logProfile('timezone', protect);
                            if (protect) { try { o.timeZone = 'UTC'; } catch (e) { } }
                            return o;
                        };
                        mark('timezone');
                    }
                    if (protect) {
                        var GTO = win.Date.prototype.getTimezoneOffset;
                        win.Date.prototype.getTimezoneOffset = function () { logProfile('timezone', true); return 0; };
                    }
                } catch (e) { }
            }
            if (V.canvas) fwHookCanvas(win, protect);
            if (V.webgl) fwHookWebGL(win, protect);
            if (V.webrtc) fwHookWebRTC(win, protect);
            // `extensions` vector is enforced in the request/resource firewall
            // (profileBlocksExt) rather than here.
            if (V.extensions) mark('extensions');
        } catch (e) {
            console.warn('[Traffic Firewall] anti-profiling failed', e);
        }

        if (PROFILE_APPLIED.length) {
            console.log('[Traffic Firewall] anti-profiling (' + PROFILE.mode + ') shielded: ' + PROFILE_APPLIED.join(', '));
        }
    })();

    /* --- Anti-profiling settings tab --- */
    function renderProfile() {
        var host = overlay && overlay.querySelector('#fw-body-profile');
        if (!host) return;

        var status = PROFILE.enabled
            ? (PROFILE_APPLIED.length
                ? '<span style="color:#8fe08f">● Active this page (' + PROFILE.mode + ') — ' + PROFILE_APPLIED.length + ' surface(s) shielded.</span>'
                : '<span style="color:#ffd479">● Enabled — reload the page to shield fingerprinting surfaces.</span>')
            : '<span style="color:#9aa4b2">○ Disabled.</span>';

        var VECTORS = [
            ['languages', 'Language & locale', 'navigator.language / languages'],
            ['hardware', 'CPU cores & memory', 'hardwareConcurrency / deviceMemory'],
            ['platform', 'Platform / vendor', 'navigator.platform / vendor / oscpu'],
            ['screen', 'Screen & pixel ratio', 'screen.* / devicePixelRatio'],
            ['plugins', 'Plugins & MIME types', 'navigator.plugins / mimeTypes → empty'],
            ['canvas', 'Canvas fingerprint', 'toDataURL / getImageData → per-read noise'],
            ['webgl', 'WebGL vendor / renderer', 'masked to a generic GPU'],
            ['timezone', 'Time zone', 'Intl / getTimezoneOffset → UTC (may shift dates)'],
            ['webrtc', 'WebRTC local-IP leak', 'drops private-IP ICE candidates'],
            ['extensions', 'Extension probing', 'blocks chrome-/moz-extension:// requests']
        ];
        var boxes = VECTORS.map(function (v) {
            var on = PROFILE.vectors[v[0]] ? ' checked' : '';
            return '<label style="display:flex;flex-direction:row;align-items:flex-start;gap:8px;font-size:12px;color:#e6e6e6;padding:4px 0">' +
                '<input type="checkbox" class="pf-v" data-v="' + v[0] + '"' + on + '>' +
                '<span><b>' + escapeHtml(v[1]) + '</b> — <span style="color:#9aa4b2">' + escapeHtml(v[2]) + '</span></span></label>';
        }).join('');

        host.innerHTML =
            '<p style="margin-top:0;color:#9aa4b2;font-size:12.5px">' +
            'Detect and, in <b>Protect</b> mode, spoof the browser signals sites use to fingerprint you. ' +
            'Applied at <code>document-start</code> before the page reads them — <b>reload to apply changes</b>. ' +
            'In <b>Detect</b> mode nothing is changed; accesses are just logged to the Activity Log.' +
            '</p>' +
            '<div style="margin-bottom:12px;font-size:12.5px">' + status + '</div>' +
            '<div class="fw-form-grid">' +
            '<label>Protection' +
            '<select class="fw-select" id="pf-enabled">' +
            '<option value="on"' + (PROFILE.enabled ? ' selected' : '') + '>enabled</option>' +
            '<option value="off"' + (!PROFILE.enabled ? ' selected' : '') + '>disabled</option>' +
            '</select></label>' +
            '<label>Mode' + sel('pf-mode', ['protect', 'detect'], PROFILE.mode) + '</label>' +
            '</div>' +
            '<div style="display:flex;gap:8px;margin-bottom:10px">' +
            '<button class="fw-btn ghost mini" id="pf-all">Select all</button>' +
            '<button class="fw-btn ghost mini" id="pf-none">Clear all</button>' +
            '</div>' +
            '<fieldset style="border:1px solid #2c313a;border-radius:6px;padding:8px 12px;margin:0 0 12px">' +
            '<legend style="color:#9aa4b2;font-size:11.5px;padding:0 6px">Surfaces</legend>' + boxes +
            '</fieldset>' +
            '<div class="fw-row-actions">' +
            '<button class="fw-btn primary" id="pf-save">Save anti-profiling</button>' +
            '<span style="align-self:center;color:#6b7480;font-size:11.5px">Reload the page after saving to apply. Time-zone / UA spoofing can change site behaviour.</span>' +
            '</div>';

        host.querySelector('#pf-all').addEventListener('click', function () {
            host.querySelectorAll('.pf-v').forEach(function (cb) { cb.checked = true; });
        });
        host.querySelector('#pf-none').addEventListener('click', function () {
            host.querySelectorAll('.pf-v').forEach(function (cb) { cb.checked = false; });
        });
        host.querySelector('#pf-save').addEventListener('click', function () {
            PROFILE.enabled = host.querySelector('#pf-enabled').value === 'on';
            PROFILE.mode = host.querySelector('#pf-mode').value === 'detect' ? 'detect' : 'protect';
            host.querySelectorAll('.pf-v').forEach(function (cb) { PROFILE.vectors[cb.dataset.v] = cb.checked; });
            saveProfile(PROFILE);
            var b = host.querySelector('#pf-save');
            b.textContent = 'Saved ✓ — reload to apply';
            setTimeout(function () { var x = host.querySelector('#pf-save'); if (x) x.textContent = 'Save anti-profiling'; }, 1600);
        });
    }
