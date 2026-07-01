# Browser Traffic Watcher

A client-side network firewall userscript for **Violentmonkey** (and compatible managers such as Greasemonkey / Tampermonkey).  
It intercepts every outbound network request the page makes — XHR, Fetch, WebSocket, and `sendBeacon` — and lets you **block, alert, replace, or allow** them in real time using a persistent rule set and a built-in settings UI.

---

## Features

### Network interception
- Wraps `XMLHttpRequest`, `fetch`, `WebSocket`, and `navigator.sendBeacon` before any page script runs (`@run-at document-start`)
- Evaluates every request against your rule set before it leaves the browser
- **First-party trust** — same-origin requests are allowed by default so the firewall never breaks a site's own functionality (explicit rules still override this)

### Rule engine
- **Match strategies**: exact URL, substring contains, wildcard glob (`*` / `?`), or full regex
- **Traffic type filter**: any, XHR, fetch, WebSocket, or beacon
- **HTTP method filter**: any, GET, POST, PUT, PATCH, DELETE, …
- **Actions**:
  | Action | Behaviour |
  |--------|-----------|
  | `block` | Drop the request (return empty 200 or network error — your choice) |
  | `alert` | Pause and ask you whether to allow or block |
  | `replace` | Return a synthetic response with a custom body and status code |
  | `log` | Allow but record the request to the activity log |
  | `allow` | Explicitly permit (useful to carve exceptions inside a broader block rule) |
- Rules are saved persistently via `GM_setValue` (or `localStorage` as a fallback)

### Watch-tags
- Define keyword tags (e.g. your username, email, or any sensitive string)
- Any request whose URL, body, headers, or cookies contain a tag triggers an **ask-the-user prompt**
- **Deep-scan mode** (on by default) also catches tags that are hidden behind common encodings:
  - URL-encoding (single and double)
  - Base64 (including URL-safe variant)
  - Hex runs
  - `\uXXXX` / `\xXX` escape sequences
  - HTML numeric and named entities
  - Obfuscation via separators or zero-width characters

### JS-source policy
- Maintain a **whitelist** or **blacklist** of origins/URLs that are allowed to load and execute as `<script>` tags
- Three modes: `off` (disabled), `blacklist`, `whitelist`
- Optional "trust self-origin" toggle
- The **JS Sources tab** shows every external script the page has loaded, with its action and reason, so you can build rules from what you observe

### Resource redirect
- A `replace` rule whose replacement body is a URL **redirects** the resource rather than blocking it — e.g. swap a CDN script for a patched local build, or point an ad script at a harmless stub
- Works for scripts, iframes, images, media, and stylesheets

### Environment hardening
- Optionally `Object.freeze`, `seal`, or `preventExtensions` built-in prototypes **before** any page script runs
- Prevents the page from monkey-patching `Array.prototype`, `Function.prototype`, DOM prototypes, etc.
- Configurable target set (core JS intrinsics, extended types, DOM prototypes); off by default to avoid breaking sites

### Page freeze
- After a configurable delay, block all further DOM mutations on the live page
- Useful for inspecting a page's state without the site continuing to change it
- The firewall's own UI is always exempt from the freeze

### Operating modes
| Mode | Behaviour |
|------|-----------|
| `disabled` | Firewall is passive — rules are ignored, nothing is blocked or prompted |
| `normal` | Explicit rules apply; unmatched connections prompt the user |
| `learning` | Explicit rules apply; unmatched connections auto-create an allow rule |

### Activity log
- In-memory log of the last 500 requests with timestamp, method, URL, action, and body preview
- Expandable rows in the UI show the full URL and request body
- Click any log row to inspect or create a rule from it

### Settings UI
- Accessible via the Violentmonkey menu or a floating button (`🛡`)
- Tabbed interface: **Rules**, **Log**, **Tags**, **JS Sources**, **Settings**
- Dark-themed, responsive modal; works inside Trusted-Types-enforcing pages (e.g. Google)

---

## Installation

1. Install [Violentmonkey](https://violentmonkey.github.io/) (Firefox / Chrome / Edge)
2. Open Violentmonkey → **New script**
3. Paste the contents of `js_traffic_wachter.js` and save
4. The script activates automatically on every page (YouTube is excluded by default via `@exclude`)

---

## Building from source

The userscript is authored as four modular source blocks that are concatenated into the final single-file script by a small Node.js combiner.

```
build/
  header.txt              — UserScript metadata block
  block1-core.js          — Storage, hardening, Trusted-Types shim, config, rule engine
  block2-network.js       — Watch-tags, decision engine, prompt modal, XHR/fetch/WS/beacon hooks
  block3-resource-firewall.js — JS-source policy, resource redirect, DOM-mutation & page-freeze hooks
  block4-ui.js            — Styles, settings modal, tab renderers, rule editor, boot
  build.js                — Combiner — wraps everything in one IIFE
```

```sh
node build/build.js
```

This writes `js_traffic_wachter.js` in the repo root.

> **Note:** The four blocks share one function scope after concatenation so they can freely reference each other's hoisted declarations. Do not wrap a block in its own IIFE. Always edit the source blocks — the generated file is overwritten on every build.

---

## Usage overview

1. Click the **🛡** floating button (or use the Violentmonkey menu) to open the settings modal
2. Switch the **mode** from `disabled` to `normal` (or `learning` to auto-build an allow list)
3. Add rules on the **Rules** tab, or let the prompt ask you on first contact with each host
4. Add sensitive keywords on the **Tags** tab to be alerted any time they appear in a request
5. Review traffic on the **Log** tab; click a row to create a rule from it

---

## Limitations

Understanding what the firewall **cannot** do is just as important as knowing what it can.

| Limitation | Detail |
|---|---|
| **No browser-native requests** | Requests triggered by the browser itself — navigation (`<a>` clicks, form submissions, address-bar URLs), prefetch/preload hints, favicon fetches, HSTS checks — are never routed through JavaScript and therefore cannot be intercepted |
| **No cross-origin iframe isolation** | Each cross-origin `<iframe>` runs in its own JS realm. The script only injects into the top-level page (and same-origin frames); a third-party iframe's network calls are invisible to it |
| **No Web Worker / Service Worker coverage** | Workers run in a separate global scope. Requests made inside a `Worker`, `SharedWorker`, or `ServiceWorker` bypass the hooks entirely |
| **No response inspection for allowed requests** | The firewall sees the outbound request (URL, method, headers, body). It does **not** intercept or inspect the response body of requests it allows through |
| **No binary body decoding** | Request bodies sent as `ArrayBuffer`, `Blob`, or `FormData` are not decoded for watch-tag scanning; only string/JSON bodies are scanned |
| **JS-source policy cannot stop inline scripts** | The JS-source whitelist/blacklist only applies to external `<script src="…">` elements. Inline `<script>` blocks and `eval()` calls are not affected |
| **Scripts injected before document-start may escape** | Any script the browser pre-parses from the initial HTML response and executes before the userscript manager fires is beyond reach. In practice `@run-at document-start` is very early, but there is no absolute guarantee |
| **Page freeze stops DOM mutations, not JS execution** | After a freeze the page's JavaScript continues running; only attempts to mutate the live DOM are blocked. Timers, network calls, and in-memory state changes are unaffected |
| **Environment hardening can break sites** | Freezing built-in prototypes (`Object.prototype`, DOM prototypes, etc.) is an aggressive measure that some frameworks and libraries do not tolerate. It is off by default for this reason |
| **No TLS / packet-level visibility** | This is a JavaScript-layer tool. It sees what JS sees — URLs and serialisable bodies. It has no access to raw TCP streams, TLS handshakes, HTTP headers set by the browser internally, or traffic generated outside the tab |
| **Browser extension traffic is invisible** | Requests made by other browser extensions (including the userscript manager itself) do not pass through the page's JS context |

---

## Browser compatibility

Tested in Violentmonkey on **Firefox** and **Chromium-based browsers** (Chrome, Edge, Brave).  
Greasemonkey 4+ and Tampermonkey should also work; `GM_*` APIs are used where available with a `localStorage` fallback.

---

## License

MIT
