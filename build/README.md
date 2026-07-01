# Build

The userscript is authored as four source blocks that are concatenated into the
final single-file script `../js_traffic_wachter.js`.

## Files

| File | Contents |
|------|----------|
| `header.txt` | The `// ==UserScript==` metadata block (name, @match, @grant, …) |
| `block1-core.js` | Storage helpers, environment hardening, Trusted-Types shim, config/state, rule engine |
| `block2-network.js` | Watch-tags, decision engine, ask-user prompt modal, XHR/fetch/WebSocket/beacon interception |
| `block3-resource-firewall.js` | JS-source white/black-list, script/iframe/img/media blocking & redirect (load a patched newer build / stub), loaded-script registry, DOM-mutation & page-freeze hooks |
| `block4-ui.js` | Styles, settings modal, tab renderers, rule editor, launchers, boot |
| `build.js` | Combiner — wraps header + blocks in one IIFE and writes the final script |

## Build

```sh
node build/build.js
```

This writes `js_traffic_wachter.js` in the repo root.

## Notes

- The four blocks share **one function scope** after concatenation, so they can
  freely reference each other's hoisted `function` declarations. Do **not** wrap
  a block in its own IIFE.
- Keep the block order in `build.js` — top-level statements (prototype hooks,
  `boot()`, freeze scheduling) execute in that sequence.
- Edit the blocks (and `header.txt`), never the generated `js_traffic_wachter.js`
  directly — it is overwritten on every build.
