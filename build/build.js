#!/usr/bin/env node
/*
 * Build script for the Browser Traffic Firewall userscript.
 *
 * Combines the metadata header and the four source blocks into the final
 * single-file userscript at ../js_traffic_wachter.js, wrapped in one IIFE.
 *
 * Usage:  node build/build.js        (run from the repo root, or anywhere)
 *
 * The blocks share one function scope after concatenation, so they may
 * reference each other's hoisted function declarations freely. Keep the
 * order below — top-level statements (hooks, boot) run in this sequence.
 */
'use strict';

var fs = require('fs');
var path = require('path');

var SRC_DIR = __dirname;                                   // the build/ folder
var OUT_FILE = path.join(SRC_DIR, '..', 'js_traffic_wachter.js');

// Ordered list of the four body blocks.
var BLOCKS = [
    'block1-core.js',              // storage, hardening, Trusted-Types shim, state, rule engine
    'block2-network.js',          // watch-tags, decision engine, prompt modal, XHR/fetch/WS/beacon
    'block3-resource-firewall.js',// JS-source policy, resource blocking, DOM-mutation & freeze hooks
    'block4-ui.js',               // styles, settings modal, renderers, launchers, boot
    'block5-antiprofiling.js'     // anti-fingerprinting hooks + settings tab
];

function read(name) {
    return fs.readFileSync(path.join(SRC_DIR, name), 'utf8');
}

function stripTrailingBlankLines(s) {
    return s.replace(/\s+$/, '');
}

function build() {
    var header = stripTrailingBlankLines(read('header.txt'));

    var body = BLOCKS.map(function (name) {
        var code = read(name);
        // Normalise line endings and trim surrounding blank lines so the
        // combined output has one clean blank line between blocks.
        return stripTrailingBlankLines(code.replace(/\r\n/g, '\n')).replace(/^\n+/, '');
    }).join('\n\n');

    var out =
        header + '\n\n' +
        '(function () {\n' +
        "    'use strict';\n\n" +
        body + '\n' +
        '})();\n';

    fs.writeFileSync(OUT_FILE, out, 'utf8');
    console.log('[build] wrote ' + path.relative(process.cwd(), OUT_FILE) +
        ' (' + out.split('\n').length + ' lines from ' + BLOCKS.length + ' blocks)');
}

build();
