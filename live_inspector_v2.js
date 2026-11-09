// ==UserScript==
// @name         Max AIO Live Inspector v2.0
// @namespace    http://tampermonkey.net/
// @version      2.0
// @description  Advanced Live Pentest Dashboard for SPAs
// @author       Red Ops
// @match        *://staging.runehall.com/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    const panel = document.createElement('div');
    panel.style.cssText = 'position:fixed; bottom:20px; right:20px; width:350px; background:#0d1117; color:#c9d1d9; border:1px solid #30363d; border-radius:8px; padding:15px; z-index:99999; font-family:monospace; font-size:12px; box-shadow:0 0 20px rgba(0,0,0,0.8);';
    panel.innerHTML = `
        <h3 style="margin:0 0 10px;color:#f85149;border-bottom:1px solid #30363d;padding-bottom:5px;">Max AIO Inspector</h3>
        <div style="margin-bottom:10px;">
            <span style="color:#58a6ff;">Endpoints:</span> <span id="ep-count">0</span> | 
            <span style="color:#d29922;">WS:</span> <span id="ws-count">0</span>
        </div>
        <div id="inspector-output" style="max-height:150px; overflow-y:auto; border:1px solid #30363d; padding:5px; margin-bottom:10px; background:#010409;"></div>
        <div style="display:flex; gap:5px; flex-wrap:wrap;">
            <button id="btn-xss" style="background:#d29922; color:#000; border:none; padding:5px; border-radius:4px; cursor:pointer; flex:1;">Fuzz XSS</button>
            <button id="btn-storage" style="background:#58a6ff; color:#000; border:none; padding:5px; border-radius:4px; cursor:pointer; flex:1;">Dump Storage</button>
            <button id="btn-clear" style="background:#30363d; color:#c9d1d9; border:none; padding:5px; border-radius:4px; cursor:pointer; flex:1;">Clear Log</button>
        </div>
    `;
    document.body.appendChild(panel);
    
    const output = document.getElementById('inspector-output');
    let epCount = 0, wsCount = 0;

    function log(msg, color = '#c9d1d9') {
        const div = document.createElement('div');
        div.style.color = color;
        div.innerHTML = `> ${msg}`;
        output.appendChild(div);
        output.scrollTop = output.scrollHeight;
    }

    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
        const url = args[0];
        if (typeof url === 'string' && (url.includes('/api/') || url.includes('/graphql'))) {
            epCount++; document.getElementById('ep-count').textContent = epCount;
            log(`API: ${url.substring(0, 50)}...`, '#58a6ff');
        }
        return originalFetch(...args);
    };

    const OriginalWS = window.WebSocket;
    window.WebSocket = function(url, protocols) {
        wsCount++; document.getElementById('ws-count').textContent = wsCount;
        log(`WS: ${url}`, '#d29922');
        const ws = new OriginalWS(url, protocols);
        ws.addEventListener('message', (e) => log(`WS Msg: ${String(e.data).substring(0, 40)}...`, '#e3b341'));
        return ws;
    };
    window.WebSocket.prototype = OriginalWS.prototype;

    document.getElementById('btn-storage').onclick = () => {
        log('--- LocalStorage ---', '#58a6ff');
        for (let i = 0; i < localStorage.length; i++) {
            let k = localStorage.key(i);
            let v = localStorage.getItem(k);
            if (/(token|auth|jwt|key|secret)/i.test(k)) log(`WARN ${k} = ${String(v).substring(0,24)}...`, '#f85149');
            else log(`${k} = ${String(v).substring(0,24)}...`);
        }
    };

    document.getElementById('btn-xss').onclick = async () => {
        const payload = '<img src=x onerror=alert("XSS")>';
        const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea');
        log(`Found ${inputs.length} input fields.`, '#58a6ff');
        for (let input of inputs) {
            input.value = payload;
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
            if (input.form) {
                try { input.form.submit(); } catch(e) {}
            } else {
                input.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', keyCode: 13, bubbles: true}));
            }
            log(`Fuzzed: ${input.name || input.id || 'unnamed'}`, '#d29922');
        }
        log('XSS Fuzzing complete. Check for alerts.', '#3fb950');
    };

    document.getElementById('btn-clear').onclick = () => {
        output.innerHTML = '';
        epCount = 0; wsCount = 0;
        document.getElementById('ep-count').textContent = 0;
        document.getElementById('ws-count').textContent = 0;
    };

    log('Inspector v2.0 loaded. Monitoring...', '#3fb950');
})();
