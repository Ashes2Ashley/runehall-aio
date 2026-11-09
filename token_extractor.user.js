// ==UserScript==
// @name         Runehall AIO Token Extractor
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Capture & copy your own staging auth JWTs (kwbk666 / daygun) for feeding into the AIO pentest harness. Staging-only, your own accounts.
// @author       Red Ops
// @match        *://staging.runehall.com/*
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function () {
    'use strict';

    // Known test accounts to label captured tokens by.
    const KNOWN_USERS = []; // add your own staging test usernames here, e.g. ['userA','userB']
    // Config keys the harness expects.
    const CONFIG_SLOT = { kwbk666: 'USER_A_JWT', daygun: 'USER_B_JWT' };

    const captured = {}; // username -> { token, source }
    let anonCount = 0;

    // ---- JWT decode (no verification; display only) ----
    function b64urlDecode(s) {
        try {
            s = s.replace(/-/g, '+').replace(/_/g, '/');
            s += '='.repeat((4 - (s.length % 4)) % 4);
            return decodeURIComponent(atob(s).split('').map(c =>
                '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
        } catch (e) { return null; }
    }
    function decodeJwt(tok) {
        if (typeof tok !== 'string' || tok.split('.').length !== 3) return null;
        const p = b64urlDecode(tok.split('.')[1]);
        if (!p) return null;
        try { return JSON.parse(p); } catch (e) { return null; }
    }
    function looksLikeJwt(v) {
        return typeof v === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
    }
    function usernameFromPayload(pl) {
        if (!pl) return null;
        for (const k of ['username', 'user', 'name', 'preferred_username', 'login', 'sub', 'email']) {
            if (pl[k] != null) return String(pl[k]);
        }
        return null;
    }

    function record(token, source) {
        if (!looksLikeJwt(token)) return;
        const pl = decodeJwt(token);
        let who = usernameFromPayload(pl);
        // Match against known usernames (substring, case-insensitive).
        let label = null;
        if (who) {
            const lw = who.toLowerCase();
            label = KNOWN_USERS.find(u => lw.includes(u.toLowerCase())) || who;
        }
        if (!label) label = 'account_' + (++anonCount);
        if (captured[label] && captured[label].token === token) return;
        captured[label] = { token, source, payload: pl };
        render();
    }

    // ---- Harvest from storage ----
    function harvestStorage() {
        [['localStorage', window.localStorage], ['sessionStorage', window.sessionStorage]].forEach(([name, store]) => {
            try {
                for (let i = 0; i < store.length; i++) {
                    const k = store.key(i);
                    const v = store.getItem(k);
                    if (looksLikeJwt(v)) record(v, name + "['" + k + "']");
                    else if (v && v[0] === '{') {
                        // token may be nested in a JSON blob
                        try {
                            const o = JSON.parse(v);
                            for (const kk in o) if (looksLikeJwt(o[kk])) record(o[kk], name + "['" + k + "']." + kk);
                        } catch (e) {}
                    }
                }
            } catch (e) {}
        });
    }
    function harvestCookies() {
        try {
            document.cookie.split(';').forEach(c => {
                const idx = c.indexOf('=');
                if (idx < 0) return;
                const k = c.slice(0, idx).trim();
                const v = decodeURIComponent(c.slice(idx + 1).trim());
                if (looksLikeJwt(v)) record(v, "cookie['" + k + "']");
            });
        } catch (e) {}
    }

    // ---- Hook network for Authorization bearer tokens ----
    const origFetch = window.fetch;
    window.fetch = function (...args) {
        try {
            const init = args[1] || {};
            const h = init.headers;
            let auth = null;
            if (h instanceof Headers) auth = h.get('Authorization') || h.get('authorization');
            else if (h && typeof h === 'object') auth = h.Authorization || h.authorization;
            if (auth && /^Bearer\s+/i.test(auth)) record(auth.replace(/^Bearer\s+/i, ''), 'fetch Authorization header');
        } catch (e) {}
        return origFetch.apply(this, args);
    };
    const origSet = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.setRequestHeader = function (k, v) {
        try {
            if (typeof k === 'string' && k.toLowerCase() === 'authorization' && /^Bearer\s+/i.test(v))
                record(v.replace(/^Bearer\s+/i, ''), 'XHR Authorization header');
        } catch (e) {}
        return origSet.apply(this, arguments);
    };

    // ---- UI ----
    let panel, body;
    function buildPanel() {
        if (!document.body) return setTimeout(buildPanel, 200);
        panel = document.createElement('div');
        panel.style.cssText = 'position:fixed;bottom:20px;left:20px;width:380px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:8px;padding:14px;z-index:999999;font-family:monospace;font-size:12px;box-shadow:0 0 20px rgba(0,0,0,.8);';
        panel.innerHTML =
            '<h3 style="margin:0 0 8px;color:#3fb950;border-bottom:1px solid #30363d;padding-bottom:6px;">AIO Token Extractor</h3>' +
            '<div id="tok-body" style="max-height:260px;overflow-y:auto;"></div>' +
            '<div style="display:flex;gap:5px;margin-top:8px;">' +
            '<button id="tok-rescan" style="flex:1;background:#58a6ff;color:#000;border:none;padding:5px;border-radius:4px;cursor:pointer;">Rescan</button>' +
            '<button id="tok-config" style="flex:1;background:#d29922;color:#000;border:none;padding:5px;border-radius:4px;cursor:pointer;">Copy config</button>' +
            '</div>';
        document.body.appendChild(panel);
        body = panel.querySelector('#tok-body');
        panel.querySelector('#tok-rescan').onclick = rescan;
        panel.querySelector('#tok-config').onclick = copyConfig;
        render();
    }
    function copy(text, btn) {
        navigator.clipboard.writeText(text).then(() => {
            if (btn) { const t = btn.textContent; btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = t, 1200); }
        }).catch(() => {});
    }
    function copyConfig() {
        const lines = Object.entries(captured).map(([label, o]) => {
            const slot = CONFIG_SLOT[label] || (label.toUpperCase() + '_JWT');
            return slot + ' = "' + o.token + '"';
        });
        copy(lines.join('\n'), panel.querySelector('#tok-config'));
    }
    function render() {
        if (!body) return;
        const labels = Object.keys(captured);
        if (!labels.length) { body.innerHTML = '<div style="color:#8b949e;">No token yet. Log in, then Rescan.</div>'; return; }
        body.innerHTML = '';
        labels.forEach(label => {
            const o = captured[label];
            const slot = CONFIG_SLOT[label] ? ' → ' + CONFIG_SLOT[label] : '';
            const known = KNOWN_USERS.includes(label);
            const row = document.createElement('div');
            row.style.cssText = 'border:1px solid #30363d;border-radius:4px;padding:6px;margin-bottom:6px;background:#161b22;';
            row.innerHTML =
                '<div style="color:' + (known ? '#3fb950' : '#58a6ff') + ';font-weight:bold;">' + label + slot + '</div>' +
                '<div style="color:#8b949e;font-size:11px;margin:2px 0;">' + o.source + '</div>' +
                '<div style="word-break:break-all;color:#79c0ff;font-size:11px;margin-bottom:4px;">' + o.token.slice(0, 48) + '…</div>';
            const btn = document.createElement('button');
            btn.textContent = 'Copy token';
            btn.style.cssText = 'background:#238636;color:#fff;border:none;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:11px;';
            btn.onclick = () => copy(o.token, btn);
            row.appendChild(btn);
            body.appendChild(row);
        });
    }
    function rescan() { harvestStorage(); harvestCookies(); render(); }

    // Boot
    buildPanel();
    rescan();
    // Re-scan periodically to catch post-login tokens.
    setInterval(rescan, 3000);
})();
