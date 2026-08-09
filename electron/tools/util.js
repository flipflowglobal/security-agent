'use strict';
/**
 * Shared helpers for the Security-Agent native tool engine.
 * Every helper is dependency-free and works in Electron's main process.
 */

// ─── Byte / hex / encoding helpers ──────────────────────────────────────────

function hexToBytes(hex) {
    if (typeof hex !== 'string') return null;
    const clean = hex.replace(/\s+/g, '').replace(/^0x/i, '');
    if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) return null;
    const out = Buffer.alloc(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

function escapeLikeHex(str) {
    // Convert "\x90\x90" style strings into real bytes (best effort).
    return str.replace(/\\x([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
}

function formatMac(bytes) {
    if (!bytes || bytes.length < 6) return 'unknown';
    const parts = [];
    for (let i = 0; i < 6; i++) parts.push(bytes[i].toString(16).padStart(2, '0'));
    return parts.join(':');
}

// ─── Shannon entropy (bytes) ────────────────────────────────────────────────

function entropyOfBytes(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (const b of bytes) freq[b]++;
    let e = 0;
    const len = bytes.length;
    for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            const p = freq[i] / len;
            e -= p * Math.log2(p);
        }
    }
    return e;
}

function entropyOfString(str) {
    return entropyOfBytes(Buffer.from(String(str), 'utf8'));
}

// ─── Character class helpers ────────────────────────────────────────────────

function charsetClasses(str) {
    let upper = 0, lower = 0, digits = 0, symbols = 0, whitespace = 0, unicode = 0;
    for (const ch of String(str)) {
        const c = ch.codePointAt(0);
        if (c > 0x7f) unicode++;
        else if (/[A-Z]/.test(ch)) upper++;
        else if (/[a-z]/.test(ch)) lower++;
        else if (/[0-9]/.test(ch)) digits++;
        else if (/\s/.test(ch)) whitespace++;
        else symbols++;
    }
    return { upper, lower, digits, symbols, whitespace, unicode };
}

// ─── Human-readable size / time formatting ──────────────────────────────────

function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
    return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(ms) {
    if (ms < 1) return '<1 ms';
    if (ms < 1000) return `${ms} ms`;
    if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`;
    return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

// Crack-time formatting at a given guesses/sec throughput.
function crackTime(seconds) {
    if (seconds < 0.001) return 'instant';
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
    if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} minutes`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`;
    if (seconds < 31_536_000) return `${(seconds / 86400).toFixed(1)} days`;
    if (seconds < 31_536_000_000) return `${(seconds / 31_536_000).toFixed(1)} years`;
    if (seconds < 31_536_000_000_000) return `${(seconds / 31_536_000_000).toFixed(1)} thousand years`;
    if (seconds < 31_536_000_000_000_000) return `${(seconds / 31_536_000_000_000).toFixed(1)} million years`;
    return 'heat death of the universe+';
}

// ─── Probability / log helpers ──────────────────────────────────────────────

const LOG2 = Math.log(2);
function log2(n) { return Math.log(n) / LOG2; }

// ─── Randomness (crypto) ────────────────────────────────────────────────────

function cryptoRandom(min, max) {
    const range = max - min;
    if (range <= 0) return min;
    const bytes = new Uint32Array(1);
    require('crypto').randomFillSync(bytes);
    return min + (bytes[0] % range);
}

// ─── Text helpers ───────────────────────────────────────────────────────────

function truncate(str, max) {
    const s = String(str);
    return s.length <= max ? s : s.slice(0, max);
}

function slugify(str) {
    return String(str).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function safeJoin(items, sep = ', ') {
    return items.filter(Boolean).join(sep);
}

// ─── Structured result helpers ──────────────────────────────────────────────
// Native tools return { ok, engine, ms, view, title, subtitle, sections, raw }
// The renderer turns `sections` into rich HTML.

function kvSection(heading, pairs) {
    return { type: 'kv', heading, pairs };
}

function listSection(heading, items) {
    return { type: 'list', heading, items };
}

function tableSection(heading, columns, rows) {
    return { type: 'table', heading, columns, rows };
}

function codeSection(heading, code, language) {
    return { type: 'code', heading, code, language };
}

function badgeSection(heading, items) {
    return { type: 'badges', heading, items };
}

function result(view, title, subtitle, sections, raw, extra) {
    return Object.assign({ ok: true, view, title, subtitle, sections, raw }, extra || {});
}

module.exports = {
    hexToBytes, bytesToHex, escapeLikeHex, formatMac,
    entropyOfBytes, entropyOfString, charsetClasses,
    formatBytes, formatDuration, crackTime, log2,
    cryptoRandom, truncate, slugify, safeJoin,
    kvSection, listSection, tableSection, codeSection, badgeSection, result,
};
