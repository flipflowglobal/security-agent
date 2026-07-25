#!/usr/bin/env node
// Generate app icon PNGs from the SVG source.
// Uses only Node.js built-ins — no native image libraries required.
// Produces electron/icon.png (256×256) used by electron-builder for all platforms.

'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const WIDTH = 256;
const HEIGHT = 256;

// ── Shield geometry ──────────────────────────────────────────────────────
// Returns true if (x,y) is inside the shield shape (normalised 0-1).
function inShield(nx, ny) {
    // Shield is symmetric about nx = 0.5
    var ax = Math.abs(nx - 0.5);
    // Top edge: flat until ~20%, then tapers
    // Side curve: parabolic taper from top to bottom point
    var t = ny; // 0 = top, 1 = bottom
    var halfWidth;
    if (t < 0.15) {
        halfWidth = 0.42; // flat top
    } else {
        // Quadratic taper to a point at t=1
        var s = (t - 0.15) / 0.85;
        halfWidth = 0.42 * (1 - s * s);
    }
    return ax < halfWidth && ny > 0.05 && ny < 0.95;
}

// Returns true if (x,y) is inside the checkmark
function inCheck(nx, ny) {
    // Checkmark is two line segments: short down-stroke + long up-stroke
    // Segment 1: (0.28, 0.52) → (0.38, 0.64)  — the V bottom
    // Segment 2: (0.38, 0.64) → (0.72, 0.38)  — the long stroke up
    var thickness = 0.045;

    function distToSeg(x, y, x1, y1, x2, y2) {
        var dx = x2 - x1, dy = y2 - y1;
        var lenSq = dx * dx + dy * dy;
        if (lenSq === 0) return Math.hypot(x - x1, y - y1);
        var t = Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / lenSq));
        var px = x1 + t * dx, py = y1 + t * dy;
        return Math.hypot(x - px, y - py);
    }

    return distToSeg(nx, ny, 0.28, 0.52, 0.38, 0.64) < thickness ||
           distToSeg(nx, ny, 0.38, 0.64, 0.72, 0.38) < thickness;
}

// ── PNG Encoder (raw, no deps) ──────────────────────────────────────────

function crc32(buf) {
    var table = new Int32Array(256);
    for (var n = 0; n < 256; n++) {
        var c = n;
        for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        table[n] = c;
    }
    var crc = -1;
    for (var i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
    return (crc ^ -1) >>> 0;
}

function chunk(type, data) {
    var len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    var typeData = Buffer.concat([Buffer.from(type), data]);
    var crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(typeData));
    return Buffer.concat([len, typeData, crc]);
}

function createPNG(width, height, rgba) {
    var sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

    var ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(width, 0);
    ihdr.writeUInt32BE(height, 4);
    ihdr[8] = 8;  // bit depth
    ihdr[9] = 6;  // color type: RGBA
    ihdr[10] = 0; // compression
    ihdr[11] = 0; // filter
    ihdr[12] = 0; // interlace

    // Prepend filter byte (0 = none) to each row
    var raw = Buffer.alloc(height * (1 + width * 4));
    for (var y = 0; y < height; y++) {
        raw[y * (1 + width * 4)] = 0; // filter: none
        rgba.copy(raw, y * (1 + width * 4) + 1, y * width * 4, (y + 1) * width * 4);
    }

    var compressed = zlib.deflateSync(raw, { level: 9 });

    return Buffer.concat([
        sig,
        chunk('IHDR', ihdr),
        chunk('IDAT', compressed),
        chunk('IEND', Buffer.alloc(0))
    ]);
}

// ── Render Shield Icon ───────────────────────────────────────────────────

function renderIcon(w, h) {
    var buf = Buffer.alloc(w * h * 4);

    for (var y = 0; y < h; y++) {
        for (var x = 0; x < w; x++) {
            var nx = x / w;
            var ny = y / h;
            var idx = (y * w + x) * 4;

            if (inShield(nx, ny)) {
                // Shield gradient: top #58a6ff → bottom #1f6feb
                var t = ny;
                var r = Math.round(88 + (31 - 88) * t);
                var g = Math.round(166 + (111 - 166) * t);
                var b = Math.round(255 + (235 - 255) * t);

                // Edge darkening
                var ax = Math.abs(nx - 0.5);
                var edgeDist = inCheck(nx, ny) ? 0 : 1;

                // Shield border
                var shieldT = ny;
                var halfW = shieldT < 0.15 ? 0.42 : 0.42 * (1 - Math.pow((shieldT - 0.15) / 0.85, 2));
                var edgeFactor = Math.max(0, 1 - Math.abs(ax - halfW) / 0.025);
                r = Math.round(r * (1 - edgeFactor * 0.4));
                g = Math.round(g * (1 - edgeFactor * 0.4));
                b = Math.round(b * (1 - edgeFactor * 0.4));

                // Checkmark: green
                if (inCheck(nx, ny)) {
                    r = 63; g = 185; b = 80;
                }

                buf[idx] = r;
                buf[idx + 1] = g;
                buf[idx + 2] = b;
                buf[idx + 3] = 255;
            } else {
                // Transparent background
                buf[idx] = 0;
                buf[idx + 1] = 0;
                buf[idx + 2] = 0;
                buf[idx + 3] = 0;
            }
        }
    }
    return buf;
}

// ── Main ─────────────────────────────────────────────────────────────────

var outDir = path.join(__dirname, '..', 'assets');
fs.mkdirSync(outDir, { recursive: true });

console.log('Generating ' + WIDTH + 'x' + HEIGHT + ' icon...');
var rgba = renderIcon(WIDTH, HEIGHT);
var png = createPNG(WIDTH, HEIGHT, rgba);
var outPath = path.join(outDir, 'icon.png');
fs.writeFileSync(outPath, png);
console.log('Wrote ' + outPath + ' (' + png.length + ' bytes)');

// Also generate a 1024x1024 for high-DPI / Mac
var S = 1024;
console.log('Generating ' + S + 'x' + S + ' icon...');
var rgbaLarge = renderIcon(S, S);
var pngLarge = createPNG(S, S, rgbaLarge);
var outPathLarge = path.join(outDir, 'icon-1024.png');
fs.writeFileSync(outPathLarge, pngLarge);
console.log('Wrote ' + outPathLarge + ' (' + pngLarge.length + ' bytes)');

console.log('Done. Icons ready for electron-builder.');
