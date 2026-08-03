#!/usr/bin/env node
// Generate a multi-size Windows .ico from the shield renderer.
// Pure Node.js built-ins — writes BMP-based 32-bit entries at
// 16/24/32/48/64/128/256 so NSIS and Windows accept it everywhere.

'use strict';

const fs = require('fs');
const path = require('path');

// ── Shield geometry (same as generate-icons.js) ───────────────────────────

function inShield(nx, ny) {
    var ax = Math.abs(nx - 0.5);
    var t = ny;
    var halfWidth;
    if (t < 0.15) {
        halfWidth = 0.42;
    } else {
        var s = (t - 0.15) / 0.85;
        halfWidth = 0.42 * (1 - s * s);
    }
    return ax < halfWidth && ny > 0.05 && ny < 0.95;
}

function inCheck(nx, ny) {
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

// RGBA (top-down) buffer for a given size.
function renderIcon(w, h) {
    var buf = Buffer.alloc(w * h * 4);
    for (var y = 0; y < h; y++) {
        for (var x = 0; x < w; x++) {
            var nx = x / w;
            var ny = y / h;
            var idx = (y * w + x) * 4;
            if (inShield(nx, ny)) {
                var t = ny;
                var r = Math.round(88 + (31 - 88) * t);
                var g = Math.round(166 + (111 - 166) * t);
                var b = Math.round(255 + (235 - 255) * t);
                var shieldT = ny;
                var halfW = shieldT < 0.15 ? 0.42 : 0.42 * (1 - Math.pow((shieldT - 0.15) / 0.85, 2));
                var ax = Math.abs(nx - 0.5);
                var edgeFactor = Math.max(0, 1 - Math.abs(ax - halfW) / 0.025);
                r = Math.round(r * (1 - edgeFactor * 0.4));
                g = Math.round(g * (1 - edgeFactor * 0.4));
                b = Math.round(b * (1 - edgeFactor * 0.4));
                if (inCheck(nx, ny)) {
                    r = 63; g = 185; b = 80;
                }
                buf[idx] = r; buf[idx + 1] = g; buf[idx + 2] = b; buf[idx + 3] = 255;
            } else {
                buf[idx] = 0; buf[idx + 1] = 0; buf[idx + 2] = 0; buf[idx + 3] = 0;
            }
        }
    }
    return buf;
}

// ── ICO encoder ───────────────────────────────────────────────────────────

// Build one 32-bit BMP-based ICO image (bottom-up BGRA + empty AND mask).
function icoImageData(w, h, rgbaTopDown) {
    var header = Buffer.alloc(40);
    header.writeUInt32LE(40, 0);      // biSize
    header.writeInt32LE(w, 4);        // biWidth
    // biHeight: spec says XOR+AND (h*2); several strict parsers (makensis,
    // some icon libs) expect the plain bitmap height (h). ICO_BH=h switches.
    var bh = process.env.ICO_BH === 'h' ? h : h * 2;
    header.writeInt32LE(bh, 8);
    header.writeUInt16LE(1, 12);      // biPlanes
    header.writeUInt16LE(32, 14);     // biBitCount
    header.writeUInt32LE(0, 16);      // biCompression (BI_RGB)
    header.writeUInt32LE(w * h * 4, 20); // biSizeImage

    // XOR data: bottom-up rows, each pixel BGRA
    var xor = Buffer.alloc(w * h * 4);
    for (var y = 0; y < h; y++) {
        var srcRow = (h - 1 - y) * w * 4;
        var dstRow = y * w * 4;
        for (var x = 0; x < w; x++) {
            var si = srcRow + x * 4;
            var di = dstRow + x * 4;
            xor[di] = rgbaTopDown[si + 2];     // B
            xor[di + 1] = rgbaTopDown[si + 1]; // G
            xor[di + 2] = rgbaTopDown[si];     // R
            xor[di + 3] = rgbaTopDown[si + 3]; // A
        }
    }

    // AND mask: 1bpp, each row padded to 32 bits; all 0 (alpha is in XOR)
    var andRowBytes = Math.ceil(w / 32) * 4;
    var and = Buffer.alloc(andRowBytes * h);

    return Buffer.concat([header, xor, and]);
}

function createIco(sizes) {
    var images = sizes.map(function (s) {
        return { size: s, data: icoImageData(s, s, renderIcon(s, s)) };
    });

    // Single buffer: ICONDIR (6 bytes) followed by one 16-byte entry per image.
    var headerSize = 6 + images.length * 16;
    var header = Buffer.alloc(headerSize);
    header.writeUInt16LE(0, 0);              // reserved
    header.writeUInt16LE(1, 2);              // type: icon
    header.writeUInt16LE(images.length, 4);  // count

    var offset = headerSize;
    images.forEach(function (img, i) {
        var base = 6 + i * 16;
        header[base] = img.size === 256 ? 0 : img.size;      // width (0 = 256)
        header[base + 1] = img.size === 256 ? 0 : img.size;  // height (0 = 256)
        header[base + 2] = 0;  // palette
        header[base + 3] = 0;  // reserved
        header.writeUInt16LE(1, base + 4);               // planes
        header.writeUInt16LE(32, base + 6);              // bpp
        header.writeUInt32LE(img.data.length, base + 8); // bytesInRes
        header.writeUInt32LE(offset, base + 12);         // imageOffset
        offset += img.data.length;
    });

    return Buffer.concat([header].concat(images.map(function (i) { return i.data; })));
}

// ── Main ─────────────────────────────────────────────────────────────────

var outPath = path.join(__dirname, '..', 'assets', 'icon.ico');
var sizes = [16, 24, 32, 48, 64, 128, 256];
if (process.argv[2]) {
    sizes = process.argv[2].split(',').map(Number);
    outPath = path.join(__dirname, '..', 'assets', 'icon-' + sizes.join('-') + '.ico');
}
var ico = createIco(sizes);
fs.writeFileSync(outPath, ico);
console.log('Wrote ' + outPath + ' (' + ico.length + ' bytes, sizes=' + sizes.join(',') + ')');
