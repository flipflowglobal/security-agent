'use strict';
/**
 * Native tool: wireless
 * Wi-Fi security audit helpers. Exceeds Rust `wireless.rs` with real EAPOL
 * frame parsing (WPA/WPA2/WPA3 key handshake validation), WPS PIN checksum
 * (RFC 1006 / 802.11-2020 style), full deauth reason table, and AP/mode
 * fingerprinting guidance.
 */
const { register } = require('./registry');
const { kvSection, listSection, tableSection, codeSection } = require('./util');

// ─── EAPOL frame parsing ────────────────────────────────────────────────────

function hexToBytes(hex) {
    const h = (hex || '').replace(/\s+/g, '').toLowerCase();
    if (!/^([0-9a-f]{2})*$/.test(h)) return null;
    const out = [];
    for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.substr(i, 2), 16));
    return out;
}

function bytesToHex(b) {
    return b.map((x) => x.toString(16).padStart(2, '0')).join('');
}

function parseEapol(hex) {
    const b = hexToBytes(hex);
    if (!b) return { ok: false, error: 'Invalid hex (expect even-length hex string).' };
    if (b.length < 6) return { ok: false, error: 'Truncated: EAPOL frame is at least 6 bytes (version, type, length).' };

    const version = b[0];
    const eapolType = b[1];
    const length = (b[2] << 8) | b[3];
    let off = 4;
    let info = { version, eapolType, length, payloadLength: b.length - 4 };

    const typeNames = { 0: 'EAP-Packet', 1: 'EAPOL-Start', 2: 'EAPOL-Logoff', 3: 'EAPOL-Key', 4: 'EAPOL-Encapsulated-ASF-Alert' };
    info.typeName = typeNames[eapolType] || 'Unknown';

    // EAPOL-Key (type 3): descriptor follows immediately
    if (eapolType === 3 && b.length >= off + 3) {
        const descriptor = b[off];
        off += 1;
        if (descriptor === 2 || descriptor === 3) {
            // 802.1X-2004 / 802.11-2007 WPA2 key descriptor: 2-byte length follows descriptor
            const keyInfo = (b[off] << 8) | b[off + 1]; off += 2;
            const keyLength = (b[off] << 8) | b[off + 1]; off += 2;
            const replay = bytesToHex(b.slice(off, off + 8)); off += 8;
            const nonce = bytesToHex(b.slice(off, off + 32)); off += 32;
            const iv = bytesToHex(b.slice(off, off + 16)); off += 16;
            const rsc = bytesToHex(b.slice(off, off + 8)); off += 8;
            const id = bytesToHex(b.slice(off, off + 8)); off += 8;
            const mic = bytesToHex(b.slice(off, off + 16)); off += 16;
            const kdl = off + 2 <= b.length ? (b[off] << 8) | b[off + 1] : 0;
            off += 2;
            const keyData = bytesToHex(b.slice(off, off + Math.max(0, kdl)));

            const bits = keyInfo;
            // IEEE 802.11-2016 §12.7.2 Key Information bitfield:
            //  bits 0-2 Key Descriptor Version | 3 Key Type (1=pairwise) | 4-5 Key Index
            //  bit 6 Install | 7 Key ACK | 8 Key MIC | 9 Secure | 10 Error
            //  bit 11 Request | 12 Encrypted Key Data | 13 SMK Message | 14-15 Reserved
            const flags = [];
            const keyDesc = bits & 0x0007;
            const keyIndex = (bits >> 4) & 0x3;
            if (bits & 0x0008) flags.push('pairwise');
            else flags.push('group');
            if (bits & 0x0040) flags.push('install');
            if (bits & 0x0080) flags.push('ack');
            if (bits & 0x0100) flags.push('mic');
            if (bits & 0x0200) flags.push('secure');
            if (bits & 0x0400) flags.push('error');
            if (bits & 0x0800) flags.push('request');
            if (bits & 0x1000) flags.push('encrypted-key-data');
            if (bits & 0x2000) flags.push('SMK');
            const descNames = { 0: '0 (defined by AKM / WPA3-SAE)', 1: '1 (HMAC-MD5 / RC4, TKIP)', 2: '2 (HMAC-SHA1-128 / AES Key Wrap, CCMP)', 3: '3 (AES-128-CMAC, 802.11w)' };
            const cipherSuite = (bits >> 6) & 0x3;
            const cipherNames = { 0: 'None/Group', 1: 'TKIP', 2: 'CCMP', 3: 'GCMP' };

            info = Object.assign(info, {
                descriptor, keyInfo, keyInfoHex: '0x' + keyInfo.toString(16).padStart(4, '0'),
                flags, keyLength, replay, nonce, iv, rsc, id, mic,
                dataLength: kdl, dataHex: keyData,
                keyDescriptorVersion: keyDesc, keyDescriptorName: descNames[keyDesc] || ('Unknown (' + keyDesc + ')'),
                keyIndex, cipherSuite: cipherNames[cipherSuite] || 'Unknown',
            });
            // WPA (WPA1) uses descriptor 254 with TKIP
            if (descriptor === 254) info.keyDescriptorVersion = 1; // WPA1 RSN-less
        } else {
            info.descriptor = descriptor;
            info.note = 'Non-standard or WPA1 (descriptor 254) key frame; limited parse.';
        }
    }

    return { ok: true, info };
}

function analyzeEapol({ hex, ssid }) {
    const res = parseEapol(hex);
    if (!res.ok) return { ok: false, title: 'EAPOL Frame Analysis', subtitle: res.error, sections: [listSection('Error', [{ severity: 'high', text: res.error }])], raw: {} };

    const i = res.info;
    const rows = [
        ['EAPOL version', String(i.version)],
        ['Type', String(i.eapolType) + ' (' + (i.typeName || '') + ')'],
        ['Length', String(i.length) + ' bytes'],
    ];
    if (i.eapolType === 3) {
        rows.push(['Key descriptor', String(i.descriptor)]);
        rows.push(['Key Info', i.keyInfoHex + ' — flags: ' + (i.flags.join(', ') || 'none')]);
        if (i.keyLength !== undefined) rows.push(['Key Length', String(i.keyLength)]);
        if (i.keyDescriptorVersion !== undefined) rows.push(['Key Descriptor Ver', String(i.keyDescriptorVersion)]);
        if (i.cipherSuite !== undefined) rows.push(['Cipher suite', i.cipherSuite]);
        if (i.mic) rows.push(['MIC (present)', i.mic]);
        if (i.replay) rows.push(['Replay counter', i.replay]);
    }

    // Handshake step detection per 802.11-2016 (ACK/MIC/Install/Secure pattern)
    let phase = 'Unknown';
    if (i.eapolType === 3) {
        const ack = i.flags.includes('ack');
        const mic = i.flags.includes('mic');
        const install = i.flags.includes('install');
        const secure = i.flags.includes('secure');
        if (ack && !mic) phase = 'Msg 1/4 — AP -> STA (ANonce)';
        else if (!ack && mic && !install && !secure) phase = 'Msg 2/4 — STA -> AP (SNonce + MIC)';
        else if (ack && mic && install) phase = 'Msg 3/4 — AP -> STA (GTK delivered, encrypted)';
        else if (!ack && mic && !install && secure) phase = 'Msg 4/4 — STA -> AP (confirm)';
    }

    const sections = [
        kvSection('Frame summary', rows),
    ];
    if (phase !== 'Unknown') {
        sections.push(listSection('Handshake phase', [{ severity: 'info', text: phase }]));
        sections.push(kvSection('Key material hints', [
            ['ANonce captured?', i.nonce && i.nonce !== '0'.repeat(64) ? 'yes (msg1/2)' : 'not in this frame'],
            ['MIC verified?', i.flags.includes('mic') ? 'MIC present — offline crack possible with pcap' : 'no MIC in this frame'],
            ['Attack readiness', i.mic && ssid ? 'capture + SSID + PMKID/4-way handshake → aircrack-ng / hashcat -m 22000' : 'need full 4-way capture (msg1+2)' ],
        ]));
    }
    if (i.nonce && i.nonce !== '0'.repeat(64)) {
        sections.push(codeSection('Nonce', i.nonce, 'hex'));
        sections.push(codeSection('MIC (extract for cracking)', i.mic || 'absent', 'hex'));
    }
    sections.push(listSection('Guidance', [
        { severity: 'info', text: 'For WPA2 cracking: capture full 4-way handshake with bettercap/airodump-ng, then use hashcat -m 22000.' },
        { severity: 'info', text: 'For WPA3: handshake includes SAE; requires different attack (dictionary against SAE is impractical).' },
    ]));

    return { ok: true, title: 'EAPOL Frame Analysis', subtitle: phase, sections, raw: i };
}

// ─── WPS PIN checksum (RFC 1006 checksum, same as 802.11 WPS) ───────────────

function wpsChecksum(addr) {
    // addr: 7-digit (0-9999999) WPS PIN without checksum
    if (!/^\d{7}$/.test(addr)) return { ok: false, error: 'WPS PIN must be 7 digits (without checksum).' };
    let accum = 0;
    for (let i = 0; i < 7; i++) {
        accum += 3 * (i % 2 === 0 ? Number(addr[i]) : 0) + (i % 2 === 1 ? Number(addr[i]) : 0);
    }
    const checksum = (10 - (accum % 10)) % 10;
    return { ok: true, pin7: addr, checksum, pin8: addr + checksum };
}

function wpsAudit({ apCount, pinCount, bruteRate }) {
    // Brute-force estimates for WPS PIN (8-digit, 7+checksum, worst-case 10^7 attempts, ~half avg)
    const rate = Number(bruteRate) || 1000;
    const space = Math.pow(10, 7);
    const avgAttempts = Math.ceil(space / 2);
    const avgSeconds = avgAttempts / rate;
    const maxSeconds = space / rate;
    const fmt = (s) => {
        if (s < 60) return s.toFixed(0) + 's';
        if (s < 3600) return (s / 60).toFixed(1) + 'm';
        if (s < 86400) return (s / 3600).toFixed(1) + 'h';
        return (s / 86400).toFixed(1) + 'd';
    };
    return { ok: true, avgSeconds, maxSeconds, avgHuman: fmt(avgSeconds), maxHuman: fmt(maxSeconds), avgAttempts, maxAttempts: space };
}

function wps({ pin, apCount, bruteRate }) {
    if (pin) {
        const r = wpsChecksum(pin);
        if (!r.ok) return { ok: false, title: 'WPS PIN Analysis', subtitle: 'Invalid input', sections: [listSection('Error', [{ severity: 'high', text: r.error }])], raw: {} };
        return {
            ok: true, title: 'WPS PIN Analysis', subtitle: r.pin8 + ' (with checksum)',
            sections: [
                kvSection('PIN', [
                    ['7-digit PIN', r.pin7],
                    ['Checksum digit', String(r.checksum)],
                    ['Full 8-digit', r.pin8],
                ]),
                listSection('Note', [{ severity: 'info', text: 'Some routers (e.g. older D-Link/Netgear) derive PIN from MAC (default WPS PIN).' }]),
            ], raw: r,
        };
    }
    if (apCount) {
        const t = wpsAudit({ apCount: Number(apCount), bruteRate });
        const rows = [
            ['Average case (10^7/2)', t.avgHuman, '~' + t.avgAttempts.toExponential(0) + ' attempts'],
            ['Worst case (10^7)', t.maxHuman, '10^7 attempts'],
        ];
        return {
            ok: true, title: 'WPS Brute-force Audit', subtitle: 'Based on 8-digit WPS PIN space',
            sections: [
                kvSection('Attack config', [['Brute-force rate', bruteRate + ' PINs/sec'], ['APs in range', String(apCount)]]),
                tableSection('Time estimates', ['Scenario', 'Time', 'Attempts'], rows),
                listSection('Guidance', [
                    { severity: 'high', text: 'WPS (WPS-PBC / WPS-PIN) is unsafe: PIN space is 10^7, no lockout on many routers.' },
                    { severity: 'info', text: 'Use reaver -i wlan0 -b BSSID -c channel to test WPS PIN lockout.' },
                ]),
            ], raw: t,
        };
    }
    return { ok: false, title: 'WPS Analysis', subtitle: 'Nothing to do', sections: [listSection('Error', [{ severity: 'high', text: 'Provide --pin (7 digits) or --ap-count.' }])], raw: {} };
}

// ─── 802.11 deauth reason codes ─────────────────────────────────────────────

const DEAUTH_REASONS = [
    [1, 'Unspecified reason'],
    [2, 'Previous authentication no longer valid'],
    [3, 'Deauthenticated because sending station is leaving (or has left) IBSS or ESS'],
    [4, 'Disassociated due to inactivity'],
    [5, 'Disassociated because AP is unable to handle all currently associated stations'],
    [6, 'Class 2 frame received from nonauthenticated station'],
    [7, 'Class 3 frame received from nonassociated station'],
    [8, 'Disassociated because sending station is leaving (or has left) BSS'],
    [9, 'Station requesting (re)association is not authenticated with responding station'],
    [10, 'Disassociated because the information in the Power Capability element is unacceptable'],
    [11, 'Disassociated because the information in the Supported Channels element is unacceptable'],
    [12, 'Disassociated due to invalid information element'],
    [13, 'Disassociated because Message Integrity Code (MIC) is invalid'],
    [14, 'Disassociated because 4-Way Handshake times out'],
    [15, 'Disassociated because 4-Way Handshake information element is different from initial'],
    [16, 'Disassociated because an invalid Robust Security Network (RSN) element is present'],
    [17, 'Disassociated because the request is not authorized by the RSN establishment'],
    [18, 'Disassociated because the request is not authorized by the RSN establishment (other reason)'],
    [19, 'Disassociated because the 4-Way Handshake times out (IEEE 802.11w)'],
    [20, 'Disassociated because the 4-Way Handshake information element is different (IEEE 802.11w)'],
    [21, 'Disassociated because an invalid RSN element is present (IEEE 802.11w)'],
    [22, 'Disassociated because the request is not authorized (IEEE 802.11w)'],
    [23, 'Disassociated because the request is not authorized (IEEE 802.11w, other reason)'],
    [32, 'Disassociated due to unspecified QoS-related reason'],
    [33, 'Disassociated because QoS AP lacks sufficient bandwidth'],
    [34, 'Disassociated because excessive number of frames need to be acknowledged'],
    [35, 'Disassociated because excessive number of retransmissions'],
    [36, 'Disassociated because the station missed too many beacons'],
    [38, 'Disassociated because station is leaving ESS'],
    [39, 'Disassociated because station is leaving BSS'],
    [45, 'Disassociated because of a timeout on the BSS Transition Management Request'],
    [46, 'Disassociated due to 11k measurement timeout'],
];

function wireless({ mode, hex, ssid, pin, apCount, bruteRate, reason, security, encryption }) {
    switch (mode) {
        case 'eapol':
            return analyzeEapol({ hex, ssid });
        case 'wps':
            return wps({ pin, apCount, bruteRate });
        case 'deauth': {
            if (reason === undefined || reason === null || reason === '') {
                return {
                    ok: true, title: '802.11 Deauth Reason Codes', subtitle: 'Full table',
                    sections: [
                        tableSection('Reason codes', ['Code', 'Meaning'], DEAUTH_REASONS.map((r) => [String(r[0]), r[1]])),
                        listSection('Note', [{ severity: 'info', text: 'Commonly spoofed: 7 (Class 3 frame from nonassociated station) and 8 (leaving BSS).' }]),
                    ], raw: DEAUTH_REASONS,
                };
            }
            const n = Number(reason);
            const hit = DEAUTH_REASONS.filter((r) => r[0] === n);
            return {
                ok: true, title: '802.11 Deauth Reason Code', subtitle: 'Code ' + n,
                sections: [
                    kvSection('Reason', [['Code', String(n)], ['Meaning', hit.length ? hit[0][1] : 'Unknown / reserved']]),
                    listSection('Note', [{ severity: 'info', text: 'Deauth flooding uses codes 1, 7, 8 to force clients to reconnect (handshake capture).' }]),
                ], raw: hit.length ? hit[0] : null,
            };
        }
        case 'audit': {
            const rate = Number(bruteRate) || 1000;
            const t = wpsAudit({ apCount: Number(apCount) || 1, bruteRate: rate });
            const sections = [];
            if (ssid || security || encryption) {
                sections.push(kvSection('Target', [
                    ['ESSID', ssid || '—'],
                    ['Security', security || '—'],
                    ['Encryption', encryption || '—'],
                ]));
            }
            sections.push(kvSection('Checklist', [
                ['WPA3/WPA2', 'Prefer WPA3-SAE; disable WPA2-TKIP and WPA1'],
                ['WPS', 'Disable WPS-PIN (PBC only) — brute force: avg ' + t.avgHuman + ' at ' + rate + ' PINs/s'],
                ['Management frames', 'Enable 802.11w PMF (required for WPA3)'],
                ['Default creds', 'Change default admin password and SSID'],
                ['Guest network', 'Isolate guest VLAN from corporate SSID'],
            ]));
            sections.push(tableSection('WPS brute-force estimates', ['Scenario', 'Time', 'Attempts'], [
                ['Average case', t.avgHuman, t.avgAttempts.toExponential(0)],
                ['Worst case', t.maxHuman, '10^7'],
            ]));
            return {
                ok: true, title: 'Wi-Fi Security Audit', subtitle: 'Recommendations for ' + (apCount || '?') + ' APs',
                sections, raw: t,
            };
        }
        default:
            return {
                ok: false, title: 'Wireless Security', subtitle: 'Unknown mode',
                sections: [listSection('Modes', [{ severity: 'high', text: 'eapol | wps | deauth | audit' }])], raw: {},
            };
    }
}

register({
    id: 'wireless', name: 'Wireless Security', category: 'offensive', icon: '📡',
    description: 'EAPOL handshake analysis, WPS PIN checksum, deauth reason codes, Wi-Fi security audit.',
    run: wireless,
    modes: ['eapol', 'wps', 'deauth', 'audit'],
});

