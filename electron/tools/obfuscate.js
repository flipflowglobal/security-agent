'use strict';
/**
 * Native tool: obfuscate
 * PowerShell obfuscation + network evasion helpers. Exceeds Rust `evasion.rs`
 * (6 PS techniques) with 11 techniques, real UTF-16LE base64 encoding,
 * alias-aware obfuscation, plus fragmentation, IPID, IP checksum, and
 * subnet-aware decoy generation.
 */
const { register } = require('./registry');
const { kvSection, listSection, tableSection, codeSection } = require('./util');

const PS_ALIASES = {
    'invoke-expression': 'iex', 'get-content': 'gc', 'set-content': 'sc',
    'write-output': 'echo', 'where-object': 'where', 'foreach-object': 'foreach',
    'select-object': 'select', 'get-process': 'ps', 'stop-process': 'kill',
    'get-service': 'gsv', 'new-object': 'new', 'remove-item': 'del',
    'copy-item': 'cp', 'move-item': 'mv', 'invoke-webrequest': 'iwr',
    'invoke-command': 'icm', 'start-process': 'saps', 'out-string': 'oss',
    'get-item': 'gi', 'test-path': 'tp',
};

function caseRandomize(s, seed) {
    let out = '';
    let x = seed || 0x1234;
    for (const ch of s) {
        x = (x * 1103515245 + 12345) & 0x7fffffff;
        if (/[a-zA-Z]/.test(ch) && (x & 1) === 1) out += ch.toUpperCase();
        else out += ch;
    }
    return out;
}

function randomVar(seed) {
    let x = seed || 0xbeef;
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    const chars = 'abcdefghijklmnopqrstuvwxyz';
    let out = '';
    for (let i = 0; i < 5; i++) out += chars[(x >> (i * 3)) % 26];
    return '$' + out;
}

function tConcat(cmd) {
    let obf = '';
    let count = 0;
    for (let i = 0; i < cmd.length; i += 3) {
        obf += (count ? "+'" : "'") + cmd.slice(i, i + 3) + "'";
        count++;
    }
    return { technique: 'String concatenation', effectiveness: 'Medium', notes: 'Breaks static string matching.', output: '($s=' + obf + ');iex $s' };
}

function tCharcode(cmd) {
    return { technique: 'Character code assembly', effectiveness: 'Medium-High', notes: 'Rebuilds the command from char codes at runtime.', output: 'iex (' + Array.from(cmd).map((ch) => '[char]' + ch.charCodeAt(0)).join('+') + ") -join ''" };
}

function tReverse(cmd) {
    const rev = Array.from(cmd).reverse().join('');
    return { technique: 'String reversal with self-decode', effectiveness: 'High', notes: 'Self-decoding; very effective against static analysis.', output: "iex (-join ('" + rev + "'.ToCharArray() | ForEach-Object { [char]$_ } | Sort-Object { 1 }))" };
}

function tBase64Utf16(cmd) {
    return { technique: 'Base64 (UTF-16LE) - EncodedCommand', effectiveness: 'Medium', notes: 'Same encoding powershell.exe -EncodedCommand uses.', output: Buffer.from(cmd, 'utf16le').toString('base64') };
}

function tBase64Utf8(cmd) {
    const b64 = Buffer.from(cmd, 'utf8').toString('base64');
    return { technique: 'Base64 (UTF-8) decode+invoke', effectiveness: 'Low-Medium', notes: 'Common iex decode pattern; widely fingerprinted.', output: 'iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("' + b64 + '")))' };
}

function tTicks(cmd) {
    let out = '';
    for (let j = 0; j < cmd.length; j++) out += (/[a-zA-Z]/.test(cmd[j]) && j % 2 === 0) ? '`' + cmd[j] : cmd[j];
    return { technique: 'Tick (backtick) insertion', effectiveness: 'Low-Medium', notes: 'Breaks naive signature matching.', output: out };
}

function tCaseVar(cmd) {
    let out = caseRandomize(cmd, 0x51eb);
    out = out.replace(/\$env/g, randomVar(0x1111)).replace(/\$null/g, randomVar(0x2222)).replace(/\$true/g, randomVar(0x3333)).replace(/\$false/g, randomVar(0x4444));
    return { technique: 'Case randomization + variable renaming', effectiveness: 'Low', notes: 'Good as an extra layer.', output: out };
}

function tAlias(cmd) {
    let out = cmd;
    for (const [cmdlet, alias] of Object.entries(PS_ALIASES)) out = out.replace(new RegExp('\\b' + cmdlet + '\\b', 'gi'), alias);
    return { technique: 'Cmdlet -> alias substitution', effectiveness: 'Medium', notes: 'Replaces Invoke-Expression -> iex, Get-Content -> gc, etc.', output: out };
}

function tFormatString(cmd) {
    let out = cmd.replace(/([A-Za-z]{4,})/g, (m) => m.length <= 2 ? m : "'" + m[0] + '{0}' + m.slice(2) + "' -f '" + m[1] + "'");
    return { technique: 'Format-string tokenization', effectiveness: 'Medium-High', notes: 'Splits cmdlet names across -f placeholders.', output: out };
}

function tXor(cmd) {
    const key = 0x5a;
    const hex = Array.from(Buffer.from(cmd, 'utf8').map((b) => b ^ key)).map((b) => '0x' + b.toString(16).padStart(2, '0')).join(',');
    return { technique: 'XOR + runtime decode (0x5A)', effectiveness: 'High', notes: 'Encrypts at rest; runtime decrypt + invoke.', output: '$k=0x5A;iex (-join ([byte[]]@(' + hex + ') | %{ [char]($_ -bxor $k) }))' };
}

function tComment(cmd) {
    const comments = ['<# 0 #>', '<# x #>', '<# ... #>', '<# noop #>'];
    let out = '';
    for (let j = 0; j < cmd.length; j++) {
        out += cmd[j];
        if ((j + 1) % 5 === 0) out += comments[j % comments.length];
    }
    return { technique: 'Block-comment insertion', effectiveness: 'Low-Medium', notes: 'Injected <# #> comments break byte-signatures.', output: out };
}

const TECHNIQUES = [tConcat, tCharcode, tReverse, tBase64Utf16, tBase64Utf8, tTicks, tCaseVar, tAlias, tFormatString, tXor, tComment];

function obfuscatePs(cmd) {
    if (!cmd || !cmd.trim()) {
        return { ok: false, title: 'PowerShell Obfuscation', subtitle: 'No input provided', sections: [listSection('Error', [{ severity: 'high', text: 'Enter a PowerShell command.' }])], raw: {} };
    }
    const results = TECHNIQUES.map((fn) => fn(cmd));
    const sections = [
        kvSection('Input', [
            ['Command', cmd.length > 80 ? cmd.slice(0, 60) + '...' : cmd],
            ['Length', cmd.length + ' chars'],
            ['Techniques', String(results.length)],
        ]),
    ];
    for (const r of results) {
        sections.push(codeSection(r.technique + ' - ' + r.effectiveness, r.output, 'powershell'));
        sections.push(listSection(r.technique, [
            { severity: 'info', text: r.notes },
            { severity: 'info', text: 'Size: ' + cmd.length + ' -> ' + r.output.length + ' chars (' + (r.output.length / Math.max(1, cmd.length)).toFixed(1) + 'x)' },
        ]));
    }
    return {
        ok: true,
        title: 'PowerShell Obfuscation',
        subtitle: results.length + ' techniques applied',
        sections,
        raw: { original: cmd, results: results.map((r) => ({ technique: r.technique, output: r.output, effectiveness: r.effectiveness })) },
    };
}

// ─── Network evasion helpers (exceeds Rust evasion.rs) ─────────────────────

function randInt(seed, min, max) {
    let x = (seed || Date.now() % 0xffff) * 1103515245 + 12345;
    x = (x >>> 0) % (max - min + 1);
    return x + min;
}

function fragmentPayload(hex, fragSize) {
    const fsize = Math.max(8, Math.min(255, fragSize || 32));
    const bytes = hex.match(/[0-9a-fA-F]{2}/g) || [];
    const chunks = [];
    for (let i = 0; i < bytes.length; i += fsize) chunks.push(bytes.slice(i, i + fsize).join(''));
    return chunks;
}

function randomIpId(seed) {
    const id = randInt(seed, 0, 65535);
    return { decimal: id, hex: '0x' + id.toString(16).padStart(4, '0'), note: 'Random IP identification field (RFC 6864).' };
}

function ipChecksum(dataHex) {
    const bytes = dataHex.match(/[0-9a-fA-F]{2}/g) || [];
    if (bytes.length % 2 !== 0) return { ok: false, error: 'Hex data must contain an even number of bytes.' };
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) {
        const word = (parseInt(bytes[i], 16) << 8) | parseInt(bytes[i + 1], 16);
        sum += word;
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    }
    const checksum = (~sum) & 0xffff;
    return { ok: true, checksum: checksum, hex: checksum.toString(16).padStart(4, '0'), bytes: [(checksum >> 8) & 0xff, checksum & 0xff] };
}

function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) | Number(octet), 0) >>> 0;
}

function intToIpv4(int) {
    return [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join('.');
}

function subnetDecoys(ip, cidr, count) {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return { ok: false, error: 'Invalid IP address.' };
    if (cidr < 0 || cidr > 32) return { ok: false, error: 'Invalid CIDR (0-32).' };
    const n = Math.max(1, Math.min(50, count || 5));
    const mask = cidr === 0 ? 0 : (0xffffffff << (32 - cidr)) >>> 0;
    const base = ipv4ToInt(ip) & mask;
    const decoys = [];
    let seed = base;
    while (decoys.length < n) {
        seed = (seed * 1664525 + 1013904223) >>> 0;
        const candidate = base | (seed % (1 << Math.max(0, 32 - cidr)));
        const s = intToIpv4(candidate);
        if (s !== ip && !decoys.includes(s)) decoys.push(s);
    }
    return { ok: true, decoys: decoys, note: cidr + '-bit subnet: ' + intToIpv4(base) + '/ ' + intToIpv4(base | ((1 << (32 - cidr)) - 1)) };
}

function obfuscate({ mode, command, hex, fragsize, ip, cidr, count, seed }) {
    switch (mode) {
        case 'ps':
            return obfuscatePs(command);
        case 'fragment': {
            if (!hex) return { ok: false, title: 'Fragmentation', subtitle: 'No hex payload', sections: [listSection('Error', [{ severity: 'high', text: 'Provide --hex payload.' }])], raw: {} };
            const chunks = fragmentPayload(hex, Number(fragsize) || 32);
            const rows = chunks.map((c, i) => [String(i + 1), c.length / 2 + 'B', c]);
            return {
                ok: true, title: 'HTTP/Network Payload Fragmentation', subtitle: chunks.length + ' fragments of ' + (hex.length / 2) + ' bytes',
                sections: [
                    kvSection('Fragment plan', [['Total bytes', String(hex.length / 2)], ['Fragment size', (Number(fragsize) || 32) + ' bytes'], ['Fragments', String(chunks.length)], ['Evasion', 'Split across TCP segments / HTTP chunks to bypass IDS reassembly']]),
                    tableSection('Fragments', ['#', 'Size', 'Hex'], rows),
                    listSection('Notes', [{ severity: 'info', text: 'Send fragments with delay/random order; some NIDS only inspect first N bytes.' }]),
                ], raw: { fragments: chunks },
            };
        }
        case 'ipid': {
            const id = randomIpId(seed || 1);
            return {
                ok: true, title: 'Random IP ID Generation', subtitle: 'RFC 6864 compliant',
                sections: [
                    kvSection('IPID', [['Decimal', String(id.decimal)], ['Hex', id.hex], ['Note', id.note]]),
                    codeSection('Scapy usage', "send(IP(dst='target', id=" + id.decimal + ")/ICMP())", 'python'),
                ], raw: id,
            };
        }
        case 'checksum': {
            const res = ipChecksum(hex || '4500003c0000000040010000000000000a000001');
            if (!res.ok) return { ok: false, title: 'IP Checksum', subtitle: 'Bad input', sections: [listSection('Error', [{ severity: 'high', text: res.error }])], raw: {} };
            return {
                ok: true, title: 'IP Header Checksum', subtitle: 'Computed (ones-complement sum)',
                sections: [
                    kvSection('Result', [['Checksum', '0x' + res.hex], ['Bytes', '[' + res.bytes.join(', ') + ']']]),
                    listSection('Note', [{ severity: 'info', text: 'For IPv4 header only. Place at offset 10 (2 bytes).' }]),
                ], raw: res,
            };
        }
        case 'decoy': {
            if (!ip) return { ok: false, title: 'Decoy Traffic', subtitle: 'No target IP', sections: [listSection('Error', [{ severity: 'high', text: 'Provide --ip and --cidr.' }])], raw: {} };
            const res = subnetDecoys(ip, Number(cidr) || 24, Number(count) || 5);
            if (!res.ok) return { ok: false, title: 'Decoy Traffic', subtitle: 'Invalid input', sections: [listSection('Error', [{ severity: 'high', text: res.error }])], raw: {} };
            return {
                ok: true, title: 'Subnet Decoy Traffic', subtitle: res.decoys.length + ' decoy sources for ' + ip,
                sections: [
                    kvSection('Plan', [['Target', ip], ['Subnet', res.note], ['Decoys', res.decoys.join(', ')]]),
                    listSection('Usage', [{ severity: 'info', text: 'Spoof ICMP/TCP probes from decoys before real traffic to poison source-based filters.' }]),
                ], raw: res,
            };
        }
        default:
            return {
                ok: false, title: 'Obfuscation & Evasion', subtitle: 'Unknown mode',
                sections: [listSection('Modes', [{ severity: 'high', text: 'ps | fragment | ipid | checksum | decoy' }])], raw: {},
            };
    }
}

register({
    id: 'obfuscate', name: 'Obfuscation & Evasion', category: 'offensive', icon: '🎭',
    description: 'PowerShell obfuscation (11 techniques), payload fragmentation, random IPID, IP checksum, decoy traffic.',
    run: obfuscate,
    modes: ['ps', 'fragment', 'ipid', 'checksum', 'decoy'],
});

