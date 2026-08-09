'use strict';
/**
 * Native tool: password-strength
 *
 * zxcvbn-style password strength analysis. Exceeds the Rust
 * `analyze_password_strength` (which only counts character classes) by:
 *   - evaluating actual *guessability* via pattern matching (dictionary,
 *     sequences, repeats, keyboard walks, l33t, dates, years),
 *   - scoring against three attack speeds (online, GPU, cluster),
 *   - NIST 800-63-3 guidelines check, and
 *   - per-pattern explanations of why the password is weak.
 */

const { register } = require('./registry');
const { kvSection, listSection, tableSection, crackTime } = require('./util');

// ─── Common password dictionary (top ~600) ────────────────────────────────
const COMMON = new Set([
    '123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111',
    '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein',
    'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael',
    '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe',
    'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster',
    'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', 'charlie',
    'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', '112233', 'george',
    'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111',
    '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger',
    'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', '696969',
    'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas',
    'austin', 'thunder', 'taylor', 'matrix', 'william', 'corvette', 'hello', 'martin',
    'heather', 'secret', 'merlin', 'diamond', '1234qwer', 'gfhjkm', 'hammer', 'silver',
    '222222', '88888888', 'anthony', 'justin', 'test', 'bailey', 'q1w2e3r4t5', 'patrick',
    'internet', 'scooter', 'orange', '11111', 'golfer', 'cookie', 'richard', 'samantha',
    'bigdog', 'guitar', 'jackson', 'whatever', 'mickey', 'chicken', 'sparky', 'snoopy',
    'maverick', 'phoenix', 'camaro', 'sexy', 'peanut', 'morgan', 'welcome', 'falcon',
    'cowboy', 'ferrari', 'samsung', 'andrea', 'smokey', 'steelers', 'joseph', 'mercedes',
    'dakota', 'arsenal', 'eagles', 'melissa', 'boomer', 'booboo', 'spider', 'nascar',
    'monster', 'tigers', 'yellow', 'xxxxxx', '123123123', 'gateway', 'marina', 'diablo',
    'bulldog', 'qwer1234', 'compaq', 'purple', 'hardcore', 'banana', 'junior', 'hannah',
    '123654', 'porsche', 'lakers', 'iceman', 'money', 'cowboys', '987654', 'london',
    'tennis', '999999', 'ncc1701', 'coffee', 'scooby', '0000', 'miller', 'boston',
    'q1w2e3r4', 'brandon', 'yamaha', 'chester', 'mother', 'forever', 'johnny', 'edward',
    '333333', 'oliver', 'redsox', 'mickey1', 'victoria', '123456a', 'poohbear', 'metallic',
    'gandalf', 'jesus', '1q2w3e4r', 'ashley1', 'qwerty123', 'whatever1', 'scorpion',
    'kitten', 'marley', 'mybaby', 'metallica', 'admin', 'blahblah', 'qwerty1', 'corona',
    'hello123', 'mountain', 'charlie1', 'passw0rd', 'admin123', 'winter', 'summer1',
    'daddy', 'shadow1', 'princess1', 'monkey1', 'mustang1', 'super123', 'test123',
    'qazwsxedc', '1q2w3e', 'qweasd', 'zaq12wsx', 'zxc123', 'asd123', 'abc12345',
    '123456789a', 'a123456', 'a12345', 'q123456', 'password1', 'password123', 'admin1',
    'iloveyou1', 'letmein1', 'welcome1', 'shadow123', 'dragon1', 'baseball1',
    'football1', 'hunter2', 'abc1234', 'qwer123', 'asdf1234', 'zxcv1234', 'welcome123',
    'passw0rd1', 'changeme', 'guest', 'root', 'toor', 'system', 'user', 'test1',
    'default', 'temp', 'temp123', 'demo', 'demo123', 'login', 'passwd', 'p@ssw0rd',
    'P@ssw0rd', 'Password1', 'Password123', 'Welcome1', 'Summer2020', 'Winter2021',
    'Spring2019', 'Autumn2018', 'qwertyuiop1', 'poiuytrewq', 'mnbvcxz', 'lkjhgfdsa',
    '1a2b3c4d', 'a1b2c3d4', 'z1x2c3v4', 'q1w2e3', '1qazxsw2', 'zaqxswcde', '2wsx3edc',
]);

// Keyboard adjacency graph (qwerty rows).
const KEY_ROWS = [
    ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
    ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'],
    ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'],
    ['z', 'x', 'c', 'v', 'b', 'n', 'm'],
];
const KEY_POS = new Map();
KEY_ROWS.forEach((row, r) => row.forEach((k, c) => KEY_POS.set(k, [r, c])));

function isAdjacent(a, b) {
    const pa = KEY_POS.get(a);
    const pb = KEY_POS.get(b);
    if (!pa || !pb) return false;
    const dr = Math.abs(pa[0] - pb[0]);
    const dc = Math.abs(pa[1] - pb[1]);
    return (dr === 0 && dc <= 1) || (dr === 1 && dc <= 1);
}

function isSequence3(a, b, c) {
    const ca = a.charCodeAt(0), cb = b.charCodeAt(0), cc = c.charCodeAt(0);
    if ((cb === ca + 1 && cc === cb + 1) || (cb === ca - 1 && cc === cb - 1)) return true;
    if (a === '8' && b === '9' && c === '0') return true;
    if (a === '0' && b === '9' && c === '8') return true;
    return false;
}

const L33T = {
    '4': 'a', '@': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g', '9': 'g', '1': 'l',
    '!': 'i', '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't', '2': 'z',
};

function l33tNormalize(s) {
    let out = '';
    for (const ch of s) out += L33T[ch] || ch;
    return out;
}

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

function findWeaknesses(pw, lower) {
    const weaknesses = [];
    const seen = new Set();
    const add = (text, severity) => {
        if (!seen.has(text)) { seen.add(text); weaknesses.push({ text, severity }); }
    };

    // 1. Dictionary match (with l33t / suffix tolerance)
    if (COMMON.has(pw)) add('Exact match in common password list', 'high');
    else {
        const l33t = l33tNormalize(lower);
        if (COMMON.has(l33t)) add('Matches a common password after l33t-substitution', 'high');
        const suffixes = ['123', '1234', '12345', '123456', '!', '@', '1', '0', '!1', '123!', '2020', '2021', '2022', '2023', '2024', '2025', '2026'];
        for (const suffix of suffixes) {
            if (l33t.endsWith(suffix)) {
                const base = l33t.slice(0, -suffix.length);
                if (base && COMMON.has(base)) { add('Common base password + predictable suffix "' + suffix + '"', 'high'); break; }
            }
        }
    }

    // 2. Sequences
    let seqLen = 0;
    for (let i = 0; i + 2 < lower.length; i++) {
        if (isSequence3(lower[i], lower[i + 1], lower[i + 2])) {
            let j = i + 3;
            while (j < lower.length && lower.charCodeAt(j) === lower.charCodeAt(j - 1) + 1) { seqLen = Math.max(seqLen, j - i + 1); j++; }
            while (j < lower.length && lower.charCodeAt(j) === lower.charCodeAt(j - 1) - 1) { seqLen = Math.max(seqLen, j - i + 1); j++; }
        }
    }
    if (seqLen >= 3) add('Contains ' + seqLen + '-char sequential run (abc/123)', 'medium');

    // 3. Repeats
    let repLen = 0;
    for (let i = 0; i + 1 < lower.length; i++) {
        if (lower[i] === lower[i + 1]) {
            let j = i + 2;
            while (j < lower.length && lower[j] === lower[i]) j++;
            repLen = Math.max(repLen, j - i);
            i = j - 1;
        }
    }
    if (repLen >= 3) add(repLen + ' identical chars in a row', 'medium');
    if (repLen === 2 && lower.length >= 8) add('Repeated character pair', 'low');

    // 4. Keyboard walks
    let kbLen = 0;
    for (let i = 0; i + 2 < lower.length; i++) {
        if (isAdjacent(lower[i], lower[i + 1]) && isAdjacent(lower[i + 1], lower[i + 2])) {
            let j = i + 3;
            while (j < lower.length && isAdjacent(lower[j - 1], lower[j])) j++;
            kbLen = Math.max(kbLen, j - i);
        }
    }
    if (kbLen >= 4) add(kbLen + '-key keyboard run (qwerty adjacent)', 'medium');

    // 5. Years / dates
    const yearMatch = lower.match(/19\d\d|20\d\d/);
    if (yearMatch) add('Contains year "' + yearMatch[0] + '" - first guess class for birthdays', 'medium');
    const dateMatch = lower.match(/(0?[1-9]|1[0-2])[\/\-.](0?[1-9]|[12][0-9]|3[01])[\/\-.](19|20)\d\d/);
    if (dateMatch) add('Contains a full date (MM/DD/YYYY)', 'high');
    for (const m of MONTHS) {
        if (lower.includes(m)) { add('Contains month name "' + m + '"', 'low'); break; }
    }

    // 6. Structural
    if (pw.length < 8) add('Too short (under 8 chars) - trivial offline brute force', 'high');
    if (pw.length < 12) add('Under 12 chars - below modern minimum-length guidance', 'medium');

    const classes = { upper: /[A-Z]/.test(pw), lower: /[a-z]/.test(pw), digit: /\d/.test(pw), symbol: /[^A-Za-z0-9]/.test(pw) };
    const used = Object.values(classes).filter(Boolean).length;
    if (used === 1) add('Single character class', 'medium');
    if (used === 2 && pw.length < 14) add('Only two character classes and short length', 'low');

    if (/^[\d]+$/.test(pw) && pw.length >= 5) add('All digits - pure numeric space', 'high');
    if (/^[a-z]+$/.test(pw) && pw.length >= 6) add('All lowercase letters - dictionary space', 'medium');
    if (/^[A-Z][a-z]+\d+!?$/.test(pw)) add('Common "Capital+lowercase+digits" template', 'medium');
    if (pw.length > 0 && new Set(pw).size <= pw.length * 0.4) add('Low character diversity', 'low');

    return weaknesses;
}

function estimateGuesses(pw) {
    const n = pw.length;
    const classes = { upper: /[A-Z]/.test(pw), lower: /[a-z]/.test(pw), digit: /\d/.test(pw), symbol: /[^A-Za-z0-9]/.test(pw) };
    let charset = 0;
    if (classes.lower) charset += 26;
    if (classes.upper) charset += 26;
    if (classes.digit) charset += 10;
    if (classes.symbol) charset += 33;

    const lower = pw.toLowerCase();
    let base = Math.pow(Math.max(charset, 2), n);

    // Pattern-aware boost: dictionary content makes a password far easier to guess.
    let dictBonus = 1;
    for (const w of COMMON) {
        if (lower.includes(w) && w.length >= 4) {
            dictBonus *= Math.pow(10, Math.min(w.length, 8) / 3);
            break;
        }
    }
    if (lower.length >= 4) {
        let kb = 0;
        for (let i = 0; i + 2 < lower.length; i++) {
            if (isAdjacent(lower[i], lower[i + 1]) && isAdjacent(lower[i + 1], lower[i + 2])) kb = Math.max(kb, 3);
        }
        if (kb) dictBonus *= 100;
    }
    for (let i = 0; i + 2 < lower.length; i++) {
        if (isSequence3(lower[i], lower[i + 1], lower[i + 2])) { dictBonus *= 100; break; }
    }
    if (/\d{4}/.test(lower)) dictBonus *= 10;
    let repLen = 0;
    for (let i = 0; i + 1 < lower.length; i++) {
        if (lower[i] === lower[i + 1]) {
            let j = i + 2;
            while (j < lower.length && lower[j] === lower[i]) j++;
            repLen = Math.max(repLen, j - i);
            i = j - 1;
        }
    }
    if (repLen >= 3) dictBonus *= 1000;

    return base * dictBonus;
}

const SPEEDS = [
    { label: 'Online (100 g/s)', value: 100, note: 'Throttled web login, rate-limited' },
    { label: 'Offline GPU (10B g/s)', value: 1e10, note: '8x RTX 4090 cracking MD5/NTLM-class' },
    { label: 'Cluster (1T g/s)', value: 1e12, note: 'Datacenter GPU array / high-end rigs' },
];

function analyze(pw) {
    if (!pw) {
        return { ok: false, title: 'Password Strength', subtitle: 'No input provided', sections: [listSection('Error', [{ severity: 'high', text: 'Enter a password to analyze.' }])], raw: {} };
    }

    const lower = pw.toLowerCase();
    const guesses = estimateGuesses(pw);
    const entropy = Math.log2(Math.max(guesses, 2));

    let rating, score;
    if (entropy < 28) { rating = 'Very Weak'; score = 0; }
    else if (entropy < 36) { rating = 'Weak'; score = 1; }
    else if (entropy < 60) { rating = 'Fair'; score = 2; }
    else if (entropy < 80) { rating = 'Strong'; score = 3; }
    else { rating = 'Very Strong'; score = 4; }

    const weaknesses = findWeaknesses(pw, lower);

    // NIST 800-63-3 checklist
    const nist = [];
    if (pw.length < 8) nist.push({ text: 'FAIL - minimum 8 characters required', ok: false });
    else nist.push({ text: 'Length >= 8', ok: true });
    if (pw.length >= 15) nist.push({ text: 'Length >= 15 (recommended)', ok: true });
    if (COMMON.has(pw)) nist.push({ text: 'FAIL - password on blocklist', ok: false });
    else if (weaknesses.some((w) => w.severity === 'high' && w.text.indexOf('common') !== -1)) nist.push({ text: 'FAIL - derivable from common password', ok: false });

    const crackRows = SPEEDS.map((s) => {
        const secs = guesses / s.value;
        return [s.label, crackTime(secs), s.note];
    });

    const sections = [
        kvSection('Summary', [
            ['Rating', rating],
            ['Score', score + '/4'],
            ['Estimated entropy', entropy.toFixed(1) + ' bits'],
            ['Estimated guesses', guesses >= 1e9 ? (guesses / 1e9).toFixed(2) + ' billion' : guesses >= 1e6 ? (guesses / 1e6).toFixed(1) + ' million' : String(Math.round(guesses))],
            ['Length', pw.length + ' chars'],
            ['Character classes', String((/[A-Z]/.test(pw) ? 'Upper ' : '') + (/[a-z]/.test(pw) ? 'Lower ' : '') + (/\d/.test(pw) ? 'Digit ' : '') + (/[^A-Za-z0-9]/.test(pw) ? 'Symbol' : '')).trim() || 'none'],
        ]),
        tableSection('Time to crack', ['Attack', 'Est. time', 'Model'], crackRows),
    ];

    if (weaknesses.length) {
        sections.push(listSection('Weaknesses', weaknesses.map((w) => ({ text: w.text, severity: w.severity }))));
    } else {
        sections.push(listSection('Weaknesses', [{ text: 'No common weaknesses detected', severity: 'info' }]));
    }

    sections.push(listSection('NIST 800-63-3 checklist', nist.map((n) => ({ text: n.text, severity: n.ok ? 'ok' : 'high' }))));

    const recs = [];
    if (pw.length < 15) recs.push({ text: 'Use a passphrase >= 15 chars - 4+ random words beats short gibberish', severity: 'medium' });
    if (weaknesses.some((w) => w.severity === 'high')) recs.push({ text: 'Avoid dictionary words, dates, and sequential patterns even with symbols', severity: 'medium' });
    if (!(/[^A-Za-z0-9]/.test(pw) && /\d/.test(pw) && /[A-Z]/.test(pw))) recs.push({ text: 'Mix uppercase, digits, and symbols - but length matters most', severity: 'low' });
    recs.push({ text: 'Use a password manager; never reuse passwords across accounts', severity: 'info' });
    sections.push(listSection('Recommendations', recs));

    return {
        ok: true,
        title: 'Password Strength Analysis',
        subtitle: rating + ' (' + score + '/4) - ' + entropy.toFixed(1) + ' bits',
        sections,
        raw: { password: pw, entropy, guesses, rating, score, weaknesses, nist, crackRows },
    };
}

module.exports = register({
    id: 'password-strength',
    name: 'Password Strength Analysis',
    description: 'zxcvbn-style guessability analysis with pattern detection, crack-time estimates, and NIST 800-63-3 checks.',
    category: 'Credential',
    run: (args) => analyze(args.password || args.input || ''),
});

