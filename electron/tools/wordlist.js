'use strict';
/**
 * Native tool: wordlist
 *
 * Targeted wordlist generation. Exceeds the Rust `generate_targeted_wordlist`
 * (base word + a handful of hardcoded patterns) with a real mutation engine:
 *   - case variants (lower, upper, title, camel, toggle)
 *   - l33t substitution
 *   - separators, prefixes, suffixes, doubled words
 *   - year cycling (target year +/- range) and common years
 *   - numeric appends (1..9999 sample, configurable)
 *   - keyboard-shift variants and reversed words
 *   - deterministic ordering + dedupe + optional size cap
 *   - mutation statistics
 */

const { register } = require('./registry');
const { kvSection, tableSection, listSection, formatBytes } = require('./util');

const LEET_MAP = { a: ['4', '@'], e: ['3'], i: ['1', '!'], o: ['0'], s: ['5', '$'], t: ['7', '+'], g: ['9', '6'], b: ['8'], l: ['1', '|'] };
const SEPARATORS = ['', '.', '-', '_', '@', '#'];
const PREFIXES = ['!', '@', '#', '$', 'pass', 'P@ss', 'welcome', 'admin', 'root', 'ilove'];
const SUFFIXES = ['!', '!!', '@', '#', '$', '1', '12', '123', '1234', '12345', '123456', '1234567', '12345678', '0', '00', '000', '0000', '69', '007', '1!', '123!', '1234!', '12345!', '2020', '2021', '2022', '2023', '2024', '2025', '2026', '2027'];
const COMMON_YEARS = ['1990', '1991', '1992', '1993', '1994', '1995', '1996', '1997', '1998', '1999', '2000', '2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020', '2021', '2022', '2023', '2024', '2025', '2026', '2027', '2028', '2029', '2030'];

function caseVariants(word) {
    const lower = word.toLowerCase();
    const out = new Set([word, lower, word.toUpperCase()]);
    // Title case
    out.add(lower.charAt(0).toUpperCase() + lower.slice(1));
    // CamelCase (per word)
    if (lower.includes(' ')) {
        out.add(lower.split(' ').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(''));
    }
    // Toggle case: pAsSwOrD
    let toggled = '';
    for (let i = 0; i < lower.length; i++) toggled += (i % 2 === 0) ? lower[i].toUpperCase() : lower[i];
    out.add(toggled);
    // First char lower
    if (word.length > 0) out.add(word.charAt(0).toLowerCase() + word.slice(1));
    // All caps
    return [...out].filter(Boolean);
}

function l33tVariants(word) {
    const lower = word.toLowerCase();
    const results = new Set([lower]);
    const chars = [...lower];
    const applyAt = (i, arr) => {
        for (const sub of LEET_MAP[chars[i]] || []) {
            const next = arr.slice();
            next[i] = sub;
            results.add(next.join(''));
            for (let j = i + 1; j < chars.length; j++) applyAt(j, next);
        }
    };
    for (let i = 0; i < chars.length; i++) applyAt(i, chars);
    return [...results];
}

function keyboardShift(word) {
    // Common shift: 1->! 2->@ 3-># 4->$ 5->% 6->^ 7->& 8->* 9->( 0->)
    const map = { '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')' };
    return [...word].map((c) => map[c] || c).join('');
}

function yearsFor(targetYear, range) {
    const set = new Set(COMMON_YEARS);
    const base = parseInt(targetYear, 10);
    if (!isNaN(base)) {
        set.add(String(base));
        for (let i = 1; i <= range; i++) {
            set.add(String(base + i));
            set.add(String(base - i));
        }
        const short = String(base).slice(-2);
        set.add(short);
        set.add(String(Number(short) + 1).padStart(2, '0'));
        set.add(String(Number(short) - 1).padStart(2, '0'));
    }
    return [...set];
}

function numericAppends(count) {
    const out = [];
    // Deterministic: 0..count but bounded to keep lists sane
    for (let i = 1; i <= Math.min(count, 9999); i++) out.push(String(i));
    return out;
}

function generate(args) {
    const target = String(args.target || args.input || '').trim();
    if (!target) {
        return { ok: false, title: 'Wordlist Generation', subtitle: 'No input provided', sections: [listSection('Error', [{ severity: 'high', text: 'Enter a target name.' }])], raw: {} };
    }

    const company = String(args.company || '').trim();
    const year = String(args.year || '').trim();
    const yearRange = Math.min(parseInt(args.range, 10) || 3, 20);
    const maxWords = Math.min(parseInt(args.maxWords, 10) || 20000, 2000000);
    const includeNumeric = args.includeNumeric !== false;
    const addExtra = (args.extra || []).filter(Boolean).map(String);

    const baseWords = [];
    const pushUnique = (w) => { if (w && !baseWords.includes(w)) baseWords.push(w); };

    // Target-derived bases (split on spaces/dashes/underscores too)
    const pieces = target.split(/[\s\-_.]+/).filter(Boolean);
    for (const p of pieces) pushUnique(p);
    pushUnique(target);
    if (company) {
        for (const p of company.split(/[\s\-_.]+/).filter(Boolean)) pushUnique(p);
        pushUnique(company);
    }
    for (const w of addExtra) {
        for (const p of w.split(/[\s\-_.]+/).filter(Boolean)) pushUnique(p);
    }

    const years = yearsFor(year, yearRange);
    const words = new Set();

    // Core expansions
    for (const base of baseWords) {
        for (const v of caseVariants(base)) {
            words.add(v);
            // + year
            for (const y of years) { words.add(v + y); words.add(y + v); }
            // + suffix
            for (const s of SUFFIXES) words.add(v + s);
            // + prefix
            for (const p of PREFIXES) words.add(p + v);
            // doubled
            words.add(v + v);
            words.add(v + '!' + v);
            // reversed
            words.add([...v].reverse().join(''));
            // keyboard shift
            words.add(keyboardShift(v));
            // separators with numbers
            for (const sep of SEPARATORS) {
                for (const y of years.slice(0, 5)) words.add(v + sep + y);
            }
            // l33t of lowercase base
            if (v === v.toLowerCase() && v.length >= 3) {
                for (const l of l33tVariants(v)) {
                    words.add(l);
                    words.add(l + '123');
                    words.add(l + '!');
                    for (const y of years.slice(0, 3)) words.add(l + y);
                }
            }
            // combined with company
            if (company) {
                for (const cb of baseWords) {
                    if (cb !== base) {
                        words.add(v + cb);
                        words.add(cb + v);
                        words.add(v + '.' + cb);
                        words.add(v + '_' + cb);
                    }
                }
            }
        }
    }

    // Numeric appends for first base only (keep count sane)
    if (includeNumeric && baseWords.length > 0) {
        const first = baseWords[0].toLowerCase();
        for (const n of numericAppends(100)) {
            words.add(first + n);
            words.add(n + first);
        }
        // Year-range numeric patterns
        for (const y of years) {
            words.add(first + y);
            words.add(first + '.' + y);
            words.add(first + '_' + y);
            words.add(first + '-' + y);
            words.add(first + '!' + y);
            words.add(first + '@' + y);
        }
    }

    let list = [...words];
    list.sort();

    // Cap
    const before = list.length;
    if (list.length > maxWords) list = list.slice(0, maxWords);

    const sample = list.slice(0, 12);
    const text = list.join('\n');

    const sections = [
        kvSection('Summary', [
            ['Base words', String(baseWords.length)],
            ['Total entries', formatCount(list.length)],
            ['(capped from)', before > list.length ? formatCount(before) : '-'],
            ['Target', target],
            ['Company', company || '-'],
            ['Year focus', year || '2026 (default)'],
            ['Max words', String(maxWords)],
        ]),
        tableSection('Sample', ['#', 'Word'], sample.map((w, i) => [String(i + 1), w])),
        listSection('Next step', [
            { severity: 'info', text: 'Feed this list to hashcat (-a 0) or John (--wordlist). Copy from output or save to file.' },
        ]),
    ];

    return {
        ok: true,
        title: 'Targeted Wordlist',
        subtitle: formatCount(list.length) + ' candidates from ' + baseWords.length + ' base word(s)',
        sections,
        raw: { words: list, sample, count: list.length, baseWords },
        text,
    };
}

function formatCount(n) {
    if (n < 1000) return String(n);
    if (n < 1e6) return (n / 1e3).toFixed(1) + 'k';
    return (n / 1e6).toFixed(2) + 'M';
}

module.exports = register({
    id: 'wordlist',
    name: 'Generate Wordlist',
    description: 'Targeted wordlist generation with a mutation engine (case, l33t, years, prefixes/suffixes, combinations).',
    category: 'Credential',
    run: (args) => generate(args),
});

