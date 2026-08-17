// Generates electron/config/agent-tools.json from `security-agent --list-tools`.
// This is the tool-usage configuration the desktop app consumes so the agent
// knows how to invoke every cataloged tool and where its inputs/outputs live
// in the workspace — eliminating the need for the user to type file locations.
//
// Usage: node scripts/generate-agent-config.js [path-to-list-tools-output]
const fs = require('fs');
const path = require('path');

const SRC = process.argv[2] || path.join(__dirname, '..', 'config', 'agent-tools.json');
const RAW = process.argv[3]
  ? fs.readFileSync(process.argv[3], 'utf8')
  : require('child_process')
      .execFileSync(
        process.env.SECURITY_AGENT_BIN ||
          path.join(__dirname, '..', '..', 'target', 'release', 'security-agent'),
        ['--list-tools'],
        { encoding: 'utf-8' }
      );

// name -> category (substring match, first hit wins)
const CAT = [
  ['aircrack', 'wireless'], ['kismet', 'wireless'], ['reaver', 'wireless'],
  ['wifite', 'wireless'], ['chirpw', 'wireless'], ['giskismet', 'wireless'],
  ['driftnet', 'wireless'], ['macchanger', 'wireless'],
  ['binwalk', 'forensic'], ['foremost', 'forensic'], ['bulk_extractor', 'forensic'],
  ['volatility', 'forensic'], ['autopsy', 'forensic'], ['sqlitebrowser', 'forensic'],
  ['mdb-sql', 'forensic'], ['httrack', 'forensic'], ['cutycapt', 'forensic'],
  ['keepnote', 'forensic'], ['recordmydesktop', 'forensic'], ['netsniff-ng', 'forensic'],
  ['tcpdump', 'forensic'], ['wireshark', 'forensic'], ['chkrootkit', 'forensic'],
  ['androguard', 'mobile'], ['apkleaks', 'mobile'], ['apksigner', 'mobile'],
  ['apktool', 'mobile'], ['dex2jar', 'mobile'], ['jadx', 'mobile'], ['mobsf', 'mobile'],
  ['objection', 'mobile'], ['qark', 'mobile'], ['drozer', 'mobile'], ['trueseeing', 'mobile'],
  ['termineter', 'iot'],
  ['hashcat', 'creds'], ['john', 'creds'], ['ophcrack', 'creds'], ['rcrack', 'creds'],
  ['crunch', 'creds'], ['cewl', 'creds'], ['galleta', 'creds'], ['mfterm', 'creds'],
  ['mfoc', 'creds'], ['pyrit', 'creds'],
  ['sqlmap', 'exploit'], ['hydra', 'exploit'], ['medusa', 'exploit'], ['ncrack', 'exploit'],
  ['crackmapexec', 'exploit'], ['netexec', 'exploit'], ['msfconsole', 'exploit'],
  ['msfpc', 'exploit'], ['setoolkit', 'exploit'], ['beef-xss', 'exploit'],
  ['burpsuite', 'exploit'], ['wpscan', 'exploit'], ['skipfish', 'exploit'],
  ['thc-ipv6', 'exploit'], ['yersinia', 'exploit'], ['ettercap', 'exploit'],
  ['bettercap', 'exploit'], ['mitmproxy', 'exploit'], ['lynis', 'recon'],
  ['nmap', 'recon'], ['zenmap', 'recon'], ['masscan', 'recon'], ['amass', 'recon'],
  ['subfinder', 'recon'], ['dmitry', 'recon'], ['netdiscover', 'recon'],
  ['feroxbuster', 'recon'], ['gobuster', 'recon'], ['dirb', 'recon'], ['ffuf', 'recon'],
  ['wfuzz', 'recon'], ['nikto', 'recon'], ['whatweb', 'recon'], ['wafw00f', 'recon'],
  ['nuclei', 'recon'], ['enum4linux', 'recon'], ['searchsploit', 'recon'],
];

// Tools whose normal operation opens a live socket / makes outbound requests.
const NET = new Set([
  'nmap', 'zenmap', 'masscan', 'amass', 'subfinder', 'dmitry', 'netdiscover',
  'feroxbuster', 'gobuster', 'dirb', 'ffuf', 'wfuzz', 'nikto', 'whatweb', 'wafw00f',
  'nuclei', 'enum4linux', 'searchsploit', 'sqlmap', 'hydra', 'medusa', 'ncrack',
  'crackmapexec', 'netexec', 'msfconsole', 'beef-xss', 'burpsuite', 'wpscan',
  'skipfish', 'ettercap', 'bettercap', 'mitmproxy', 'reaver', 'wifite', 'aircrack-ng',
  'kismet', 'netsniff-ng', 'yersinia', 'thc-ipv6', 'wpscan',
]);

// Where each category's artifacts land by default (workspace subdirs).
const CAT_IO = {
  recon: { input: 'engagements', output: 'reports' },
  exploit: { input: 'engagements', output: 'reports' },
  creds: { input: 'engagements', output: 'findings' },
  wireless: { input: 'engagements', output: 'exports' },
  forensic: { input: 'engagements', output: 'exports' },
  mobile: { input: 'engagements', output: 'exports' },
  iot: { input: 'engagements', output: 'exports' },
  general: { input: 'engagements', output: 'runs' },
};

const CAT_DESC = {
  recon: 'Reconnaissance & mapping — discover hosts, services, web apps, subdomains.',
  exploit: 'Vulnerability exploitation & post-access — targeted, authorized only.',
  creds: 'Credential testing & cracking — hashes, wordlists, brute force.',
  wireless: 'Wireless auditing — Wi-Fi capture, WPA/WEP, RF.',
  forensic: 'Forensics & artifact recovery — firmware, memory, packets, files.',
  mobile: 'Mobile application auditing — Android/iOS static & dynamic.',
  iot: 'IoT / industrial protocol auditing.',
  general: 'General-purpose utility.',
};

function categoryFor(name) {
  for (const [sub, cat] of CAT) if (name.includes(sub)) return cat;
  return 'general';
}

const tools = [];
for (const line of RAW.split(/\r?\n/)) {
  if (!line.trim()) continue;
  const cols = line.split('\t');
  const name = cols[0];
  const executable = (cols[2] || '').replace(/^executable=/, '');
  const cat = categoryFor(name);
  const io = CAT_IO[cat];
  tools.push({
    id: name,
    name,
    category: cat,
    needsNetwork: NET.has(name),
    installed: executable !== 'not-installed',
    executable: executable === 'not-installed' ? null : executable,
    keywords: [name, cat],
    io,
    description: CAT_DESC[cat],
    hint: `Default I/O: in=${io.input}/, out=${io.output}/ (resolved inside the workspace automatically).`,
  });
}

tools.sort((a, b) => a.name.localeCompare(b.name));

const config = {
  version: 1,
  generatedFrom: 'security-agent --list-tools',
  toolCount: tools.length,
  categories: CAT_DESC,
  workspace: {
    subdirs: ['engagements', 'findings', 'reports', 'exports', 'runs'],
    note: 'All tool input/output paths are resolved relative to these workspace subdirs; the user never types absolute paths.',
  },
  tools,
};

const out = path.join(__dirname, '..', 'config', 'agent-tools.json');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(config, null, 2) + '\n');
console.log('Wrote ' + out + ' (' + tools.length + ' tools)');
