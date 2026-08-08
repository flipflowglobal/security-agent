'use strict';
/**
 * Native tool: hash-id
 *
 * Identifies hash formats by prefix, envelope, length, and character set.
 * Exceeds the Rust `classify_hash_by_prefix`/`classify_hash_by_length`
 * implementation by supporting 80+ formats (vs ~35), validating the full
 * character set of the digest body (not just length), returning multiple
 * candidate matches ranked by confidence, mapping to Hashcat + John The
 * Ripper + Hashcat example-hash metadata, and accepting Hashcat mode-style
 * queries (e.g. `hash-id 1400`).
 */

const { register } = require('./registry');
const { entropyOfString, charsetClasses, kvSection, listSection, tableSection, result } = require('./util');

// Format descriptor:
//   prefix, suffix, exactLen (or min/max), charset, name, category, hashcat, john, example, notes, confidence
// Match order matters: prefix/suffix formats first (most specific), then exact-length hex families.

const FORMATS = [
    // â”€â”€ Unix / password crypt formats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    { prefix: '$1$', name: 'md5crypt (Unix)', category: 'Unix crypt', hashcat: 500, john: 'md5crypt', example: '$1$salt$hash', notes: 'Unix $1$ MD5 password hash. Weak by modern standards â€” cracked in seconds.' },
    { prefix: '$5$', name: 'sha256crypt (Unix)', category: 'Unix crypt', hashcat: 7400, john: 'sha256crypt', example: '$5$salt$hash', notes: 'Unix $5$ SHA-256 password hash.' },
    { prefix: '$6$', name: 'sha512crypt (Unix)', category: 'Unix crypt', hashcat: 1800, john: 'sha512crypt', example: '$6$salt$hash', notes: 'Unix $6$ SHA-512 password hash. Standard on modern Linux.' },
    { prefix: '$y$', name: 'yescrypt', category: 'Unix crypt', hashcat: 25600, john: 'yescrypt', example: '$y$j9T$salt$hash', notes: 'Newer password hashing; used by Debian/Ubuntu 22.04+.' },
    { prefix: '$2a$', name: 'bcrypt ($2a$)', category: 'Unix crypt', hashcat: 3200, john: 'bcrypt', example: '$2a$10$abcdefghijklmnopqrstuu', notes: 'Blowfish-based, cost factor in 2nd field.' },
    { prefix: '$2b$', name: 'bcrypt ($2b$)', category: 'Unix crypt', hashcat: 3200, john: 'bcrypt', example: '$2b$12$abcdefghijklmnopqrstuu', notes: 'Current bcrypt variant (OpenBSD/Blowfish bug fix).' },
    { prefix: '$2y$', name: 'bcrypt ($2y$)', category: 'Unix crypt', hashcat: 3200, john: 'bcrypt', example: '$2y$10$abcdefghijklmnopqrstuu', notes: 'PHP bcrypt variant.' },
    { prefix: '$2x$', name: 'bcrypt ($2x$)', category: 'Unix crypt', hashcat: 3200, john: 'bcrypt', example: '$2x$08$abcdefghijklmnopqrstuu', notes: 'Legacy bcrypt bug-compatibility variant.' },
    { prefix: '$7$', name: 'scrypt (Unix)', category: 'Unix crypt', hashcat: 8900, john: 'scrypt', example: '$7$salt$hash', notes: 'Memory-hard KDF.' },
    { prefix: '$argon2id$', name: 'Argon2id', category: 'KDF', hashcat: 25600, john: 'argon2', example: '$argon2id$v=19$m=65536,t=2,p=1$...', notes: 'Winner of the Password Hashing Competition; memory-hard.' },
    { prefix: '$argon2i$', name: 'Argon2i', category: 'KDF', hashcat: 25600, john: 'argon2', example: '$argon2i$v=19$m=65536,t=2,p=1$...', notes: 'Argon2i â€” data-independent, side-channel resistant.' },
    { prefix: '$argon2d$', name: 'Argon2d', category: 'KDF', hashcat: 25600, john: 'argon2', example: '$argon2d$v=19$m=65536,t=2,p=1$...', notes: 'Argon2d â€” data-dependent, GPU-friendly.' },
    { prefix: '$argon2', name: 'Argon2 (family)', category: 'KDF', hashcat: 25600, john: 'argon2', example: '$argon2*$v=19$m=65536,t=2,p=1$...', notes: 'Generic Argon2 envelope.' },
    { prefix: '$P$', name: 'phpass (WordPress/Drupal legacy)', category: 'Web CMS', hashcat: 400, john: 'phpass', example: '$P$Bhash...', notes: 'Portable PHP password hash â€” WordPress, Joomla, phpBB.' },
    { prefix: '$H$', name: 'phpass (phpBB)', category: 'Web CMS', hashcat: 400, john: 'phpass', example: '$H$hash...', notes: 'phpBB variant of phpass.' },
    { prefix: '$S$', name: 'Drupal 7+', category: 'Web CMS', hashcat: 7900, john: 'drupal7', example: '$S$Dhash...', notes: 'Drupal 7+ SHA-512 based hash.' },
    { prefix: 'sha1$', name: 'Django (SHA1)', category: 'Web CMS', hashcat: 124, john: 'django', example: 'sha1$salt$hash', notes: 'Django SHA1 password hash.' },
    { prefix: 'pbkdf2_sha256$', name: 'Django (PBKDF2-SHA256)', category: 'Web CMS', hashcat: 10900, john: 'django', example: 'pbkdf2_sha256$iter$salt$hash', notes: 'Django default since 1.6.' },
    { prefix: '$pbkdf2-sha256$', name: 'PBKDF2-SHA256', category: 'KDF', hashcat: 10900, john: 'pbkdf2', example: '$pbkdf2-sha256$iter$salt$hash', notes: 'Generic PBKDF2 envelope (Dovecot/FreeBSD).' },
    { prefix: '$pbkdf2-sha512$', name: 'PBKDF2-SHA512', category: 'KDF', hashcat: 7100, john: 'pbkdf2', example: '$pbkdf2-sha512$iter$salt$hash', notes: 'PBKDF2 with SHA-512.' },
    { prefix: '$pbkdf2-', name: 'PBKDF2 (generic)', category: 'KDF', hashcat: 10900, john: 'pbkdf2', example: '$pbkdf2-...$iter$salt$hash', notes: 'Generic PBKDF2 envelope.' },
    { prefix: '{SSHA}', name: 'SSHA (LDAP)', category: 'Directory', hashcat: 111, john: 'ssha', example: '{SSHA}base64', notes: 'Salted SHA-1 used by OpenLDAP.' },
    { prefix: '{SHA}', name: 'SHA-1 (LDAP/NetWare)', category: 'Directory', hashcat: 101, john: 'nsldaps', example: '{SHA}base64', notes: 'Base64 SHA-1, unsalted â€” commonly LDAP.' },
    { prefix: '{MD5}', name: 'MD5 (LDAP)', category: 'Directory', hashcat: 0, john: 'raw-md5', example: '{MD5}base64', notes: 'Base64 MD5, unsalted â€” commonly LDAP.' },
    { prefix: '{CRYPT}', name: 'CRYPT (LDAP)', category: 'Directory', hashcat: null, john: 'crypt', example: '{CRYPT}$1$...', notes: 'LDAP CRYPT wrapper.' },
    { prefix: '$apr1$', name: 'Apache MD5-crypt', category: 'Web server', hashcat: 1600, john: 'md5apr1', example: '$apr1$salt$hash', notes: 'Apache htpasswd MD5 crypt.' },
    { prefix: '$ht$', name: 'Apache htpasswd SHA', category: 'Web server', hashcat: 1600, john: 'htpasswd', example: '$ht$hash', notes: 'Apache htpasswd SHA.' },
    { prefix: '$dmd5$', name: 'Dovecot MD5', category: 'Mail', hashcat: 6300, john: 'dovecot', example: '$dmd5$salt$hash', notes: 'Dovecot salted MD5.' },
    { prefix: '$dovecot$', name: 'Dovecot', category: 'Mail', hashcat: null, john: 'dovecot', example: '$dovecot$...', notes: 'Dovecot password scheme.' },
    { prefix: '$grub$', name: 'GRUB2 PBKDF2', category: 'Bootloader', hashcat: 17200, john: 'grub', example: '$grub$pbkdf2-sha512$...', notes: 'GRUB2 bootloader hash.' },
    { prefix: '$sshnt$', name: 'SSH NTLM (putty)', category: 'Auth', hashcat: null, john: 'ssh', example: '$sshnt$hex', notes: 'Putty SSH private key NTLM check value.' },
    { prefix: '$cisco4$', name: 'Cisco type 4', category: 'Network device', hashcat: 9200, john: 'cisco4', example: '$cisco4$hex', notes: 'Cisco IOS type-4 (SHA-256).' },
    { prefix: '$cisco9$', name: 'Cisco type 9', category: 'Network device', hashcat: 9300, john: 'cisco9', example: '$cisco9$scrypt', notes: 'Cisco IOS type-9 (scrypt).' },
    { prefix: '$wpa$', name: 'WPA-PBKDF2-PMKID', category: 'Wireless', hashcat: 22000, john: 'wpapmkid', example: '$wpa$ap_mac$client_mac$pmkid', notes: 'WPA2 PMKID â€” offline crack without client.' },
    { prefix: '$WPAPSK$', name: 'WPA-PSK (passphrase)', category: 'Wireless', hashcat: 22000, john: 'wpapsk', example: '$WPAPSK$ssid$hex', notes: 'WPA/WPA2 passphrase handshake hash.' },
    { prefix: '$sntp$', name: 'SNTP challenge', category: 'Network', hashcat: null, john: 'sntp', example: '$sntp$hex', notes: 'SNTP challenge hash.' },
    { prefix: '$mysql$', name: 'MySQL 3.x', category: 'Database', hashcat: 200, john: 'mysql', example: '$mysql$hex', notes: 'MySQL pre-4.1 password hash.' },
    { prefix: '$mysqlna$', name: 'MySQL 4.1+', category: 'Database', hashcat: 300, john: 'mysqlna', example: '$mysqlna$hex', notes: 'MySQL 4.1+ SHA1-based auth.' },
    { prefix: '$postgres$', name: 'PostgreSQL', category: 'Database', hashcat: 12, john: 'postgres', example: '$postgres$hex', notes: 'PostgreSQL MD5 auth hash.' },
    { prefix: '$mssql$', name: 'MSSQL (2000)', category: 'Database', hashcat: 132, john: 'mssql', example: '$mssql$hex', notes: 'Microsoft SQL Server 2000.' },
    { prefix: '$smb$', name: 'SMB (LanMan challenge)', category: 'Network', hashcat: 5500, john: 'netlm', example: '$smb$challenge$hex', notes: 'NetLMv1 challenge/response.' },
    { prefix: '$krb5tgs$', name: 'Kerberos TGS-REP', category: 'Network', hashcat: 13100, john: 'krb5tgs', example: '$krb5tgs$23$*user$realm$spn*$hash', notes: 'Kerberoast target â€” extractable from memory of a domain controller.' },
    { prefix: '$krb5asrep$', name: 'Kerberos AS-REP', category: 'Network', hashcat: 18200, john: 'krb5asrep', example: '$krb5asrep$23$user@realm:hash', notes: 'AS-REP roast â€” no preauth account.' },
    { prefix: '$krb5pa$', name: 'Kerberos encrypted timestamp', category: 'Network', hashcat: 19800, john: 'krb5pa', example: '$krb5pa$23$user$realm$hash', notes: 'Kerberos preauth encrypted timestamp.' },
    { prefix: '$1$', name: 'md5crypt', category: 'Unix crypt', hashcat: 500, john: 'md5crypt', example: '$1$salt$hash', notes: 'Unix MD5 crypt (redundant guard).' },
    // â”€â”€ Microsoft formats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    { prefix: 'admin::', name: 'NetNTLMv1/v2 (capture)', category: 'Microsoft', hashcat: 5600, john: 'netntlmv2', example: 'admin::NTLM:challenge:response', notes: 'Responder/Inveigh capture â€” offline crack.' },
    { prefix: '$NETNTLMv2$', name: 'NetNTLMv2', category: 'Microsoft', hashcat: 5600, john: 'netntlmv2', example: '$NETNTLMv2$user$domain$...', notes: 'Explicit NetNTLMv2 envelope.' },
    { prefix: '$NETNTLM$', name: 'NetNTLMv1', category: 'Microsoft', hashcat: 5500, john: 'netntlm', example: '$NETNTLM$user$domain$...', notes: 'NetNTLMv1 challenge/response.' },
    { prefix: '$DPAPImk$', name: 'DPAPI masterkey', category: 'Microsoft', hashcat: 27000, john: 'dmg', example: '$DPAPImk$...', notes: 'Windows DPAPI master key (offline decrypt).' },
    { prefix: '$DCC2$', name: 'Domain Cached Credentials v2', category: 'Microsoft', hashcat: 2100, john: 'mscash2', example: '$DCC2$user#domain#hash', notes: 'MSCache v2 â€” local Windows cached creds.' },
    { prefix: '$MSCASH$', name: 'Domain Cached Credentials v1', category: 'Microsoft', hashcat: 1100, john: 'mscash', example: '$MSCASH$hash', notes: 'MSCache v1.' },
    { prefix: '0x0100', name: 'MSSQL 2005/2008', category: 'Database', hashcat: 131, john: 'mssql05', example: '0x0100...', notes: 'MSSQL 2005 (54 hex) / 2008+ (94 hex) SHA1-based.' },
    // â”€â”€ Network appliances â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    { prefix: 'type7', name: 'Cisco type 7', category: 'Network device', hashcat: null, john: 'cisco', example: 'type7 04480E051A33490E', notes: 'Cisco IOS type-7 â€” trivially reversible XOR obfuscation, NOT a real hash.' },
    { prefix: 'enable 5', name: 'Cisco enable secret (type 5)', category: 'Network device', hashcat: 500, john: 'md5crypt', example: 'enable 5 $1$...', notes: 'Cisco IOS enable secret â€” MD5 crypt.' },
    { prefix: 'enable 9', name: 'Cisco enable secret (type 9)', category: 'Network device', hashcat: 9300, john: 'cisco9', example: 'enable 9 $cisco9$...', notes: 'Cisco IOS enable secret â€” scrypt.' },
    { prefix: 'S:', name: 'Oracle 11g', category: 'Database', hashcat: 112, john: 'oracle11', example: 'S:hex...', notes: 'Oracle 11g password verifier (salted SHA1).' },
    { prefix: 'T:', name: 'Oracle 12c', category: 'Database', hashcat: null, john: 'oracle12', example: 'T:hex...', notes: 'Oracle 12c password verifier (PBKDF2).' },
    { prefix: 'O:', name: 'Oracle 10g', category: 'Database', hashcat: 3100, john: 'oracle', example: 'O:hex', notes: 'Oracle 10g password verifier.' },
    { prefix: 'sha256$', name: 'Cryptacular SHA256', category: 'Generic', hashcat: 1410, john: 'crypt', example: 'sha256$salt$hash', notes: 'Cryptacular PBKDF2 wrapper.' },
    { prefix: 'md5$', name: 'Cryptacular MD5', category: 'Generic', hashcat: 10, john: 'crypt', example: 'md5$salt$hash', notes: 'Cryptacular MD5 wrapper.' },
    // â”€â”€ KDF / JWT / misc envelopes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    { prefix: '$scrypt$', name: 'scrypt', category: 'KDF', hashcat: 8900, john: 'scrypt', example: '$scrypt$ln=...$salt$hash', notes: 'Generic scrypt envelope.' },
    { prefix: 'eyJ', name: 'JWT (JSON Web Token)', category: 'Web', hashcat: 16500, john: 'jwt', example: 'eyJhbGciOiJIUzI1NiJ9...', notes: 'Base64url header.payload.signature â€” try JWT cracking (HS256).' },
];

// Exact-length hex families, matched only when the full body is hex.
const LENGTH_FORMATS = [
    { len: 16, name: 'LM hash', category: 'Microsoft', hashcat: 3000, john: 'lm', example: 'aad3b435b51404eeaad3b435b51404ee', notes: '32 hex chars uppercase (legacy LM).' },
    { len: 32, name: 'MD5', category: 'Generic', hashcat: 0, john: 'raw-md5', example: '5f4dcc3b5aa765d61d8327deb882cf99', notes: 'MD5 hex digest (128-bit).' },
    { len: 32, name: 'NTLM', category: 'Microsoft', hashcat: 1000, john: 'nt', example: 'b4b9b02e6f09a9bd760f408b673c6d84', notes: 'NTLM hex digest â€” MD4(UTF-16LE(password)). Identical length to MD5; check context.' },
    { len: 32, name: 'MD4', category: 'Generic', hashcat: 900, john: 'raw-md4', example: 'af979c61a5d9b0e2a4c1b1a9e2d9e2c1', notes: 'MD4 hex digest (128-bit).' },
    { len: 32, name: 'MySQL 4.1+', category: 'Database', hashcat: 300, john: 'mysqlna', example: '81bdf501ef9ae91cb0e2c5cac0a5d9a2', notes: 'MySQL SHA1(SHA1(pass)).' },
    { len: 32, name: 'Half-MD5', category: 'Generic', hashcat: 5100, john: 'half-md5', example: '5f4dcc3b5aa765d6', notes: 'First 16 bytes of MD5.' },
    { len: 40, name: 'SHA-1', category: 'Generic', hashcat: 100, john: 'raw-sha1', example: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1', notes: 'SHA-1 hex digest (160-bit).' },
    { len: 40, name: 'MySQL 5', category: 'Database', hashcat: 300, john: 'mysqlna', example: '81bdf501ef9ae91cb0e2c5cac0a5d9a2...', notes: 'MySQL 5 double-SHA1 variant.' },
    { len: 40, name: 'RIPEMD-160', category: 'Generic', hashcat: 6000, john: 'ripemd160', example: '9c1185a5c5e9fc54612808977ee8f548b2258d31', notes: 'RIPEMD-160 hex digest.' },
    { len: 48, name: 'SHA-384', category: 'Generic', hashcat: 10800, john: 'raw-sha384', example: 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7', notes: 'SHA-384 hex digest (384-bit).' },
    { len: 56, name: 'SHA-224', category: 'Generic', hashcat: 1300, john: 'raw-sha224', example: 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f', notes: 'SHA-224 hex digest (224-bit).' },
    { len: 64, name: 'SHA-256', category: 'Generic', hashcat: 1400, john: 'raw-sha256', example: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', notes: 'SHA-256 hex digest (256-bit).' },
    { len: 64, name: 'SHA3-256', category: 'Generic', hashcat: 5000, john: 'raw-sha3', example: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', notes: 'SHA3-256 hex digest.' },
    { len: 64, name: 'RIPEMD-256', category: 'Generic', hashcat: 6000, john: 'ripemd160', example: 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc', notes: 'RIPEMD-256 hex digest.' },
    { len: 96, name: 'SHA-384 (BLAKE2b-384)', category: 'Generic', hashcat: 10800, john: 'raw-sha384', example: '83b5025281e6f3c5a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2', notes: 'SHA-384 hex digest (384-bit).' },
    { len: 96, name: 'Whirlpool', category: 'Generic', hashcat: 6100, john: 'whirlpool', example: '19fa61d75522a4669b44e39c1d2e3c6c', notes: 'Whirlpool hex digest (512-bit).' },
    { len: 128, name: 'SHA-512', category: 'Generic', hashcat: 1700, john: 'raw-sha512', example: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', notes: 'SHA-512 hex digest (512-bit).' },
    { len: 128, name: 'SHA3-512', category: 'Generic', hashcat: 5100, john: 'raw-sha3', example: 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26', notes: 'SHA3-512 hex digest.' },
    { len: 128, name: 'Whirlpool', category: 'Generic', hashcat: 6100, john: 'whirlpool', example: 'b3d6c4a5b8e9d1e2a3b4c5d6e7f8a9b0', notes: 'Whirlpool hex digest (512-bit).' },
];

// Uppercase-only special cases (LM, Cisco type-7 style).
function matchByShape(hash) {
    const len = hash.length;
    const lower = hash.toLowerCase();
    const isHex = /^[0-9a-fA-F]+$/.test(hash);
    const isUpperHex = /^[0-9A-F]+$/.test(hash);

    if (isHex) {
        for (const f of LENGTH_FORMATS) {
            if (f.len === len) return [Object.assign({ confidence: 'high' }, f)];
        }
        // Odd-but-common lengths
        if (len === 16) {
            return [Object.assign({ confidence: 'medium' }, LENGTH_FORMATS.find((x) => x.name === 'Half-MD5'))];
        }
    }

    // Non-hex exact lengths
    const bodyLen = hash.length;
    const base64ish = /^[A-Za-z0-9+/]+={0,2}$/.test(hash) && hash.length % 4 === 0;
    if (base64ish) {
        if (bodyLen === 28) return [{ name: 'Base64 SHA-1', category: 'Generic', hashcat: 101, john: 'raw-sha1', confidence: 'medium', notes: '28 base64 chars = 160-bit digest.' }];
        if (bodyLen === 44) return [{ name: 'Base64 SHA-256', category: 'Generic', hashcat: 1400, john: 'raw-sha256', confidence: 'medium', notes: '44 base64 chars = 256-bit digest.' }];
        if (bodyLen === 88) return [{ name: 'Base64 SHA-512', category: 'Generic', hashcat: 1700, john: 'raw-sha512', confidence: 'medium', notes: '88 base64 chars = 512-bit digest.' }];
    }

    return [];
}

// Detect whether the input *looks* like a Hashcat mode query ("1400", "3200", "0").
const KNOWN_MODES = new Map();
[
    [0, 'MD5'], [10, 'MD5($pass.$salt)'], [100, 'SHA1'], [1400, 'SHA256'], [1700, 'SHA512'],
    [1000, 'NTLM'], [3000, 'LM'], [1100, 'Domain Cached Credentials'], [2100, 'Domain Cached Credentials 2'],
    [500, 'md5crypt'], [3200, 'bcrypt'], [7400, 'sha256crypt'], [1800, 'sha512crypt'],
    [5500, 'NetNTLMv1'], [5600, 'NetNTLMv2'], [13100, 'Kerberos TGS-REP'], [18200, 'Kerberos AS-REP'],
    [22000, 'WPA-PBKDF2-PMKID'], [22100, 'WPA-PBKDF2-PMKID+EAPOL'], [10900, 'PBKDF2-HMAC-SHA256'],
    [8900, 'scrypt'], [25600, 'yescrypt'], [400, 'phpass'], [7900, 'Drupal7'], [124, 'Django(SHA1)'],
    [112, 'Oracle 11g'], [131, 'MSSQL 2005'], [132, 'MSSQL 2000'], [1731, 'MSSQL 2012/2014'],
    [300, 'MySQL4.1/MySQL5'], [200, 'MySQL323'], [12, 'PostgreSQL'], [13200, 'AxCrypt'],
    [13400, 'Keepass 1.x'], [13500, 'Keepass 2.x'], [11300, 'Bitlocker'], [13600, 'Windows 8+ phone pin'],
    [6300, 'AIX {smd5}'], [6400, 'AIX {ssha1}'], [1410, 'PBKDF2-HMAC-SHA256 (raw)'],
].forEach(([mode, name]) => KNOWN_MODES.set(String(mode), { mode, name }));

function identifyHash(hash) {
    const trimmed = String(hash || '').trim();

    // Empty / whitespace guard
    if (!trimmed) {
        return {
            ok: false,
            title: 'Hash Identification',
            subtitle: 'No input provided',
            sections: [listSection('Error', [{ severity: 'high', text: 'Enter a hash or a Hashcat mode number (e.g. 1400).' }])],
            raw: { input: '' },
        };
    }

    // Hashcat-mode query support (a Rust-gap feature).
    if (KNOWN_MODES.has(trimmed)) {
        const m = KNOWN_MODES.get(trimmed);
        return {
            ok: true,
            title: 'Hashcat Mode Lookup',
            subtitle: `Mode ${m.mode} â†’ ${m.name}`,
            sections: [
                kvSection('Mode', [
                    ['Hashcat mode', String(m.mode)],
                    ['Hash family', m.name],
                    ['John format', formatJohnForMode(m.mode)],
                ]),
                listSection('Hint', [
                    { severity: 'info', text: `Run hashcat with -m ${m.mode} for ${m.name} hashes.` },
                ]),
            ],
            raw: { mode: m.mode, name: m.name },
        };
    }

    const candidates = [];

    // 1) Prefix/suffix envelope matching (ordered; first is highest confidence).
    for (const f of FORMATS) {
        if (trimmed.startsWith(f.prefix)) {
            const entry = Object.assign({}, f, { confidence: 'high', match: 'prefix' });
            if (f.prefix === '$2a$' || f.prefix === '$2b$' || f.prefix === '$2y$' || f.prefix === '$2x$') {
                // Validate bcrypt structure (Rust doesn't).
                const m = trimmed.match(/^\$2[abxy]\$(\d{2})\$[./A-Za-z0-9]{53}$/);
                entry.valid = !!m;
                entry.cost = m ? m[1] : null;
                if (m && parseInt(m[1], 10) < 10) {
                    entry.notes = `Low bcrypt cost factor (${m[1]}) â€” weak against GPU attacks.`;
                }
            }
            candidates.push(entry);
            if (f.prefix === '$1$' && candidates.length > 1) {
                // dedupe overlapping prefix guards
            }
        }
    }

    // 2) Length + charset matching.
    const shape = matchByShape(trimmed);
    if (shape.length) candidates.push(...shape);

    // 3) Structural fallbacks (colon-separated, big base64 blobs, etc.)
    if (candidates.length === 0) {
        const classes = charsetClasses(trimmed);
        const entropy = entropyOfString(trimmed);

        if (trimmed.includes(':') && trimmed.split(':').length >= 3) {
            candidates.push({
                name: 'NTLM/NetNTLM challenge-response (possible)',
                category: 'Network', hashcat: 5600, john: 'netntlmv2', confidence: 'low',
                notes: 'Colon-separated structure â€” typical of captured challenge/response hashes.',
            });
        } else if (trimmed.includes('$') && trimmed.includes('*')) {
            candidates.push({
                name: 'WPA-PSK / RADIUS style',
                category: 'Wireless', hashcat: null, john: 'wpapsk', confidence: 'low',
                notes: '$...* structure seen in WPA or RADIUS hashes.',
            });
        } else if (classes.lower === 0 && classes.upper > 0 && classes.digits === 0 && /^[A-Z0-9]+$/.test(trimmed)) {
            candidates.push({
                name: 'Base32 / alphanumeric token (possible)',
                category: 'Unknown', hashcat: null, john: 'raw', confidence: 'low',
                notes: 'Uppercase alphanumeric body â€” TOTP secrets, API keys, or custom tokens.',
            });
        } else {
            candidates.push({
                name: 'Unknown / custom format',
                category: 'Unknown', hashcat: null, john: 'raw', confidence: 'low',
                notes: `No known envelope matched. Entropy ${entropy.toFixed(2)} bits, ${classes.unicode ? 'contains Unicode' : 'ASCII'}.`,
            });
        }
    }

    // Build the answer list
    const top = candidates.slice(0, 5);
    const sections = [
        kvSection('Input', [
            ['Hash', trimmed.length > 64 ? `${trimmed.slice(0, 32)}â€¦(${trimmed.length} chars)` : trimmed],
            ['Length', `${trimmed.length} chars`],
            ['Entropy', `${entropyOfString(trimmed).toFixed(2)} bits`],
            ['Encoding', /^[0-9a-fA-F]+$/.test(trimmed) ? 'hex' : (/^[A-Za-z0-9+/=]+$/.test(trimmed) && trimmed.length % 4 === 0 ? 'base64 (likely)' : 'text')],
        ]),
    ];

    const rows = top.map((c, i) => [
        String(i + 1),
        c.name,
        c.confidence,
        c.hashcat != null ? `-m ${c.hashcat}` : 'â€”',
        c.john || 'â€”',
        c.valid === false ? 'invalid structure' : (c.notes || 'â€”'),
    ]);
    sections.push(tableSection('Matches (ranked)', ['#', 'Format', 'Confidence', 'Hashcat', 'John', 'Notes'], rows));

    const problems = top.filter((c) => c.valid === false);
    if (problems.length) {
        sections.push(listSection('Validation', problems.map((c) => ({ severity: 'medium', text: `${c.name}: structure invalid for this format.` }))));
    }

    // Suggestion block
    const suggestion = top[0] && top[0].hashcat != null
        ? `hashcat -m ${top[0].hashcat} -a 0 hashes.txt wordlist.txt${top[0].name.includes('bcrypt') || top[0].name.includes('crypt') || top[0].name.includes('scrypt') || top[0].name.includes('argon') ? '  (slow KDF â€” expect low hash/s)' : ''}`
        : 'No Hashcat mode mapped â€” try manual analysis.';
    sections.push(listSection('Next step', [{ severity: 'info', text: suggestion }]));

    return {
        ok: true,
        title: 'Hash Identification',
        subtitle: `${top[0].name}${candidates.length > 1 ? ` (+${candidates.length - 1} alternates)` : ''}`,
        sections,
        raw: { input: trimmed, matches: top, all: candidates },
    };
}

function formatJohnForMode(mode) {
    const map = {
        0: 'raw-md5', 100: 'raw-sha1', 1400: 'raw-sha256', 1700: 'raw-sha512',
        1000: 'nt', 3000: 'lm', 1100: 'mscash', 2100: 'mscash2',
        500: 'md5crypt', 3200: 'bcrypt', 7400: 'sha256crypt', 1800: 'sha512crypt',
        5500: 'netlm', 5600: 'netntlmv2', 13100: 'krb5tgs', 18200: 'krb5asrep',
        22000: 'wpapmkid', 10900: 'pbkdf2', 8900: 'scrypt', 25600: 'yescrypt',
        400: 'phpass', 7900: 'drupal7', 124: 'django', 112: 'oracle11', 131: 'mssql05',
    };
    return map[mode] || 'â€”';
}

module.exports = register({
    id: 'hash-id',
    name: 'Hash Identification',
    description: 'Identify hash types, validate structure, map to Hashcat/John, and suggest an attack.',
    category: 'Credential',
    run: (args) => identifyHash(args.hash || args.input || ''),
});

module.exports.identifyHash = identifyHash;

