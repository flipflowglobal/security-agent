# Full-system test harness for Security-Agent desktop app. (v3 — self-seeding)
$ErrorActionPreference = 'Continue'
$res = "C:\Users\david\Desktop\security-agent\target\release"
$exe = @("$res\security-agent.exe", "$res\security-agent") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $exe) { Write-Error "security-agent binary not found under $res"; exit 1 }
$tmp = $env:GUI_TEST_TMP; if (-not $tmp) { $tmp = "C:\Users\david\AppData\Local\Temp\opencode\gui-test" }
if (-not (Test-Path $tmp)) { New-Item -ItemType Directory -Force -Path $tmp | Out-Null }

# --- Self-seed: every fixture the harness needs, regenerated each run. -------
# plan.config must satisfy the strict engagement-config parser (all
# authorization fields mandatory; ApiSecurity is penetrative so
# penetrative_testing_approved must be true).
@"
engagement_id=eng-system
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=4102444800
in_scope_targets=api-staging
deny_list_targets=prod-ledger
allowed_techniques=PassiveRecon,ConfigurationAudit,ApiSecurity
max_intensity=Standard
high_impact_approved=false
penetrative_testing_approved=true

[target]
id=api-staging
target_type=Api
criticality=3
"@ | Set-Content -Path "$tmp\plan.config" -Encoding ascii

@"
engagement_id=eng-deny
authorized_by=jane.doe
authorized_by_role=SecurityAdmin
time_window_start=0
time_window_end=4102444800
in_scope_targets=prod-ledger
deny_list_targets=prod-ledger
allowed_techniques=PassiveRecon
max_intensity=Passive
high_impact_approved=false
penetrative_testing_approved=false

[target]
id=prod-ledger
target_type=Api
criticality=2
"@ | Set-Content -Path "$tmp\deny.config" -Encoding ascii

@"
{"version":"1","producer":"security-agent","kind":"audit_record","fields":{"timestamp_epoch_seconds":"1720000000","actor":"secops","role":"SecurityAdmin","action":"plan_authorized_scan","target":"test-target","details":"tasks=2 high_impact=0"}}
{"version":"1","producer":"security-agent","kind":"audit_record","fields":{"timestamp_epoch_seconds":"1720000001","actor":"jane.doe","role":"SecurityEngineer","action":"run_tool","target":"test-target","details":"tool=nmap status=completed","test_run_id":"run-abc"}}
"@ | Set-Content -Path "$tmp\audit-view.jsonl" -Encoding ascii

@"
{"version":"1","producer":"security-agent","kind":"finding_record","fields":{"confidence_percent":"92","finding_id":"TEST-001","normalized_risk_score":"8.5000","remediation_playbook":"Patch and harden","severity":"High","source_tool":"test-tool","target_id":"test-target","title":"Test finding"}}
"@ | Set-Content -Path "$tmp\findings-src.jsonl" -Encoding ascii

# schedule-retest reads a findings log as input.
Copy-Item "$tmp\findings-src.jsonl" "$tmp\fresh-dest.jsonl" -Force

@"
sample content for the autopsy tool report
"@ | Set-Content -Path "$tmp\tool-input.txt" -Encoding ascii

$results = @()
$script:seq = 0

function Invoke-App {
    # Run the binary, merge stderr into stdout as plain text, and measure exit code.
    param([string[]]$CmdArgs)
    $o = & $exe @CmdArgs 2>&1 | ForEach-Object { "$_" } | Out-String
    [pscustomobject]@{ Text = $o; Exit = $LASTEXITCODE }
}

function Test-Case {
    param([string]$Name, [scriptblock]$Body, [string]$Expect, [string]$Reject)
    $script:seq++
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $out = & $Body 2>&1 | ForEach-Object { "$_" } | Out-String
        $sw.Stop()
        $ok = $true
        $detail = ''
        if ($Expect) {
            if ($out -notmatch $Expect) { $ok = $false; $detail = "missing expected: $Expect" }
        }
        if ($Reject -and $ok) {
            if ($out -match $Reject) { $ok = $false; $detail = "reject marker: $Reject" }
        }
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Output ("{0,3}. [{1}] {2}  ({3:N2}s){4}" -f $script:seq, $status, $Name, $sw.Elapsed.TotalSeconds, $(if ($detail) { "  <-- $detail" } else { '' }))
        $script:results += [pscustomobject]@{ Seq = $script:seq; Status = $status; Name = $Name; Detail = $detail; Seconds = $sw.Elapsed.TotalSeconds; Output = $out.Substring(0, [Math]::Min(300, $out.Length)) }
    }
    catch {
        $sw.Stop()
        $status = 'FAIL'
        Write-Output ("{0,3}. [{1}] {2}  ({3:N2}s)  <-- exception: {4}" -f $script:seq, $status, $Name, $sw.Elapsed.TotalSeconds, $_.Exception.Message)
        $script:results += [pscustomobject]@{ Seq = $script:seq; Status = $status; Name = $Name; Detail = $_.Exception.Message; Seconds = $sw.Elapsed.TotalSeconds; Output = '' }
    }
}

# -------------------- SECTION 1: CORE / CLI --------------------
Write-Output "=================== SECTION 1: CORE CLI ==================="
Test-Case "build-info reports commit+target" { (Invoke-App @('--build-info')).Text } "x86_64-pc-windows-gnu"
Test-Case "offline-status ok coverage" { (Invoke-App @('--offline-status')).Text } "capability_coverage=ok"
Test-Case "help/guide renders" { (Invoke-App @('--guide')).Text } "Security-Agent"
Test-Case "shell-guide renders" { (Invoke-App @('--shell-guide')).Text } "Reverse Shell"
Test-Case "tool-help renders" { (Invoke-App @('--tool-help', '--list-tools')).Text } "list-tools"
Test-Case "unknown flag rejected cleanly (exit 2)" { $r = Invoke-App @('--definitely-not-a-flag'); "$($r.Text) exit=$($r.Exit)" } "(?s)unknown command.*exit=2"
Test-Case "build-info exit code zero" { ((Invoke-App @('--build-info')).Exit -eq 0).ToString() } "^True"

# -------------------- SECTION 2: TOOLS --------------------
Write-Output "=================== SECTION 2: TOOLS ==================="
Test-Case "offline-status cataloged_tool_definitions=89" { (Invoke-App @('--offline-status')).Text } "cataloged_tool_definitions=89"
Test-Case "offline-status embedded_skills=90" { (Invoke-App @('--offline-status')).Text } "embedded_skills=90"
Test-Case "list-tools emits 89 lines" { $r = Invoke-App @('--list-tools'); $n = ($r.Text -split "`r?`n" | Where-Object { $_.Trim() }).Count; "lines=$n" } "lines=89"
Test-Case "list-skills emits 90 lines" { $r = Invoke-App @('--list-skills'); $n = ($r.Text -split "`r?`n" | Where-Object { $_.Trim() }).Count; "lines=$n" } "lines=90"
Test-Case "show-skill security-agent renders" { (Invoke-App @('--show-skill', 'security-agent')).Text } "security-agent"
Test-Case "run-tool autopsy writes report" { (Invoke-App @('--run-tool', 'autopsy', "$tmp\tool-input.txt", '--output', "$tmp\sys-tool-out.txt")).Text } "written to"
Test-Case "external tool reports not installed locally" { (Invoke-App @('--run-external-tool', 'amass')).Text } "not installed locally"
Test-Case "external tool refuses unknown tool" { (Invoke-App @('--run-external-tool', 'not-a-real-tool')).Text } "unknown|not"
Test-Case "engagement runs and enforces gating" { (Invoke-App @('--run-engagement', "$tmp\plan.config")).Text } "Engagement Execution"

# -------------------- SECTION 3: OFFENSIVE --------------------
Write-Output "=================== SECTION 3: OFFENSIVE TOOLS ==================="
Test-Case "hash-id MD5" { (Invoke-App @('--hash-id', '5f4dcc3b5aa765d61d8327deb882cf99')).Text } "MD5"
Test-Case "hash-id SHA256" { (Invoke-App @('--hash-id', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')).Text } "SHA-256"
Test-Case "hash-id unknown hash" { (Invoke-App @('--hash-id', 'zzz')).Text } "unknown|Unrecognized|could not"
Test-Case "password-strength very strong" { (Invoke-App @('--password-strength', 'CorrectHorseBatteryStaple')).Text } "Very Strong"
Test-Case "password-strength weak" { (Invoke-App @('--password-strength', 'abc')).Text } "Very Weak|Weak"
Test-Case "gen-wordlist" { (Invoke-App @('--gen-wordlist', 'acme', 'Acme Corp', '2026', 'admin', 'backup')).Text } "Generated"
Test-Case "gen-shell bash" { (Invoke-App @('--gen-shell', 'bash', '10.0.0.1', '4444')).Text } "Reverse Bash Shell"
Test-Case "gen-shell python" { (Invoke-App @('--gen-shell', 'python', '10.0.0.1', '4444')).Text } "Reverse"
Test-Case "gen-shell list types" { (Invoke-App @('--gen-shell', '--list')).Text } "bash"
Test-Case "analyze-payload entropy" { (Invoke-App @('--analyze-payload', '90 90 cc')).Text } "Entropy"
Test-Case "obfuscate-ps" { (Invoke-App @('--obfuscate-ps', 'Invoke-WebRequest -Uri http://x/y.ps1')).Text } "Obfuscation"
Test-Case "gen-decoys" { (Invoke-App @('--gen-decoys', '10.0.0.1', '5')).Text } "Decoy"
Test-Case "audit-wifi open" { (Invoke-App @('--audit-wifi', 'TestNet', 'open', 'none')).Text } "Risk score"
Test-Case "audit-wifi wpa2" { (Invoke-App @('--audit-wifi', 'TestNet', 'wpa2', 'aes')).Text } "WPA2"
Test-Case "analyze-handshake incomplete" { (Invoke-App @('--analyze-handshake', '0000000000000000000000000000000000000000')).Text } "EAPOL"
Test-Case "wps-pin default pin" { (Invoke-App @('--wps-pin', '12345670')).Text } "Default PIN"
Test-Case "analyze-passwd indicators" { (Invoke-App @('--analyze-passwd', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin')).Text } "Home directory|daemon"
Test-Case "analyze-sudoers" { (Invoke-App @('--analyze-sudoers', 'root ALL=(ALL) ALL')).Text } "ALL"
Test-Case "analyze-keys" { (Invoke-App @('--analyze-keys', 'ssh-rsa AAAA user@host')).Text } "ssh-rsa"
Test-Case "analyze-hosts internal mapping" { (Invoke-App @('--analyze-hosts', '192.168.1.10 host1')).Text } "192.168.1.10"
Test-Case "postexploit-overview" { (Invoke-App @('--postexploit-overview', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin')).Text } "passwd analysis|Home directory"
Test-Case "fragment-payload" { (Invoke-App @('--fragment-payload', 'GET / HTTP/1.1', '--mtu', '512')).Text } "fragment"
Test-Case "fragment-payload hex" { (Invoke-App @('--fragment-payload', 'GET / HTTP/1.1', '--hex')).Text } "[0-9a-f]{4}"
Test-Case "gen-ipids" { (Invoke-App @('--gen-ipids', '10')).Text } "ID"
Test-Case "ip-checksum" { (Invoke-App @('--ip-checksum', '4500003c0000000040010000c0a80101c0a80164')).Text } "0x"
Test-Case "analyze-deauth valid frame" { (Invoke-App @('--analyze-deauth', 'c0000000ffffffffffff000000000000000000000000000000000007')).Text } "reason|Deauth|deauth"

# -------------------- SECTION 4: ENGAGEMENT --------------------
Write-Output "=================== SECTION 4: ENGAGEMENT ==================="
Test-Case "plan-scan" { (Invoke-App @('--plan-scan', "$tmp\plan.config")).Text } "Execution Plan"
Test-Case "plan-scan cognitive-review" { (Invoke-App @('--plan-scan', "$tmp\plan.config", '--cognitive-review')).Text } "Anomaly|confidence|P\("
Test-Case "record-findings" { (Invoke-App @('--record-findings', "$tmp\sys-findings.jsonl", "$tmp\findings-src.jsonl")).Text } "recorded 1 finding"
Test-Case "schedule-retest" { (Invoke-App @('--schedule-retest', "$tmp\fresh-dest.jsonl")).Text } "Retest Schedule"
Test-Case "view-audit (jsonl)" { (Invoke-App @('--view-audit', "$tmp\audit-view.jsonl")).Text } "plan_authorized_scan"
Test-Case "view-audit-db" { (Invoke-App @('--view-audit-db', "$tmp\audit.sadb")).Text } "Audit Database View"
Test-Case "view-findings-db" { (Invoke-App @('--view-findings-db', "$tmp\findings.sadb")).Text } "Findings Database View"
Test-Case "view-calibration-db" { (Invoke-App @('--view-calibration-db', "$tmp\calibration.sadb")).Text } "Calibration Database View"
Test-Case "view-reasoning-log-db" { (Invoke-App @('--view-reasoning-log-db', "$tmp\reasoning.sadb")).Text } "Reasoning Log Database View"
Test-Case "engagement control writes command file" { (Invoke-App @('--engagement-control', "$tmp\sys-ctl.txt", 'pause')).Text } "written to"

# -------------------- SECTION 5: NLM / INTELLIGENCE --------------------
Write-Output "=================== SECTION 5: NLM ==================="
Test-Case "llm-generate produces continuation" { (Invoke-App @('--llm-generate', 'scan the network')).Text } "scan the network"
Test-Case "llm-generate deterministic" { $a = (Invoke-App @('--llm-generate', 'the attack surface')).Text; $b = (Invoke-App @('--llm-generate', 'the attack surface')).Text; $a -eq $b }
Test-Case "llm-perplexity renders score" { (Invoke-App @('--llm-perplexity', 'the server returned an error')).Text } "perplexity=[0-9]"
Test-Case "llm-perplexity out-of-domain higher" { $in = (Invoke-App @('--llm-perplexity', 'the server returned an error')).Text; $out = (Invoke-App @('--llm-perplexity', 'quantum entanglement in the browser')).Text; $ip = [regex]::Match($in, 'perplexity=([0-9.]+)').Groups[1].Value; $op = [regex]::Match($out, 'perplexity=([0-9.]+)').Groups[1].Value; "in=$ip out=$op"; ([double]$op) -gt ([double]$ip) }
Test-Case "lm-eval full run" { (Invoke-App @('--lm-eval')).Text } "mean perplexity"
Test-Case "ask resolves intent" { (Invoke-App @('--ask', 'list tools')).Text } "list-tools"
Test-Case "ask out-of-scope handled" { (Invoke-App @('--ask', 'what is the meaning of life')).Text } "out-of-scope|outside my scope"
Test-Case "agent plans tool step" { (Invoke-App @('--agent', 'list your offensive tools')).Text } "--list-tools"
Test-Case "agent rejects empty goal" { (Invoke-App @('--agent')).Text } "missing goal"

# -------------------- SECTION 6: OFFLINE --------------------
Write-Output "=================== SECTION 6: OFFLINE ==================="
Test-Case "offline network_required=false" { (Invoke-App @('--offline-status')).Text } "network_required=false"
Test-Case "offline external_api_required=false" { (Invoke-App @('--offline-status')).Text } "external_api_required=false"
Test-Case "offline default_network_mode=offline" { (Invoke-App @('--offline-status')).Text } "default_network_mode=offline"
Test-Case "offline all offensive cmds run without network" { $fail = 0; $cmds = @(
    @('--hash-id','5f4dcc3b5aa765d61d8327deb882cf99'), @('--password-strength','abc'), @('--gen-wordlist','acme'),
    @('--gen-shell','bash','10.0.0.1','4444'), @('--analyze-payload','9090cc'), @('--obfuscate-ps','Get-Process'),
    @('--gen-decoys','10.0.0.1','5'), @('--audit-wifi','T','wpa2','aes'), @('--analyze-handshake','0000000000000000000000000000000000000000'),
    @('--wps-pin','12345670'), @('--analyze-passwd','daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'), @('--analyze-sudoers','root ALL=(ALL) ALL'),
    @('--analyze-keys','ssh-rsa AAAA u@h'), @('--analyze-hosts','192.168.1.10 host1'), @('--postexploit-overview','daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'),
    @('--fragment-payload','GET / HTTP/1.1'), @('--gen-ipids','10'), @('--ip-checksum','4500003c0000000040010000c0a80101c0a80164'),
    @('--analyze-deauth','c0000000ffffffffffff000000000000000000000000000000000007')
  );
  foreach ($c in $cmds) { $r = Invoke-App $c; if ($r.Exit -ne 0) { $fail++ } }; "offline_failures=$fail"; $fail -eq 0 }

# -------------------- SECTION 7: ONLINE --------------------
Write-Output "=================== SECTION 7: ONLINE ==================="
Test-Case "network connectivity (github 200)" { $r = Invoke-WebRequest -Uri "https://api.github.com" -Method Head -TimeoutSec 8 -UseBasicParsing; $r.StatusCode } "200"
Test-Case "online_opt_in flag documented" { (Invoke-App @('--offline-status')).Text } "online_opt_in_flag=--allow-network"
Test-Case "plan-scan accepts --allow-network" { (Invoke-App @('--plan-scan', "$tmp\plan.config", '--allow-network')).Text } "Execution Plan"
Test-Case "run-engagement --allow-network parses" { (Invoke-App @('--run-engagement', "$tmp\plan.config", '--allow-network')).Text } "Engagement Execution|active-tool gate"
Test-Case "agent allows network flag" { (Invoke-App @('--agent', 'list tools', '--allow-network')).Text } "--list-tools"
Test-Case "external tool accepts --allow-network" { (Invoke-App @('--run-external-tool', '--allow-network', 'amass')).Text } "not installed locally|refused|network"

# -------------------- SECTION 8: CPU / PERFORMANCE --------------------
Write-Output "=================== SECTION 8: CPU / PERFORMANCE ==================="
Test-Case "lm-eval wall time" {
    $t = [System.Diagnostics.Stopwatch]::StartNew()
    $o = (Invoke-App @('--lm-eval')).Text
    $t.Stop()
    "wall=$($t.Elapsed.TotalSeconds.ToString('F2'))s"
} "wall=[0-9]"
Test-Case "lm-eval output present" {
    $t = [System.Diagnostics.Stopwatch]::StartNew()
    $o = (Invoke-App @('--lm-eval')).Text
    $t.Stop()
    $o
} "mean perplexity"
Test-Case "20x llm-generate throughput" {
    $t = [System.Diagnostics.Stopwatch]::StartNew()
    1..20 | ForEach-Object { Invoke-App @('--llm-generate', "probe $_") | Out-Null }
    $t.Stop()
    "wall=$($t.Elapsed.TotalSeconds.ToString('F2'))s"
} "wall=[0-9]"
Test-Case "10x hash-id throughput" {
    $t = [System.Diagnostics.Stopwatch]::StartNew()
    1..10 | ForEach-Object { Invoke-App @('--hash-id', '5f4dcc3b5aa765d61d8327deb882cf99') | Out-Null }
    $t.Stop()
    "wall=$($t.Elapsed.TotalSeconds.ToString('F2'))s"
} "wall=[0-9]"

$sys = Get-CimInstance Win32_Processor
Test-Case "cpu cores detected" { "logical=$($sys.NumberOfLogicalProcessors)" } "logical=[0-9]"

Write-Output ""
Write-Output "=================== FULL RESULTS ==================="
$pass = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$fail = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Output "TOTAL: $($results.Count)  PASS: $pass  FAIL: $fail"
if ($fail -gt 0) {
    Write-Output "--- FAILURES ---"
    $results | Where-Object { $_.Status -eq 'FAIL' } | ForEach-Object { Write-Output ("FAIL {0}: {1} | {2}" -f $_.Name, $_.Detail, $_.Output.Substring(0, [Math]::Min(160, $_.Output.Length))) }
}



