# Security-Agent — End-User License Agreement

**IMPORTANT — READ CAREFULLY BEFORE INSTALLING, ACCESSING, OR USING SECURITY-AGENT.**

This End-User License Agreement ("Agreement") is a legal agreement between
you, either an individual or a single entity ("Licensee" or "you"), and
FlipFlow Global ("Licensor," "we," or "us") for the Security-Agent software,
including the compiled binary, the desktop application, associated
documentation, and any updates provided to you (collectively, the
"Software").

By installing, copying, or otherwise using the Software, you agree to be
bound by the terms of this Agreement. If you do not agree, do not install or
use the Software.

This Agreement supplements — and does not replace — the source-code license
in [`LICENSE`](./LICENSE) (Business Source License 1.1, "BSL"). The BSL
governs your rights to the source code itself, including the Additional
Grant for development, testing, research, and non-commercial evaluation. If
you have purchased a **commercial license** from the Licensor for production
or commercial use, this Agreement is the commercial license referenced in
the BSL's Use Restrictions and governs that use; its terms control over the
BSL to the extent of any conflict for licensed commercial deployments.

---

## 1. Nature of the Software

Security-Agent is a **dual-use security testing tool**. It orchestrates
offensive and defensive security tooling — including network scanners,
web/API scanners, credential-testing tools, exploitation frameworks, payload
generators, and network listeners — capable of identifying, exploiting, and
interacting with vulnerabilities in computer systems, networks, and
applications. This capability is powerful and, if misused, can cause harm,
violate the law, and create civil and criminal liability for the user.

You acknowledge that you understand this nature of the Software before
proceeding.

## 2. Authorized Use Only

**You may use the Software only against systems, networks, applications, and
accounts that you own, or for which you have obtained prior, explicit,
written authorization** from the owner or operator to perform the specific
security testing activities you intend to run (a signed rules-of-engagement,
statement of work, penetration-test authorization letter, or equivalent).

You agree that you will:

- Confirm the scope, systems, and time window of your authorization before
  each engagement, and configure the Software's engagement profile
  (authorized targets, technique allow-list, intensity caps, and time
  window) to match that authorization exactly.
- Not use the Software against any system, network, or account for which
  you lack such authorization, including systems you do not own that appear
  to be "open," misconfigured, or otherwise accessible.
- Not use the Software to violate the Computer Fraud and Abuse Act (18
  U.S.C. § 1030), the UK Computer Misuse Act 1990, the EU/national
  equivalents, or any other applicable computer-crime, data-protection, or
  telecommunications law in your jurisdiction or the target's jurisdiction.
- Not use the Software to disrupt, degrade, or deny service to any system
  outside the scope and intensity limits of your authorization, to exfiltrate
  data beyond what your authorization permits, or to cause damage to any
  system.
- Not use the Software's offensive capabilities (exploitation, payload
  generation, credential attacks, listeners, and related tooling) for any
  unlawful purpose, including unauthorized access, ransomware, malware
  distribution, fraud, or attacks on critical infrastructure.
- Retain the audit records, evidence, and engagement configuration the
  Software produces for each engagement, and be able to produce your
  authorization on request.

The Software's live/active tooling requires an explicit, per-invocation
opt-in (`--allow-network`) on top of engagement authorization, and is
offline by default. **This is a safety control, not a substitute for your
own legal authorization** — removing or bypassing it does not change your
obligations under this section.

**Violation of this Section 2 immediately and automatically terminates your
license to use the Software**, without prejudice to any other remedy
available to the Licensor or any third party.

## 3. License Grant (Commercial Licensees)

Subject to your compliance with this Agreement and payment of any applicable
fees, the Licensor grants you a non-exclusive, non-transferable, revocable
license to install and use the Software for your own internal security
testing and assessment purposes, in accordance with the license tier you
purchased (e.g., named-user or per-organization, as stated on your order
confirmation or commercial license certificate).

You may not: (a) resell, sublicense, rent, or lease the Software to a third
party; (b) use the Software to provide a competing managed-security or
scanning-as-a-service product without a separate agreement; (c) remove or
alter any proprietary notices; or (d) use the Software in a manner that
exceeds your licensed seat/instance count.

Rights not expressly granted are reserved by the Licensor.

## 4. Third-Party Tools

The Software orchestrates and, where present on the host system, invokes
third-party security tools (for example: `nmap`, `masscan`, `nuclei`,
`gobuster`, `feroxbuster`, `ffuf`, `nikto`, `whatweb`, `wpscan`, `subfinder`,
`sqlmap`, `hydra`, `semgrep`, `jadx`, and others listed in the tool catalog).
Each such tool is licensed to you separately under its own license terms by
its respective authors — the Software does not grant you any rights to
these third-party tools, and you are responsible for obtaining and
complying with the license of any third-party tool you install and use
through the Software.

## 5. Disclaimer of Warranty

THE SOFTWARE IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. THE LICENSOR
DOES NOT WARRANT THAT THE SOFTWARE WILL DETECT ALL VULNERABILITIES, THAT ITS
FINDINGS ARE COMPLETE OR FREE OF FALSE POSITIVES/NEGATIVES, THAT IT WILL BE
UNINTERRUPTED OR ERROR-FREE, OR THAT IT WILL NOT CAUSE UNINTENDED EFFECTS ON
A TARGET SYSTEM (INCLUDING SERVICE DISRUPTION) WHEN USED FOR ACTIVE TESTING.
YOU ARE SOLELY RESPONSIBLE FOR EVALUATING THE SOFTWARE'S SUITABILITY FOR
YOUR ENGAGEMENT AND FOR ANY DECISIONS MADE IN RELIANCE ON ITS OUTPUT.

## 6. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE
LICENSOR BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR
PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS, REVENUE, DATA, OR BUSINESS
OPPORTUNITY, ARISING OUT OF OR RELATED TO YOUR USE OF (OR INABILITY TO USE)
THE SOFTWARE, INCLUDING DAMAGE TO OR DISRUPTION OF ANY TARGET SYSTEM,
REGARDLESS OF THE THEORY OF LIABILITY, EVEN IF THE LICENSOR HAS BEEN ADVISED
OF THE POSSIBILITY OF SUCH DAMAGES. THE LICENSOR'S TOTAL AGGREGATE LIABILITY
UNDER THIS AGREEMENT SHALL NOT EXCEED THE AMOUNT YOU PAID FOR THE LICENSE IN
THE TWELVE (12) MONTHS PRECEDING THE CLAIM.

Some jurisdictions do not allow the exclusion or limitation of certain
damages, so some of the above limitations may not apply to you.

## 7. Indemnification

You agree to indemnify, defend, and hold harmless the Licensor and its
officers, employees, and contributors from any claim, demand, loss, or
liability (including reasonable legal fees) arising out of: (a) your use of
the Software against any system without proper authorization; (b) your
breach of this Agreement; or (c) your violation of any applicable law in
connection with your use of the Software.

## 8. Export Control and Sanctions Compliance

The Software may be subject to export control and economic sanctions laws,
including the U.S. Export Administration Regulations (EAR) and sanctions
programs administered by the U.S. Treasury's Office of Foreign Assets
Control (OFAC), the EU Dual-Use Regulation, and equivalent regimes in other
jurisdictions, because it includes intrusion, exploitation, and
"cybersecurity item" functionality (e.g., payload generation and network
exploitation tooling) that is commonly export-controlled.

You represent and warrant that:

- You are not located in, and will not export, re-export, or provide access
  to the Software to any country, region, or party subject to comprehensive
  U.S. or applicable sanctions or export embargoes.
- You are not listed on any U.S. government restricted-party list
  (including OFAC's Specially Designated Nationals list, the U.S. Commerce
  Department's Entity List, or the Denied Persons List) or equivalent list
  under applicable law.
- You will not use the Software for the development, production, or use of
  chemical, biological, or nuclear weapons, or missile technology, and will
  not provide the Software to any end use or end user prohibited by
  applicable export control law.

**This section is general guidance, not legal advice.** Export
classification is fact-specific; if you intend to distribute the Software
internationally or to government/defense customers, obtain a formal export
classification opinion (e.g., a commodity classification / ECCN
determination) from qualified export-control counsel before distribution.

## 9. Data and Telemetry

The Software is offline-by-default and does not transmit engagement data,
findings, or telemetry to the Licensor. Any network activity the Software
performs is limited to the tooling and targets you explicitly configure and
authorize. If a future version introduces optional telemetry or update
checks, it will be disclosed and off by default unless you opt in.

## 10. Term and Termination

This Agreement is effective until terminated. Your rights under this
Agreement terminate automatically, without notice, if you breach any term —
in particular Section 2 (Authorized Use Only). Upon termination, you must
stop using the Software and destroy all copies in your possession. Sections
5, 6, 7, 8, and 11 survive termination.

## 11. General

- **Governing Law:** [Licensor to specify governing jurisdiction], excluding
  its conflict-of-laws rules.
- **Entire Agreement:** This Agreement, together with the `LICENSE` file and
  any signed commercial order/license certificate, is the entire agreement
  between you and the Licensor regarding the Software and supersedes any
  prior agreements.
- **Severability:** If any provision is held unenforceable, the remaining
  provisions remain in full effect.
- **No Waiver:** Failure to enforce any provision is not a waiver of the
  right to enforce it later.
- **Contact:** Questions about licensing or this Agreement can be directed
  to `[INSERT LICENSING/LEGAL CONTACT EMAIL]`.

---

*This document is a template provided for convenience and does not
constitute legal advice. Before offering the Software for sale, have this
Agreement — and the governing-law, indemnification, and export-control
sections in particular — reviewed by a licensed attorney in your
jurisdiction and any jurisdiction where you plan to sell.*
