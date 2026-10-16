# Can I trust IDWolf on my servers?

You shouldn't have to take our word for it. This page says what IDWolf does,
how to check that before running it, and how to get evidence while it runs.

## Reporting a vulnerability

Please report security issues privately, not in a public issue. Use GitHub's
**"Report a vulnerability"** button under the repository's
[Security tab](https://github.com/g4bri-3l3/IDWolf/security/advisories/new)
(Private Vulnerability Reporting). Include the affected file and version, how to
reproduce it, and the impact. You'll get an acknowledgement, and once a fix is
out the advisory is published with credit if you want it. Please don't include
real directory data in the report.

## What it does, and what it never does

- **AD: reads only.** The collector uses `Get-AD*` cmdlets, reads SYSVOL (files and the permissions of the NETLOGON and Policies folders) and
  asks DNS, DHCP, `repadmin` and `w32tm` (time) for status. With admin rights on
  the DCs it also reads, over CIM, their free disk space, which core services
  are running, the state of Print Spooler and WebClient, the NetBIOS setting
  of each network adapter and the OS build. For the build it reads one registry
  value (the update revision, `UBR`) through `StdRegProv`; the safety review
  fails on any CIM method other than a registry read. On each AD CS CA host it
  reads, the same way, the CA policy and interface flags, the CA permissions and
  the installed roles (ESC6/7/8/11/16). On the DCs it also reads the state of the
  EFS, DFS Namespace and EventLog services and looks for the coercion interface
  UUIDs in the RPC filter store (BFE, read-only); no RPC interface is ever
  called. There is no command in the code
  that creates, changes or deletes anything in AD, DNS, DHCP or GPOs.
- **Entra ID: reads only.** Read-only Graph scopes and GET requests only.
- **No binaries, no hidden code.** Plain PowerShell you can read. No
  `Invoke-Expression`, no Base64, no encoded commands, nothing downloaded and
  run, no services, scheduled tasks or registry changes.
- **Writes only its own output**: the snapshot JSON, the report files, the
  zip (or, with a password, the AES-256 encrypted `.idwolf` package; the password is read hidden and never stored) for analysis elsewhere if you ask for it, the wizard's
  remembered answers (`%LOCALAPPDATA%\IDWolf\wizard.json`: choices and paths from a fixed list of
  keys, never a password, key or directory data; not used by `-Snapshot` or scheduled runs), and temporary folders for the
  BloodHound zip and for reading that zip (deleted right after). The scheduled-run script also
  deletes its own old run folders (only names like `ad_20261006_020000`
  inside the output folder you give it).
- **Doesn't schedule itself.** `Invoke-IDWolfScheduled.ps1` is meant for a
  scheduled task, but creating the task is left to you; the safety review
  fails on any code that registers one.
- **Network**: the domain controllers (LDAP/ADWS, SMB for SYSVOL, RPC for DNS
  and replication status, NTP for the clock check, CIM/WinRM for disk and services; before an AD
  collection the launcher also reads the account's groups and the domain head's permissions over
  LDAP, to show what it can do), `graph.microsoft.com` for the Entra collector, and
  Gemini only if you say yes (or pass `-SendToAI`), after every name has been
  replaced by a token. The exact text is saved next to the report
  (`<report>_ai_prompt.txt`) before you're asked, and the reply after
  (`<report>_ai_response.json`), so you can see what left and what came back.
  The Gemini key comes from `-ApiKey`, `GEMINI_API_KEY` or a hidden prompt; it
  is only kept in memory for that run and never written to disk.
- **`tests\lab` is the one exception, and it isn't part of the tool.** It holds
  two helpers for a throw-away lab domain that DO write to AD
  (`New-LabAttackPaths.ps1` plants test accounts and rights,
  `New-LabChildDomain.ps1` promotes a server), plus one that only reads a
  snapshot. They never run on their own, nothing else calls them, they ask you
  to type the domain name before changing anything, and the safety review
  doesn't cover `tests\`. Delete the folder if you don't want them on a server.
- **Installs something only if you ask**: RSAT, the Graph authentication module
  or DSInternals, each with a prompt or `-InstallModules`.
- **No secrets in the output.** Passwords found in descriptions are masked at
  collection, SYSVOL hits are kept by path only, the password report holds
  account names and never a hash.

## It doesn't need to run on a DC

- `Collect-ADSnapshot.ps1` runs on any domain-joined machine: a workstation, a
  jump host or a PAW. A standard user gets most of it; `-Credential` lends a
  delegated account for the rest.
- `IDWolf.ps1` (the analysis) runs anywhere, even off the network.
- `Export-PasswordQuality.ps1` is the only piece that touches password hashes.
  It needs DCSync rights, not a DC logon, and it can work offline on a copy of
  `ntds.dit` plus the SYSTEM hive (for example an IFM set) on an isolated
  machine. Or skip it entirely: everything else works without it.

## Check it before running it

1. **Run the safety review.** It reads the code without running it and lists
   every command it calls, every place it writes and every address it talks
   to, then fails if anything is outside the reviewed list:

   ```powershell
   .\Test-IDWolfSafety.ps1
   ```

   It flags any command that would change AD, Entra, DNS, DHCP or GPOs, any
   command nobody reviewed, run-time code tricks (`iex`, Base64, encoded
   commands, downloads, `Start-Process`, scheduled tasks), Graph requests that
   aren't GET, and web addresses other than Microsoft Graph, Gemini and the
   MITRE links in the report. The one command that opens a file with its
   default program, `Invoke-Item`, is allowed only in `lib\Wizard.ps1`, which
   uses it to open the `.html` report the run has just written, after asking.
   The regression suite checks that it really catches these, on a
   deliberately tampered copy.

2. **Run it from a copy you got from the repository, and review that copy.**
   IDWolf itself is **not code-signed**, and there are no published hashes or
   signed release build. Take the code from the repository (a clone at a commit
   you looked at, or the zip of a release) and run the review on that copy. A
   modified copy could modify the review too, which is why, if your
   organization wants a guarantee, the strongest option is yours to apply:

3. **Sign your reviewed copy with your own certificate** (optional, and
   something only you can do: it needs a code-signing certificate that your
   machines trust, for example from your internal CA):

   ```powershell
   $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
   Get-ChildItem -Recurse -Include *.ps1, *.psm1 | Set-AuthenticodeSignature -Certificate $cert -TimestampServer http://timestamp.digicert.com
   ```

   With the `AllSigned` policy on the target machines, a file changed after
   you signed it won't run at all. It also takes care of the "not digitally
   signed" message. Sign again after every change to the code. Without a
   certificate, skip this step: everything else on this page still applies.

4. **Read it.** It's PowerShell: the AD collector is one file, the checks are
   in `lib\`. `Test-IDWolfSafety.ps1` tells you where each command is used, so
   you can go straight to the parts that matter.

5. **Run it in a lab first**, on a copy of your domain or a test domain.

## Get evidence while it runs

- **PowerShell logging.** With script block logging on (event 4104 in
  *Microsoft-Windows-PowerShell/Operational*), every piece of code that runs
  is recorded, including the parts inside the spinner. `Start-Transcript`
  keeps the console output.
- **No directory changes.** With "Audit Directory Service Changes" enabled on
  the DCs, any change shows up as event 5136, 5137, 5139 or 5141. Filter by the
  account that ran IDWolf: there should be none.
- **Network.** Firewall or EDR logs should show only the DC, plus
  `graph.microsoft.com` for Entra and Gemini if you agreed to it.

## The third-party pieces

IDWolf calls three modules it doesn't ship:

- **ActiveDirectory and DnsServer (RSAT)**: Microsoft.
- **Microsoft.Graph.Authentication**: Microsoft, from the PowerShell Gallery.
- **DSInternals**: open source (github.com/MichaelGrafnetter/DSInternals),
  widely used in AD audits. It can read password hashes, which is exactly why
  EDR products flag it. IDWolf only calls its quality test and keeps account
  names. Clear it with your security team, use the offline mode, or don't use
  it.

## What the safety review can't do

It proves which commands the code can call. It can't prove that every line
is correct, and it can't vouch for the modules above. That's what reading the
code, the lab run and the logs are for. Together they leave very little to
take on trust.
