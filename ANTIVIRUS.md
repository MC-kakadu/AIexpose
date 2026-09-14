# Why your antivirus flagged this

If Windows Defender or another endpoint product quarantined `aiexpose`, that is
not surprising and it is worth understanding rather than clicking through.

## If Kaspersky blocks it: "application showing characteristics of malicious activity"

That wording means **behaviour detection**, not a signature match. System Watcher
judged what the program did while it ran, so removing suspicious strings from
the file cannot help — a different layer decided.

Version 0.10.0 removes the behaviour it was judging on:

| Was | Now |
|---|---|
| spawned `powershell.exe` to list listening sockets | calls `GetExtendedTcpTable` in process |
| spawned PowerShell or `tasklist` for process names | one `CreateToolhelp32Snapshot` call |
| spawned `powershell` / `reg.exe` for firewall state | reads the registry through the API |
| spawned PowerShell per service for command lines | dropped; the check uses environment variables |
| read PowerShell history looking for API keys | opt-in, `--scan-history` |

A normal scan now starts **no child processes at all**. After it finishes, the
report is opened in your browser through `ShellExecuteW` — the call Explorer
makes when you double-click a file — rather than by running `cmd /c start` or
PowerShell. `--no-open` turns even that off. That matters more than
any string: an unsigned executable launching `powershell.exe` to enumerate the
host is one of the strongest behavioural signals there is, and reading
`ConsoleHost_history.txt` for credentials is catalogued as an attack technique
in its own right.

If a scan is still blocked, find out what is objecting:

```
aiexpose --safe-mode
```

Safe mode starts no helper programs, reads no credential store and does not
query the router. If that runs and a normal scan does not, the remaining
difference is the router query (`--no-upnp` to skip it) — please tell us, because
that is useful information.

Report it to Kaspersky at <https://opentip.kaspersky.com>, and add an exclusion
for the single executable path if you need it working today.

## Double-clicking is a different test from running it in a terminal

If a scan ran cleanly from PowerShell, that does **not** establish that the same
scan will run cleanly on a double-click. Three things differ, and only one of
them is the program:

| | Terminal | Double-click |
|---|---|---|
| **SmartScreen** | not consulted | **"Windows protected your PC"** for any downloaded, unsigned, low-reputation exe |
| **Parent process** | `powershell.exe` / `cmd.exe` | `explorer.exe` |
| **What the run does** | scan only | scan, **write an HTML report**, **open the browser** |

The first one is the one that actually stops people, it stops the program
*before it runs at all*, and it has nothing to do with which flags are set. It
is a reputation gate, not a malware verdict: "More info" -> "Run anyway"
dismisses it, and a code-signing certificate removes it. See
[What we are doing about it](#what-we-are-doing-about-it).

The second matters to behavioural engines. An unknown unsigned binary started
by Explorer that immediately begins reading documents is closer to the
double-clicked-attachment pattern than the same binary started deliberately
from a shell.

So test one variable at a time. Double-click it **without** `--scan-docs` first.
If that is clean, the launch path is fine and anything that breaks afterwards
is the document search.

### Why `--scan-docs` is not the double-click default

It is asked for at the prompt instead, and the reason is not mainly antivirus:
a behavioural engine watches file reads, and those reads are identical whether
a flag or a keystroke caused them. Consent does not make the I/O look
different, and nobody should claim otherwise.

The reason is that the report says, in its own words, that your documents are
not searched by default because reading every text file in them is what an
information stealer does. Turning that on silently for everyone who
double-clicks would make the sentence false for most of the people reading it.

There is one real, if second-order, benefit. On a double-click the scan now
reads documents **after** a person has answered a question, several seconds in,
rather than in the first moments of an unattended process. Heuristics that
weight what a new process does immediately after launch see less. It is a
small effect and it is not the reason for the design.

### One thing that was worth fixing

Choosing where to put the report used to mean creating a hidden file beside the
executable and deleting it again, to find out whether the folder was writable.
That is a poor thing to do in a folder Windows protects. Create-then-delete in
Desktop or Documents is the canary behaviour Controlled Folder Access exists to
catch, and it is the shape of a ransomware probe, and it happened on **exactly**
the launch path most likely to be watched: an unsigned binary, started by
Explorer, on someone's Desktop.

Since 0.19.1 the report is simply written, and somewhere else if that fails.
Nothing is created that is not meant to stay.

Controlled Folder Access blocks **writes**, not reads, so the document search
itself is unaffected by it. aiexpose never writes into Desktop, Documents or
Downloads.

## What we measured

Two builds of version 0.7.0, from the same source, with the same flags, on the
same Windows machine running Kaspersky and Microsoft Defender, launched minutes
apart:

| Build | Result |
|---|---|
| rules compiled in | quarantined and deleted within seconds |
| rules loaded at runtime | ran normally |

The only difference between them was the string table. That is why the default
download no longer embeds the rules, and why they arrive as a signed JSON file
through `--update-feed` instead.

## This is not a mysterious false positive

Read what this tool does, then read what an information stealer does:

| aiexpose | an infostealer |
|---|---|
| Enumerates every listening TCP socket and the process behind it | the same |
| Scans shell history, shell profiles and `.env` files for API keys | the same |
| Carries patterns for `Login Data`, `wallet.dat`, `.ssh/id_rsa`, Discord webhooks | the same, as targets |
| Talks UPnP to your router and can delete a port forward | the same, to open one |
| Writes `HKCU\Environment` via `setx`, edits shell profiles | the same, for persistence |
| Spawns `powershell`, `reg`, `netstat`, `tasklist` | the same |

The difference is intent and direction: aiexpose reports these things to you and
never transmits them anywhere. A static scanner cannot see intent. It sees an
unsigned executable whose string table and system calls match the malware family
it is built to find.

So the honest answer is that a detection here is the scanner doing its job on
incomplete information, and the fix is for us to give it better information —
not for you to lower your defences.

## First: is it actually quarantined?

A console window that appears and vanishes is usually **not** a detection. A
command-line program launched by double-clicking gets its own window, and
Windows destroys that window the instant the program finishes — output and all.

Since 0.7.0 the executable detects that case, keeps the window open and writes
`aiexpose-report.html` beside itself. If you are on an older build, or want to
be sure, open PowerShell in the folder and run it there:

```powershell
.\aiexpose_0.8.0_windows_amd64.exe --version
echo "exit code: $LASTEXITCODE"
```

Output and a version line mean the file is fine. "The system cannot find the
file specified", or the file having disappeared from the folder, means it was
quarantined — read on.

## What to do right now

**1. Verify the file before you trust it.** Every release publishes
`SHA256SUMS`. The binary can check itself:

```
aiexpose --verify SHA256SUMS
```

If that says the file does not match, do not restore it from quarantine. Get it
again from the release page, or build it yourself.

**2. Prefer building it yourself.** This is the recommended install for anyone
with Go, and it sidesteps the problem almost entirely: the executable is
produced by your own toolchain, in your own directory, and never arrives as a
downloaded file.

```
go install github.com/MC-kakadu/AIexpose/cmd/aiexpose@latest
```

aiexpose has **no third-party dependencies** — the module graph is the Go
standard library and nothing else — so there is nothing else to audit or trust
in that build.

**3. Make sure you have the default build, not the `_offline` one.** The
default carries no detection patterns, no credential patterns, no shell history
paths and no known-bad entries. `_offline` embeds all of them and is published
only for machines with no internet access. Check which you have:

```
aiexpose --version                               # "default build" or "bundled build"
aiexpose --install-rules aiexpose-rules.json     # arms it, once
```

The rules live in a signed JSON file instead of inside the executable. Nothing
is hidden — you can read the file.

**The default build is not a guarantee.** These remain in it, because they are
what the tool does rather than strings it carries:

| Still present | Why it looks bad |
|---|---|
| `setx`, `HKCU\Environment` | how malware persists (only used by `--fix`) |
| `Get-NetTCPConnection`, `Get-CimInstance Win32_Process` | host and process enumeration |
| UPnP `DeletePortMapping` | router manipulation |
| No Authenticode signature | still the largest remaining factor |

A behavioural engine such as Kaspersky's System Watcher judges what a program
does at runtime, not only what it contains, so an unsigned binary that
enumerates sockets and writes to `HKCU\Environment` can still be stopped. If
you only need the read-only checks, `--no-fix` behaviour is the default: nothing
is written unless you pass `--fix --yes`.

**4. Report the false positive.** This is the step that actually fixes it for
everyone, because these products learn from submissions:

- Microsoft: <https://www.microsoft.com/en-us/wdsi/filesubmission> — choose
  "Software developer", submit the binary, and paste this file's URL as the
  justification.
- Most other vendors have an equivalent form; search for "<vendor> false
  positive submission".

**5. If you add an exclusion, scope it narrowly.** Exclude the single file by
its full path, never a whole directory such as Downloads or your source tree.
An exclusion is a permanent hole in your protection, which is precisely the kind
of thing this tool exists to warn you about.

## Rebuild and compare

Releases are built with `-trimpath` and are reproducible. Building the same tag
with the same Go version on any machine produces byte-identical output, so you
do not have to take our word for what is in the download:

```
git checkout v0.6.0
./build.sh                       # or: ./build.sh --check-reproducible
sha256sum dist/aiexpose_*        # compare against the published SHA256SUMS
```

Symbols are deliberately **not** stripped. A stripped Go binary has the shape
heuristics associate with packed malware, and it is harder for you to inspect.
The extra few megabytes buy transparency.

## What we are doing about it

Signing is the real fix, and it is on us rather than on you:

- **Authenticode signing** for the Windows binaries. An unsigned executable with
  no publisher and no download history is the worst possible combination for
  SmartScreen, and it is the single largest factor here.
- **Notarization** for the macOS binaries, without which Gatekeeper blocks them
  outright.
- **Package manager distribution** (winget, Scoop, Homebrew), which carries its
  own reputation.
- **Vendor submissions** ahead of each release, to Microsoft and to Kaspersky.
- **Replacing the PowerShell calls** with direct `iphlpapi.dll` calls, so a
  normal scan spawns no child processes at all.

Until those are in place, `go install` and the minimal build are the paths that
work today. See [RELEASING.md](RELEASING.md) for the full checklist.

## If the rule file is quarantined

`~/.aiexpose/feed.json` is a list of what malicious code looks like, so a
scanner can flag the file itself. aiexpose does not fail silently if that
happens: every scan then reports "This scan did not check for malicious code"
as a finding, and the CI gate fails rather than passing green.

Restore the file, exclude that single path, or pass a copy explicitly with
`--feed`.
