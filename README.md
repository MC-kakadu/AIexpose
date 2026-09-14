# aiexpose

**Is your local AI reachable by anyone but you?** And has anything in it changed behind your back?

One command tells you which AI services are running on this machine, which of
them are open to your network or the internet, whether their APIs answer with
no credentials at all, and whether your API keys are sitting in plaintext.

```
$ aiexpose

  F  1/100   exposure grade

  1 critical   2 high   2 medium   1 low   0 info

Discovered services
 ! Ollama                     0.0.0.0:11434  all-interfaces    no-auth
 . ComfyUI                    127.0.0.1:8188 loopback

CRITICAL  Ollama is open to the network with no authentication
          Ollama on 0.0.0.0:11434 is bound to a wildcard address and answered an
          API request with no credentials at all. Anyone who can reach this port
          has the same access you do.
   fix -> Unset OLLAMA_HOST, or set it to 127.0.0.1:11434, then restart Ollama.
```

> **Status.** Everything described here is implemented and tested. It has been
> exercised on Windows, Linux and macOS builds, but the real-machine testing so
> far has been on a small number of machines — see
> [Known limits](#known-limits). Downloads are not yet code-signed, so Windows
> will show a SmartScreen prompt; [ANTIVIRUS.md](ANTIVIRUS.md) explains why and
> what to do.

## Why

Around **175,000 Ollama instances** are reachable on the public internet with no
authentication. Attackers have been observed hijacking misconfigured local model
servers and using them as the reasoning engine for their own attack tooling, and
stolen inference credentials have run up five-figure daily bills on victim
accounts.

Most of those machines belong to people who chose to run AI locally *because*
they cared about privacy. One wrong bind address undoes all of it, and nothing
on the machine tells you it happened.

## Install

**Recommended, if you have Go:**

```bash
go install github.com/MC-kakadu/AIexpose/cmd/aiexpose@latest
```

This is first for a reason. aiexpose has no third-party dependencies, so this
builds from source you can read in one sitting, and the executable is produced
by your own toolchain rather than downloaded — which also avoids the antivirus
problem described below.

**Building from a clone:**

```bash
git clone https://github.com/MC-kakadu/AIexpose && cd AIexpose
go build -o aiexpose ./cmd/aiexpose
./aiexpose --install-rules internal/feed/data/feed.json   # arms it, once
./aiexpose
```

The signed rule file is in the tree you just built from. A release calls the
same file `aiexpose-rules.json`; the repository keeps it under its own name.

**From a release:** download the binary for your platform, verify it, install
the rules once, and run it. A release carries `SHA256SUMS` and
`aiexpose-rules.json` beside the binaries; neither is kept in the repository,
because one is a checksum of files that do not exist until a release is built
and the other is the same signed document the tree already holds at
`internal/feed/data/feed.json`.

```bash
# macOS / Linux
chmod +x aiexpose
./aiexpose --verify SHA256SUMS
./aiexpose --install-rules aiexpose-rules.json   # arms it, once
./aiexpose
```

```powershell
# Windows
.\aiexpose.exe --verify SHA256SUMS
.\aiexpose.exe --install-rules aiexpose-rules.json
.\aiexpose.exe
```

**On Windows, double-clicking works.** The executable notices it was launched
from Explorer, saves `aiexpose-report.html` beside itself, opens it in your
browser and holds the console window open so you can read the summary too. Use
`--no-open` if you would rather it did not. If the window still closes too
quickly on your machine, run `run-aiexpose.bat` instead.

### Installing the rules

Every release ships `aiexpose-rules.json` and its signature. Install them once
and every later scan finds them on its own:

```
aiexpose --install-rules aiexpose-rules.json
```

You can also just keep `aiexpose-rules.json` and its `.sig` in the same folder
as the executable — a scan picks up the newest signed copy it can find, whether
that is the installed one, the one beside the binary, or the one built in. That
is what makes a rule fix reach you in a release without you doing anything.

`--update-feed` does the same over the network once a feed endpoint is
published; until then it says so rather than failing with a DNS error.

Without rules the tool still reports exposure, but it cannot inspect components
for malicious code or scan for plaintext keys — and it says so in the report
rather than showing a clean result.

### Why the rules ship separately

Because the alternative gets deleted. On a Windows machine running Kaspersky and
Microsoft Defender, a build with the rules compiled in was quarantined within
seconds of launching; the default build, identical in every other respect, ran
normally. The rules are a list of what malicious code looks like — webhook
endpoints, browser credential paths, wallet filenames — which is character for
character the string table an information stealer carries.

So they ship as a signed JSON file instead. Nothing is hidden: you can read it.

An `_offline` build with the rules embedded is published for air-gapped
machines. Do not make it your default download.

If something is still flagged, [ANTIVIRUS.md](ANTIVIRUS.md) covers verifying the
file, restoring it, and reporting the false positive — which is what actually
fixes it for everyone.

## What it does

**1. Exposure.** Is anything on this machine reachable by someone else right now?

**2. Drift.** Did any component of your AI stack change after you accepted it?

**3. Credentials.** Are your API keys sitting in plaintext where anything can read them?

**4. Known-bad.** Is any of it already documented as malicious?

**5. Malware hashes.** Does any file match a known malware sample, byte for byte?

**6. Advise.** Name the exact command that resolves each finding.

**7. Attest.** Say what was examined, what was not, and what produced the answer.

**8. Gate.** Stop the same problems entering a repository in the first place.

The second one matters more than it sounds. A scanner that gives a verdict once
cannot catch the failure that actually happens: `postmark-mcp` was a well-behaved
npm package with real users for months before it was backdoored, and roughly 300
organisations had already wired it in. A clean scan the week before would have
been correct and useless.

So `aiexpose` fingerprints every ComfyUI custom node, MCP server and agent skill
on the machine, remembers the state you accepted, and tells you when one of them
moves:

```
CRITICAL  ComfyUI custom node "ComfyUI-Manager" changed and now contains dangerous code
          A component that was already installed and accepted has been modified, and
          the new version contains behaviour that was not there before.
            code changed (1 files now, 1 before)
            new risk indicators: EXFIL-TELEGRAM, STEAL-SSH
   fix -> Treat this machine as compromised until proven otherwise.
```

The first run records the baseline. After you review a legitimate update, accept
it:

```bash
aiexpose --accept
```

Double-clicking is easier: when something has changed, the scan lists it and
asks, right there in the window, whether to record it. The answer defaults to
no. A baseline is the moment you vouch for what is installed, so it is a
question rather than a button — and a button in a saved report, clicked later
and out of context, is not a review.

## 3. API keys, in the places people actually leave them

Everyone knows keys belong in a secrets manager. In practice they end up in
`.env`, in `.bashrc`, and — the case tools miss — in a note someone wrote to
themselves: `keys.txt`, `api정리.md`, a page in an Obsidian vault.

A list of filenames can never reach those, because the person made the name up.
So the search is by *file kind*, inside a bounded set of places:

| Where | Default |
|---|---|
| Files sitting directly in your home folder | **on** |
| AI tool folders — ComfyUI, SD WebUI, Jan, LM Studio, `.ollama`, `.claude`, MCP servers | **on** |
| Desktop, Documents, Downloads (and the OneDrive copies of them) | `--scan-docs` |
| A folder you name — a work drive, a project directory | `--scan-dir PATH` |

```
MEDIUM    2 API key(s) stored in plaintext config files
          - GitHub key        ~/Documents/Obsidian Vault/Dev/FDS-App.md:12  ghp_HN********WJ8
          - Hugging Face key  ~/Documents/Obsidian Vault/Dev/HF TK.md:1     hf_aDZ********bDB
          Searched 34 text file(s) under: the home folder itself, ComfyUI, Desktop, Documents.
   fix -> Rotate each key at its provider first; restricting the file does not
          undo a key that already leaked.
```

The scope line is on the finding whether or not it found anything. "Two keys"
means something different if the search covered two folders than if it covered
eight, and a reader who cannot see the scope cannot tell those apart.

**Values are always masked**, in the terminal, in the HTML report and in the
JSON. A test asserts that the full key never appears in any output.

Only text files are opened — `.txt`, `.md`, `.json`, `.yaml`, `.ini`, `.ps1` and
a dozen more. Images, archives and model weights are never read. The walk stops
at 4 folders deep, 600 files and 512 KB per file, and dependency trees
(`node_modules`, `.venv`, `__pycache__`) are skipped entirely. Each root gets
its own share of that budget, so one folder full of notes cannot starve the
others — and if a limit is hit, the report names the folder where it stopped
instead of reporting a clean result.

**Your documents are opt-in, and the report says when they were skipped.**

```
NOT RUN   Your document folders were not searched for API keys
          Desktop, Documents and Downloads were not read. They are not searched by default
          because walking a person's documents and reading every text file is precisely what
          an information stealer does, and an unsigned tool that does it unasked gets
          quarantined -- rightly.
          If you have ever pasted a key into a note to keep it handy, that is where it is.
   run -> aiexpose --scan-docs
```

That is the same reason shell history needs `--scan-history`. On a double-click
run the question is asked in the window instead, and the answer defaults to no.

Checks that did not run are printed in their own section, after the ones that
did, and never counted as passes — in the report and in the terminal both.

## 4. Known-bad components

Pattern matching reads source, so it loses to obfuscation, and it cannot know
that one specific published version of an ordinary-looking package was
backdoored. A curated list closes exactly that gap:

```
CRITICAL  postmark-mcp was backdoored after months of legitimate use
          Matched because package postmark-mcp@1.0.16.
          List entry: AIX-2025-0001 (2026.09.10)
```

Nothing in that component's source looks wrong. It is caught because the
published thing is known.

```bash
aiexpose --update-feed    # the only command that touches the network
```

The list is **signed with Ed25519** and the public key is compiled into the
binary. A copy that does not verify is discarded and the built-in one is used
instead. That matters more than it may look: this list decides whether the tool
tells someone their machine is compromised, so anyone able to serve or write the
cache file could otherwise silence it, or make it accuse innocent packages.

The update request carries nothing about your machine — no identifier, no query
string, no report of what is installed. Scans themselves never use the network,
and `--feed PATH` runs from a file for air-gapped machines.

The list ships with a handful of publicly documented entries. Its value is not
the format, which is a weekend of work; it is keeping it current. That is the
one part of this tool nobody can clone.

## 5. Malware hashes, offline

The two checks above read source and match names. Neither notices a compiled
file. `aiexpose` can also compare every file in your AI stack, byte for byte,
against a corpus of known malware hashes — with no network involved at any
point.

```bash
aiexpose --build-hashdb ./virusHashDb   # once, about 20 seconds
```

Point it at a folder of [VirusShare](https://virusshare.com/hashes) MD5 lists.
It compiles them into one sorted index under `~/.aiexpose/hashdb.bin`; every
scan from then on uses it automatically.

```
CRITICAL  ComfyUI custom node "some-node" contains a file that matches a known-malware hash
          A file inside this component hashes to a value that appears in VirusShare
          MD5 lists (42,532,864 hashes, built 2026-09-10).
          - loader.dll  md5 88cd54956f8e2d560c59bb66e3cc30a4
```

Measured on the full 500-file VirusShare set:

| | |
|---|---|
| Source text | 1.5 GB |
| Build | 18.5 s, 367 MB peak memory |
| Index on disk | 244 MB |
| Lookup | 4.9 µs |
| Effect on a scan | none measurable — 301 files hashed inside a 20 ms scan |

**Be clear about what this catches.** That corpus is general malware, mostly
Windows executables. It will recognise a commodity stealer or miner that ended
up inside an AI tool's directory. It will *not* recognise a backdoored MCP
package or a malicious ComfyUI node, because those are Python source and no
antivirus corpus has ever indexed them — that is what the curated list and the
source indicators above are for. The three layers barely overlap, which is the
reason to run all three. The report says so too, rather than letting a green
tick imply more than it proved.

Two details worth knowing:

- The index stores a **64-bit prefix** of each MD5 rather than the whole value,
  which is what makes it 244 MB instead of 680 MB. With 42 million entries the
  chance an unrelated file collides is about 1 in 400 billion per lookup. Across
  every file this tool will ever hash that is expected to happen approximately
  never — but it is why the finding says "matches a known-malware hash" rather
  than "is malware". Verified at full scale: 106,003 known hashes all found,
  200,000 random hashes produced zero matches.
- **Nothing is downloaded and nothing is uploaded.** You fetch the lists
  yourself; the tool only reads them. If you never build an index, no binary on
  your machine is ever opened for this.

Skip it with `--no-hashdb`, or delete the index file to turn it off for good.

## 6. What to do about it

Every finding names the exact step that resolves it on your operating system,
and the report puts it one click from your clipboard:

```
LOW   Ollama accepts unauthenticated requests on loopback
      Fix: Enable authentication if the service supports it, and narrow which
           browser origins may reach it.
      run -> setx OLLAMA_ORIGINS "http://localhost:3000"
```

**aiexpose does not make the change.** It reads your machine and reports; you
run the command. That is a deliberate reversal of an earlier design, for a
reason we measured rather than assumed.

Writing to `HKCU\Environment`, editing launch scripts and deleting router port
mappings are, to a behaviour engine watching an unsigned binary, exactly what
malware does to establish itself. Kaspersky blocked an earlier build of this
tool for that shape of activity. A security tool that gets quarantined the
moment someone uses its best feature is not a security tool.

There is a second reason, and it outlasts the first. A scanner that edits
launch scripts and router tables can break things, and the person holding the
consequences is the one who ran it. Printing the command keeps the decision
where it belongs, and it means you can read what will happen before it does.

The one thing a scan writes is its own state: the accepted baseline under
`~/.aiexpose`, and any report file you asked for by name.

## 7. Evidence someone else can use

Everything above produces findings. This section is about what a reader does
with them afterwards: put one in a risk register, answer a customer's security
questionnaire, or hand the lot to someone who has never heard of this tool.

**Every finding names the published risk it is evidence for** — OWASP Top 10 for
LLM Applications (2025), MITRE ATLAS, MITRE ATT&CK:

```
MEDIUM    1 API key(s) stored in plaintext config files
  maps -> LLM02:2025  AML.T0055  T1552.001
```

**The report lists what it could not examine.** This is the part that makes the
rest of it worth reading. Half the OWASP LLM Top 10 describes how an application
behaves while it is running, and a scan of files and sockets cannot see any of
it. Leaving those rows blank would let a reader assume they passed:

| | | |
|---|---|---|
| LLM03:2025 | Supply Chain | **critical** — SUP-020, SUP-030 |
| LLM04:2025 | Data and Model Poisoning | no evidence found |
| LLM05:2025 | Improper Output Handling | **not checked** |
| LLM08:2025 | Vector and Embedding Weaknesses | partly checked |

Each row says in a sentence what was examined and what was not — "embedding
inversion, cross-tenant retrieval and poisoned documents inside an index are not
examined" — so "no evidence found" means something and "not checked" is never
mistaken for it.

**The report says how it was produced**: the scanner's own SHA-256, where it ran
from, which rule version made the findings, and which malware corpus they were
matched against. A finding is only as good as the rule set behind it.

**It lists the components it fingerprinted**, with the ones it has findings about
marked, because "6 components match the baseline" is a claim and the list is the
evidence for it.

### AI bill of materials

The same inventory exports as a CycloneDX 1.6 SBOM, which SBOM platforms,
procurement processes and auditors already read:

```bash
aiexpose --aibom bom.cdx.json
```

Ollama models become `machine-learning-model` components, MCP servers become
applications with a `purl` (`pkg:npm/postmark-mcp@1.0.16`), custom nodes and
agent skills become libraries, and discovered services become CycloneDX
`services` entries carrying whether each one answered without credentials and
whether it crosses a trust boundary. Output is validated against the published
schema and passes 1.6 and 1.7.

Two deliberate omissions, both stated inside the document itself:

- **No model cards.** CycloneDX can carry a model's training data, performance
  metrics and fairness analysis. This scanner reads files on a disk and knows
  none of that, and filling those fields with guesses would make the document
  look more authoritative than the evidence behind it.
- **No hash that is not ours.** The digest on each component is this tool's own
  fingerprint over its code and config files, not a hash any registry published,
  and every component carrying one also carries a property saying so.

The serial number is derived from the document's contents, so re-scanning an
unchanged machine produces the same BOM and two of them can be diffed.

## 8. The CI gate

Everything above tells one person about one machine. `aiexpose ci` inventories
the MCP servers, agent skills and workflow nodes a **repository** ships, applies
the policy committed next to them, and exits non-zero when the gate fails.

```
$ aiexpose ci

error    postmark-mcp was backdoored after months of legitimate use
         rule: known_bad
         .mcp.json

error    agent-skill "deploy-helper" changed since it was reviewed
         rule: lock_drift
         The locked digest is 859f83c1a842 and the current contents hash to 9e15ac4298c4.

exempt   MCP server "weather" runs an unpinned package (weather-mcp)
         exempted: internal mirror pins this at the registry level; tracked in SEC-412
         expires 2026-12-31

2 error(s), 0 warning(s), 1 exempted. Gate failed.
```

`--sarif out.sarif` writes SARIF 2.1.0, so findings land on the changed lines of
a pull request rather than in a log nobody opens. A ready-made workflow is in
[.github/workflows/aiexpose.yml](.github/workflows/aiexpose.yml).

### The lockfile

`aiexpose ci --write-lock` writes `aiexpose.lock.json`: the set of components
the team has reviewed and accepted. Commit it. From then on, a pull request that
changes one of them, or adds one that is not listed, has to say so in review.
This is the whole idea — not an opinion delivered after the fact, but a gate
that has to be satisfied before code merges.

### The policy

`.aiexpose.json` is optional; without it the defaults fail on the unambiguous
problems and warn about the rest, so adding this to an existing repository does
not break its build on day one.

```json
{
  "version": 1,
  "rules": {
    "known_bad":          "error",
    "risk_indicator":     "error",
    "lock_drift":         "error",
    "unpinned_package":   "warn",
    "unlocked_component": "warn"
  },
  "exemptions": [
    {
      "rule": "unpinned_package",
      "match": { "component": "weather" },
      "reason": "internal mirror pins this at the registry level; tracked in SEC-412",
      "expires": "2026-12-31"
    }
  ]
}
```

Two deliberate choices in that file. An exemption with an empty `match` block
waives nothing, because a blanket suppression should have to be spelled out.
And an expired exemption stops suppressing and says so by name, so a temporary
waiver cannot quietly become permanent.

## What it checks

| | Check |
|---|---|
| **Exposure** | Which AI services listen on `0.0.0.0` instead of `127.0.0.1` |
| **Authentication** | Whether each service's API answers without credentials |
| **Router** | Whether your gateway forwards an internet port to one of them (read over UPnP, on your LAN only) |
| **Host firewall** | ufw / firewalld / nftables / iptables, macOS application firewall, Windows Defender Firewall |
| **Launch flags** | `--listen`, `--share` public Gradio tunnels, empty Jupyter tokens |
| **Environment** | `OLLAMA_HOST` pointing off-loopback, `OLLAMA_ORIGINS=*`, `GRADIO_SERVER_NAME` |
| **Credentials** | Plaintext API keys in shell profiles, `.env` files, AI tool folders and text notes — opt-in for shell history and document folders, always reported masked |
| **Model formats** | Weights in pickle formats (`.ckpt`, `.pt`, `.bin`) that execute code when loaded |
| **Component drift** | ComfyUI custom nodes, MCP servers and agent skills that changed since you accepted them |
| **Malicious code** | Discord/Telegram exfiltration, browser credential and wallet theft, encoded payloads, tunnels, persistence |
| **Unpinned MCP servers** | Servers launched via `npx -y pkg` or `pkg@latest`, which run whatever the registry serves today |
| **Known-bad components** | Packages, node names and file digests on the signed known-bad list |
| **Malware hashes** | Every hashed file against a local offline malware corpus, when you have built one |
| **Model integrity** | Content-addressed model blobs verified against their own digests, and models pulled from unofficial registries |
| **Risk coverage** | Each OWASP LLM Top 10 (2025) risk, with what this scan examined for it and what it cannot see |

### Services it recognises

Ollama, LM Studio, llama.cpp server, vLLM, Jan, LocalAI, KoboldCpp, Open WebUI,
AnythingLLM, SillyTavern, ComfyUI, Stable Diffusion WebUI, text-generation-webui,
Qdrant, Chroma, Weaviate, Milvus, Jupyter, Ray Dashboard, n8n, Flowise, Dify.

## Privacy

This is a tool for people who run AI locally so their data stays local. It would
be absurd for it to upload anything, so it does not.

- **No network egress during a scan.** Services are fingerprinted over
  `127.0.0.1` only, and the router query is LAN multicast. The single exception
  is `--update-feed`, which you run deliberately: it is a plain GET for two
  static files and sends nothing about this machine.
- **No telemetry, no account, no phone-home.** The malware hash index is built
  from lists you download yourself; the tool never fetches them and never
  reports what it matched.
- **Credentials are masked** before they are written anywhere, including the
  JSON output.
- **Your documents are not read unless you ask.** The default search covers your
  home folder's own files and the AI tool directories. Desktop, Documents and
  Downloads need `--scan-docs`; shell history needs `--scan-history`. Both are
  opt-in for the same reason: reading them unasked is what an information stealer
  does. The report states which of them were skipped, so a clean result is never
  mistaken for a thorough one.
- **The HTML report is self-contained** — no fonts, styles or images are
  fetched when you open it. It carries one inline script, whose entire job is
  copying a command to the clipboard; it reads nothing and sends nothing. The
  page is complete with scripting switched off.
- **Read-only.** A scan changes nothing on this machine. It writes its own
  baseline under `~/.aiexpose` and whatever report file you name, and that is
  all. A test asserts it: a full scan runs over a fixture and every file has to
  come back byte-identical.
- **No child processes during a scan.** The checks call the Windows APIs
  directly rather than running `powershell.exe`, `netstat` or `reg.exe`, and
  shell history is only read if you ask for it with `--scan-history`. Both are
  deliberate: an unsigned binary that enumerates the host through PowerShell and
  then reads credential history behaves exactly like an information stealer, and
  behaviour engines stop it — as Kaspersky stopped an earlier build of this
  tool. The one thing the program starts is your browser, after the scan, to
  show you the report; on Windows it does that through `ShellExecuteW`, the call
  Explorer itself uses, rather than by spawning a shell.
- **No third-party dependencies.** The module graph is the Go standard library
  and nothing else. A tool that warns you about supply chain risk should not add
  one.
- **Reproducible builds.** The same tag built with the same Go version produces
  byte-identical output, so you can rebuild and compare rather than trust the
  download. Symbols are deliberately not stripped: a stripped Go binary is both
  harder to inspect and more likely to be flagged as packed malware.
- **The detection patterns are data, not code.** They live in the signed feed,
  so new patterns reach you without a new binary — and the executable does not
  carry an infostealer's string table.

## Usage

```
aiexpose [flags]

  --html PATH        write a self-contained HTML report
  --json             print the report as JSON
  --json-out PATH    write the JSON report to a file
  --verbose          include informational checks that passed
  --fail-on LEVEL    exit 1 if any finding is at or above low|medium|high|critical
  --no-upnp          skip the router port-forwarding query
  --no-secrets       skip the credential scan
  --no-models        skip the model file inventory
  --no-supply        skip the supply chain inventory and drift check
  --scan-history     also search shell and PowerShell history for API keys
  --scan-docs        also search Desktop, Documents and Downloads for keys in notes
  --scan-dir PATHS   also search these folders (separated by : or ;)
  --baseline PATH    where the accepted state lives (default ~/.aiexpose/baseline.json)
  --accept           record the current components as the new known-good baseline
  --feed PATH        use a signed known-bad list from a file (air-gapped machines)
  --no-feed          skip known-bad list matching
  --install-rules F  install detection rules from a signed file (no internet needed)
  --aibom PATH       write a CycloneDX 1.6 AI bill of materials
  --build-hashdb DIR compile VirusShare .md5 lists into the offline malware index
  --hashdb PATH      where that index lives (default ~/.aiexpose/hashdb.bin)
  --hash-all         hash multi-gigabyte weights too (slow; off by default)
  --no-hashdb        skip malware hash matching
  --update-feed      download fresh detection rules and exit
  --feed-url URL     where --update-feed downloads from
  --version          print the version, build profile and this binary's SHA-256
  --verify PATH      check this binary against a published SHA256SUMS file
  --safe-mode        start no other programs and touch no credential store
  --color/--no-color force colour on or off
  --open             open the HTML report when it is written (automatic on double-click)
  --no-open          never open it automatically
  --pause            wait for Enter before exiting (automatic on double-click)
  --no-pause         never wait

aiexpose ci [flags]

  --path DIR         repository to inspect (default .)
  --write-lock       record the current components as reviewed
  --sarif PATH       write SARIF 2.1.0 for code scanning
  --policy PATH      policy file (default <path>/.aiexpose.json)
  --lock PATH        lockfile (default <path>/aiexpose.lock.json)
  --feed PATH        use a signed known-bad list from a file
  --no-feed          skip known-bad list matching
  --json             machine-readable result
```

Exit codes: `0` clean (or below `--fail-on`), `1` findings at or above the
threshold, `2` the scan could not run.

### Notes on privileges

Sockets owned by *other* users are only visible with elevated privileges, and
most firewall backends need root to read their rules. Running without `sudo`
still finds everything you started yourself; the report lists any check that
could not run rather than silently passing it.

### Why the indicator list is short

Ten rules, not a hundred. Each one describes something a workflow node or an
agent skill has no legitimate reason to do: post to a Discord webhook, read
Chrome's `Login Data`, execute a base64-decoded payload. Broad heuristics such
as "uses `subprocess`" would fire on most real nodes, and a scanner that cries
wolf gets ignored, which is worse than not running it.

## Known limits

Stated here rather than discovered later.

**Real-machine coverage is thin.** The combination verified end to end is
Ollama + Hugging Face/torch caches + ComfyUI Desktop, on Windows. Every bug this
project has fixed since the feature work stopped came from running it on a real
machine, and none came from synthetic fixtures — so a configuration nobody has
run it on is where the next one is. If you run it on something different and it
misses an installed tool, that is the single most useful bug report you can file.

**Finding an installation is harder than judging one.** A tool installed
somewhere the search paths do not cover is reported as absent, and absent reads
as clean. The report lists the paths it looked in for exactly this reason. Set
`COMFYUI_PATH` if yours lives somewhere unusual.

**On Windows, launch-flag detection is narrow.** Reading another process's
command line means calling PowerShell, which is the behaviour that gets unsigned
binaries quarantined, so it was removed. `--listen` and `--share` are detected
from environment variables there; Linux and macOS read the command line directly.

**LAN-bound services are not fingerprinted.** Service probes go to `127.0.0.1`
only — the scanner never puts a packet on your network. A service bound to a
specific interface address rather than `0.0.0.0` is therefore reported as
exposed but unconfirmed, and its authentication state is unknown, so the finding
stays at medium even when the service is in fact wide open.

**The malware corpus is general, not AI-specific.** It recognises a commodity
stealer sitting in an AI tool's folder. It does not recognise a backdoored MCP
package or a malicious custom node, because those are Python source that no
malware corpus indexes. That is what the known-bad list and the source
indicators are for, and the three layers barely overlap.

**The known-bad list is short.** Three publicly documented entries. The format
took a weekend; keeping it current is the actual work, and it is the part that
would benefit most from other people contributing.

**One detection rule is pinned by tests, not all of them.** `STEAL-BROWSER` is
fixed against 24 real true- and false-positive lines after it misfired on a
legitimate node. The other ten patterns have not been validated against a corpus
of real code at that level.

**Downloads are unsigned.** No Authenticode certificate, no macOS notarization.
SmartScreen and Gatekeeper will say so. Building from source with
`go install` sidesteps this entirely.

## Maintaining the list

`cmd/feedsign` generates the keypair and signs a feed:

```bash
go run ./cmd/feedsign -genkey                       # once, then store the private half in a secret manager
AIEXPOSE_FEED_KEY=... go run ./cmd/feedsign -in feed.json
go run ./cmd/feedsign -in feed.json -verify <public-key-hex>
```

The private key must never enter this repository. The public half lives in
`internal/feed/key.go`, so rotating it means shipping a new release — which is
the intended cost.

## Building

```bash
./build.sh                        # all six targets; the default download
./build.sh --offline              # rules embedded, for air-gapped machines
./build.sh --check-reproducible   # proves the release is byte-reproducible

go test ./...                     # default profile
go test -tags bundled ./...       # offline profile
```

[RELEASING.md](RELEASING.md) covers signing, notarization and vendor
submissions.

## Roadmap

In rough order of how much difference each would make.

- **Authenticode signing and macOS notarization.** The largest single obstacle
  between this tool and the people who would use it.
- **Runs on more kinds of machine.** See [Known limits](#known-limits); this has
  been the highest-yield activity in the project's history by a wide margin.
- **Digest entries in the known-bad list, from real samples.** An AI-specific
  corpus is the one gap the general malware index cannot fill.
- **Validating the remaining detection patterns** against real codebases, the
  way `STEAL-BROWSER` was.
- Ollama Modelfiles and Python virtualenvs in the drift inventory
- Security questionnaire answers generated from the coverage map and inventory
- CSA AIUC-1 control mapping alongside OWASP and ATLAS
- winget, Scoop and Homebrew packages
- A published feed endpoint

## Contributing

The most valuable contribution is **running it on a machine unlike the ones it
has been tested on** and saying what it got wrong — especially anything it
failed to find. A report that quietly misses an installed tool is worse than one
that is noisy, and it is the failure only other people's machines reveal.

Bug reports that include the finding ID (`SUP-030`, `EXP-001`) and the rule
version from the report's "How this report was produced" block are the quickest
to act on. Please do not paste unmasked credentials into an issue; the tool
masks them for a reason.

## Security

Report a vulnerability privately — see [SECURITY.md](SECURITY.md), which also
says what counts as one here and what is an ordinary issue.

## License

Apache 2.0. See [LICENSE](LICENSE).
