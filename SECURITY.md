# Security policy

## Reporting a vulnerability

Report privately through GitHub's [Security Advisories](../../security/advisories/new),
which opens a channel visible only to you and the maintainers. If that is not
available to you, email **mukeun.choi@gmail.com**.

Please do not open a public issue for a vulnerability first.

What helps most, in rough order:

- what an attacker gains, and what they need to already have
- the finding ID (`SUP-030`, `EXP-001`) and the rule version from the report's
  "How this report was produced" block, if a scan is involved
- a way to reproduce it, even a rough one

**Do not paste unmasked credentials.** The tool masks them in every output for a
reason, and a bug report is a worse place for them than the file they came from.

You should get an acknowledgement within a few days. This is a small project,
so please allow for that rather than assuming silence.

## What counts as a vulnerability here

This tool reads a machine and writes a report. The things that would be serious:

- **A scan writes to or changes the machine.** It is asserted read-only and a
  test enforces it. A way around that is a bug of the first order.
- **A credential reaches an output unmasked** — terminal, HTML, JSON, SARIF or
  the AI bill of materials.
- **Anything leaves the machine during a scan.** Scans do not use the network.
  Service fingerprinting goes to `127.0.0.1` only and the router query is LAN
  multicast; `--update-feed`, run deliberately, is the sole exception.
- **An unsigned or tampered rule file is accepted.** The rule document decides
  whether this tool tells someone their machine is compromised, so signature
  verification failing open would let anyone who can write the cache silence
  the scanner or make it accuse innocent packages.
- **A crafted file on the scanned machine executes code** in the scanner, or
  makes it read outside the paths it states it reads.
- **A report renders attacker-controlled content as markup.** Component names
  and file paths come from the machine being scanned and are not trusted input.

## What does not

- **A false positive or a false negative in a detection rule.** These matter a
  great deal and we want to hear about them, but as ordinary issues. The rules
  are signed data, so a fix reaches users without a release.
- **The scan not finding a tool that is installed.** Same: important, and an
  ordinary issue. It is the single most useful bug report this project
  receives.
- **Antivirus flagging the binary.** Expected, and explained in
  [ANTIVIRUS.md](ANTIVIRUS.md).

## Verifying what you downloaded

Releases publish `SHA256SUMS`, and the binary checks itself against it:

```
aiexpose --verify SHA256SUMS
```

Builds are reproducible, so you can rebuild the same tag with the same Go
version and compare rather than take the download on trust:

```
./build.sh --check-reproducible
```

The rule file is signed with Ed25519 and the public key is compiled into the
binary. A copy that does not verify is discarded.
