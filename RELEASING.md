# Releasing

## Before tagging

```bash
go vet ./...
go test ./...
for t in "linux amd64" "darwin arm64" "windows amd64" "windows arm64"; do
  set -- $t; GOOS=$1 GOARCH=$2 go vet ./... || exit 1
done
./build.sh --check-reproducible      # must report byte-identical builds
```

Reproducibility is a release blocker, not a nicety: it is what lets a user whose
antivirus quarantined a download rebuild and confirm the hash independently.

## Build

```bash
VERSION=0.6.0 ./build.sh              # dist/,          full rules embedded
VERSION=0.6.0 ./build.sh --minimal    # dist-minimal/,  no rules embedded
```

Publish both. The minimal variant exists for people whose endpoint protection
quarantines the full one; see [ANTIVIRUS.md](ANTIVIRUS.md).

## Signing

This is the part that actually determines whether users can run the tool, and
it is the largest single gap in the project today.

### Windows

An unsigned executable, from an unknown publisher, with no download history, is
the worst combination for SmartScreen and for Defender's ML detections. Options,
cheapest first:

| | Cost | Reputation |
|---|---|---|
| Unsigned | free | flagged; users must verify hashes by hand |
| OV certificate | roughly $200-400/yr | builds over time and download volume |
| EV certificate | roughly $400-700/yr | immediate SmartScreen reputation |

Since June 2023 both kinds require the key to live on approved hardware or in a
cloud signing service, so budget for the HSM or the service as well.

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
  /n "Your Company" aiexpose_0.6.0_windows_amd64.exe
signtool verify /pa /v aiexpose_0.6.0_windows_amd64.exe
```

Always timestamp. Without it every signature expires with the certificate.

### macOS

Gatekeeper blocks unsigned, un-notarized downloads outright, so this is not
optional if the binary is to be downloaded rather than built.

```bash
codesign --sign "Developer ID Application: Your Company (TEAMID)" \
         --options runtime --timestamp aiexpose_0.6.0_darwin_arm64
ditto -c -k --keepParent aiexpose_0.6.0_darwin_arm64 upload.zip
xcrun notarytool submit upload.zip --apple-id ... --team-id ... --wait
```

A single-file CLI cannot be stapled; notarization is checked online on first
run. Requires an Apple Developer account (99 USD/yr).

## Vendor submissions

Submit each signed release **before** announcing it. Detections usually clear
within a day or two, and doing it in advance avoids the first users hitting a
quarantine.

- Microsoft: <https://www.microsoft.com/en-us/wdsi/filesubmission> (choose
  "Software developer") and link to ANTIVIRUS.md as the justification.
- Repeat for any other vendor a user has reported.

## Distribution

Package managers carry reputation the project does not have yet, and they are
where a developer audience expects to find a tool:

- **winget** — submit a manifest to `microsoft/winget-pkgs`
- **Scoop** — a bucket manifest
- **Homebrew** — a formula, or a tap to start with
- **`go install github.com/MC-kakadu/AIexpose/cmd/aiexpose@latest`** — works today with no
  infrastructure at all, and is the recommended path in the README precisely
  because a locally compiled binary is rarely quarantined

## The feed

The known-bad list and the detection patterns ship as one signed document.

```bash
AIEXPOSE_FEED_KEY=... go run ./cmd/feedsign -in internal/feed/data/feed.json
go run ./cmd/feedsign -in internal/feed/data/feed.json -verify <public-key-hex>
```

Both `feed.json` and `feed.json.sig` must be served from the URL in the feed's
`source` field, since `--update-feed` fetches the signature from
`<url>.sig`. The private key never enters the repository; the public half is in
`internal/feed/key.go`, so rotating it means shipping a new binary.

Re-sign `data/empty.json` too whenever the key changes, or the minimal build
will refuse its own embedded feed.

### The rule file is a release asset, and it is easy to forget

The default build embeds no rules, so a downloaded binary reads
`aiexpose-rules.json` from its own folder. That file is a **separate release
asset** and it is not produced by `build.sh`. Publish it with every release
whose feed changed:

```bash
cp internal/feed/data/feed.json aiexpose-rules.json
AIEXPOSE_FEED_KEY=... go run ./cmd/feedsign -in aiexpose-rules.json
go run ./cmd/feedsign -in aiexpose-rules.json -verify <public-key-hex>
```

Attach `aiexpose-rules.json` and `aiexpose-rules.json.sig` to the release.

Skipping this does not break anything visibly, which is why it has already
happened once. A user who upgrades the binary but keeps the old rule file from
their previous download gets a report built on the old list — correctly signed,
silently incomplete. `RULE-002` now catches that on their machine, but the point
is not to ship the situation in the first place.

**Bump `feed.ReleasedWith` whenever `data/feed.json`'s version changes.**
`TestReleasedWithMatchesShippedFeed` fails the build if you forget, so this is a
reminder rather than a risk.

## The malware hash index

The index is roughly 255 MB, so it is published as a **release asset** and
never committed. That is not a preference: GitHub refuses any file over
100 MiB, and the corpus cannot be squeezed under that limit honestly. Forty-two
million random 64-bit prefixes need about forty bits each however they are
encoded, so a file small enough to commit would have to shorten the prefix, and
a shortened prefix means a scan that hashes a few thousand files has a
percent-level chance of calling a clean one malware. Git LFS would clear the
size limit and still be wrong: every clone would pull a quarter of a gigabyte
of general Windows malware hashes that overlap almost nothing this tool exists
to catch.

Build the index, write its manifest, sign the manifest, publish three files:

```bash
./aiexpose --build-hashdb ./virusHashDb --hashdb ./aiexpose-hashdb.bin
./aiexpose --sign-hashdb ./aiexpose-hashdb.bin
AIEXPOSE_FEED_KEY=... go run ./cmd/feedsign -in ./aiexpose-hashdb.manifest.json
go run ./cmd/feedsign -in ./aiexpose-hashdb.manifest.json -verify <public-key-hex>
```

Attach all three to the release:

| File | What it is |
|---|---|
| `aiexpose-hashdb.bin` | the index itself |
| `aiexpose-hashdb.manifest.json` | its SHA-256, size and provenance |
| `aiexpose-hashdb.manifest.json.sig` | Ed25519 over that manifest |

Ed25519 signs the manifest rather than the index so neither the signer nor the
user's machine has to hold 255 MB in memory to check it; the chain of trust
runs from the public key compiled into every binary, through the manifest, to
the bytes on disk. A user installs it with:

```bash
aiexpose --install-hashdb aiexpose-hashdb.bin
```

which refuses anything whose signature, digest, size, file name or format does
not match, and writes nothing until all five agree. Building the index locally
with `--build-hashdb` remains supported and trusts nobody's copy but the user's
own.

Re-sign the manifest whenever the index is rebuilt. A stale signature over a new
index fails the digest check, which is the intended behaviour, but it fails on
the user's machine rather than here.
