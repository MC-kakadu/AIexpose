// Command aiexpose checks whether the AI services running on this machine are
// reachable by anyone but you.
//
// Every check runs locally. The tool never transmits an inventory, an address,
// a filename or a credential, and it has no third-party dependencies.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/aibom"
	"github.com/MC-kakadu/AIexpose/internal/browse"
	"github.com/MC-kakadu/AIexpose/internal/checks"
	"github.com/MC-kakadu/AIexpose/internal/ci"
	"github.com/MC-kakadu/AIexpose/internal/control"
	"github.com/MC-kakadu/AIexpose/internal/feed"
	"github.com/MC-kakadu/AIexpose/internal/hashdb"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/netstat"
	"github.com/MC-kakadu/AIexpose/internal/probe"
	"github.com/MC-kakadu/AIexpose/internal/report"
	"github.com/MC-kakadu/AIexpose/internal/subproc"
	"github.com/MC-kakadu/AIexpose/internal/supply"
)

const (
	policyFileName = ".aiexpose.json"
	lockFileName   = "aiexpose.lock.json"

	toolName = "aiexpose"
	version  = "0.19.9"
)

// pauseChoice is set while flags are parsed, because os.Exit skips defers and
// the window has to be held open after run returns.
var pauseForce, pauseDisable bool

func main() {
	code := runGuarded()
	pauseIfLaunchedByDoubleClick(pauseForce, pauseDisable)
	os.Exit(code)
}

// runGuarded turns a panic into a readable message. Without it, a crash in a
// double-clicked window is indistinguishable from the program doing nothing.
func runGuarded() (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\naiexpose crashed: %v\n\n%s\n", r, debug.Stack())
			fmt.Fprintf(os.Stderr,
				"This is a bug. Please report it with the text above and the output of:\n  %s --version\n",
				toolName)
			code = 2
		}
	}()
	return run()
}

func run() int {
	// One subcommand: `ci` gates a repository. Everything else keeps the
	// original flags-only shape so existing invocations are unaffected.
	if len(os.Args) > 1 && os.Args[1] == "ci" {
		return runCI(os.Args[2:])
	}

	var (
		htmlPath     = flag.String("html", "", "write a self-contained HTML report to this path")
		jsonOut      = flag.Bool("json", false, "print the report as JSON instead of text")
		jsonPath     = flag.String("json-out", "", "write the JSON report to this path")
		verbose      = flag.Bool("verbose", false, "include informational checks that passed")
		noUPnP       = flag.Bool("no-upnp", false, "skip the router port-forwarding query")
		noSecrets    = flag.Bool("no-secrets", false, "skip the plaintext credential scan")
		noModels     = flag.Bool("no-models", false, "skip the model file format inventory")
		noSupply     = flag.Bool("no-supply", false, "skip the supply chain inventory and drift check")
		baseline     = flag.String("baseline", "", "path to the accepted-state baseline (default ~/.aiexpose/baseline.json)")
		accept       = flag.Bool("accept", false, "record the current components as the new known-good baseline")
		forceColor   = flag.Bool("color", false, "force ANSI colour output")
		noColor      = flag.Bool("no-color", false, "disable ANSI colour output")
		failOn       = flag.String("fail-on", "", "exit non-zero if any finding is at or above this severity (low|medium|high|critical)")
		feedPath     = flag.String("feed", "", "use this signed known-bad component list instead of the cached one")
		noFeed       = flag.Bool("no-feed", false, "skip matching against the known-bad component list")
		updateFeed   = flag.Bool("update-feed", false, "download fresh detection rules and exit (the only command that uses the network)")
		installRules = flag.String("install-rules", "", "install detection rules from a signed file and exit (works with no internet access)")
		feedURL      = flag.String("feed-url", "", "where --update-feed downloads from")
		buildHashDB  = flag.String("build-hashdb", "", "compile a folder of VirusShare .md5 hash lists into a local malware hash index and exit")
		hashDBPath   = flag.String("hashdb", "", "path to the local malware hash index (default ~/.aiexpose/hashdb.bin)")
		aibomPath    = flag.String("aibom", "", "write a CycloneDX 1.6 AI bill of materials to this path")
		hashAll      = flag.Bool("hash-all", false, "hash every model file against the malware index, including multi-gigabyte weights (slow)")
		noHashDB     = flag.Bool("no-hashdb", false, "skip matching installed files against the local malware hash index")
		scanHistory  = flag.Bool("scan-history", false, "also search shell and PowerShell history for API keys (off by default: reading it is what an information stealer does, and endpoint protection blocks unsigned programs that do)")
		noScanDocs   = flag.Bool("no-scan-docs", false, "never search the document folders, and do not ask")
		scanDocs     = flag.Bool("scan-docs", false, "also search Desktop, Documents and Downloads for API keys written into notes and text files (off by default for the same reason as --scan-history)")
		scanDirs     = flag.String("scan-dir", "", "also search these folders for API keys, separated by "+string(os.PathListSeparator)+" (for a work folder or a project directory outside your home folder)")
		openReport   = flag.Bool("open", false, "open the HTML report even when no graphical session is detected (it opens on its own whenever one is)")
		noOpen       = flag.Bool("no-open", false, "write the HTML report but never open it")
		noHTML       = flag.Bool("no-html", false, "do not write the HTML report automatically (it is written whenever a person is watching)")
		safeMode     = flag.Bool("safe-mode", false, "run only checks that start no other programs and touch no credential stores; use this if security software blocks a normal scan")
		pause        = flag.Bool("pause", false, "wait for Enter before exiting (automatic when launched by double-click)")
		noPause      = flag.Bool("no-pause", false, "never wait for Enter before exiting")
		showVer      = flag.Bool("version", false, "print the version, build profile and this executable's own SHA-256")
		verifyPath   = flag.String("verify", "", "check this executable against a published SHA256SUMS file and exit")
	)
	flag.Usage = usage
	flag.Parse()
	pauseForce, pauseDisable = *pause, *noPause

	// Safe mode exists so a scan is still possible on a machine whose endpoint
	// protection objects to this tool, and so a user can find out which
	// behaviour it objected to.
	if *safeMode {
		subproc.Allowed = false
		*scanHistory = false
		*noUPnP = true
	}

	if *showVer {
		fmt.Printf("%s %s (%s/%s, %s build)\n", toolName, version, runtime.GOOS, runtime.GOARCH, feed.BuildProfile)
		if digest, path, err := selfDigest(); err == nil {
			fmt.Printf("sha256 %s\n%s\n", digest, path)
			fmt.Printf("\nCompare that against the SHA256SUMS published with the release,\n"+
				"or run: %s --verify SHA256SUMS\n", toolName)
		}
		return 0
	}
	if *verifyPath != "" {
		return verifySelf(*verifyPath)
	}

	if *buildHashDB != "" {
		return runBuildHashDB(*buildHashDB, *hashDBPath)
	}
	if *installRules != "" {
		return runInstallRules(*installRules)
	}
	if *updateFeed {
		return runFeedUpdate(*feedURL)
	}

	threshold, err := parseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose:", err)
		return 2
	}

	start := time.Now()
	host, _ := os.Hostname()
	r := &model.Report{
		Tool: toolName, Version: version, Started: start,
		Host: host, OS: runtime.GOOS, Arch: runtime.GOARCH,
	}

	// Detection rules come from the signed feed and several checks depend on
	// them, so they are loaded once, before any check runs.
	rules := checks.LoadRules(r, *feedPath, *noFeed)

	// A failure here must not abort the scan. The credential, supply chain and
	// model checks do not depend on socket enumeration, and losing all of them
	// because one platform call failed is worse than reporting a gap.
	listeners, err := netstat.Listeners()
	if err != nil {
		r.Note("Listening sockets could not be enumerated (" + err.Error() +
			"), so no services were discovered. Every other check still ran.")
	}
	if len(listeners) == 0 && err == nil {
		r.Note("No listening TCP sockets were visible. On Linux and macOS, sockets owned by other users need elevated privileges; try running with sudo.")
	}

	services := probe.Identify(listeners)
	r.Services = services

	checks.Exposure(r, services)
	checks.LaunchFlags(r, services)
	checks.Environment(r)
	checks.LaunchScripts(r)
	checks.Firewall(r, services)

	var supplyResult checks.SupplyResult
	if !*noUPnP {
		checks.PortForwarding(r, services)
	} else {
		r.Note("Router port-forwarding check skipped (--no-upnp).")
	}
	if !*noSecrets {
		// Someone who double-clicked never saw the flag list, and the keys
		// they wrote into a note are the ones this scan would otherwise miss.
		// Asking is the only way to reach them without reading a person's
		// documents uninvited.
		docs := *scanDocs
		if !docs && !*noScanDocs && canPrompt(pauseForce, pauseDisable) {
			docs = confirmScanDocs(os.Stdin, os.Stdout)
		}
		checks.Secrets(r, checks.SecretScope{
			History: *scanHistory,
			Docs:    docs,
			Dirs:    splitPaths(*scanDirs),
		})
	} else {
		r.Note("Credential scan skipped (--no-secrets).")
	}
	var weights checks.ModelInventory
	if !*noModels {
		weights = checks.ModelFormats(r)
	} else {
		r.Note("Model format inventory skipped (--no-models).")
	}
	if !*noSupply {
		path := *baseline
		if path == "" {
			path = supply.DefaultBaselinePath()
		}
		supplyResult = checks.SupplyChain(r, checks.SupplyOptions{
			BaselinePath: path, SaveBaseline: *accept,
			FeedPath: *feedPath, DisableFeed: *noFeed,
			HashDBPath: *hashDBPath, DisableHashDB: *noHashDB,
			Weights: weights, HashAll: *hashAll,
		})
	} else {
		r.Note("Supply chain drift check skipped (--no-supply).")
	}

	if *safeMode {
		r.Note("Safe mode: no helper programs were started, shell history was not read, " +
			"and the router was not queried.")
	}

	r.Duration = time.Since(start).Round(10 * time.Millisecond).String()
	r.Finalize()

	// Control references and the coverage map are derived from the findings,
	// so they are filled after the findings are settled.
	r.Attest = attestation(r, rules, supplyResult)
	control.Annotate(r)
	control.Inventory(r, supplyResult.Inventory)

	if *aibomPath != "" {
		if err := writeFile(*aibomPath, func(f *os.File) error {
			return aibom.Write(f, r, supplyResult.Inventory)
		}); err != nil {
			fmt.Fprintln(os.Stderr, "aiexpose: could not write the AI bill of materials:", err)
			return 2
		}
	}

	// A person watching this run gets the page as well as the text, on every
	// platform.
	//
	// This used to happen only for a Windows double-click, on the reasoning
	// that the console window vanishes and takes the output with it. That is
	// true, but it made the product different depending on how it was started:
	// someone who ran it on Ubuntu got a wall of terminal text and never
	// learned the report existed. The page is the readable form of this
	// scan -- the coverage table, the evidence lists and the component
	// inventory do not fit a terminal -- so withholding it from most users was
	// the wrong default.
	//
	// It is skipped when nobody is watching: output piped to a file or another
	// program, --json, and CI. Those runs want the data, not a page, and
	// writing a file they did not ask for would be a change to their machine.
	autoReport := false
	if *htmlPath == "" && !*jsonOut && !*noHTML && (ownsConsole() || stdoutIsTerminal()) {
		*htmlPath = defaultReportPath()
		autoReport = true
	}

	if *htmlPath != "" {
		if err := writeFile(*htmlPath, func(f *os.File) error { return report.HTML(f, r) }); err != nil {
			// A path the user typed is their decision, and failing it is an
			// error. A path this program chose is a guess, and a guess that
			// does not work should be retried somewhere that does.
			if !autoReport {
				fmt.Fprintln(os.Stderr, "aiexpose: could not write HTML report:", err)
				return 2
			}
			*htmlPath = fallbackReportPath()
			if err := writeFile(*htmlPath, func(f *os.File) error { return report.HTML(f, r) }); err != nil {
				fmt.Fprintln(os.Stderr, "aiexpose: could not write HTML report:", err)
				return 2
			}
		}
	}
	if *jsonPath != "" {
		if err := writeFile(*jsonPath, func(f *os.File) error { return report.JSON(f, r) }); err != nil {
			fmt.Fprintln(os.Stderr, "aiexpose: could not write JSON report:", err)
			return 2
		}
	}

	useColor := report.UseColor(*forceColor, *noColor)

	if *jsonOut {
		if err := report.JSON(os.Stdout, r); err != nil {
			fmt.Fprintln(os.Stderr, "aiexpose:", err)
			return 2
		}
	} else {
		report.Terminal(os.Stdout, r, useColor, *verbose)
		if *htmlPath != "" {
			fmt.Printf("A readable report was saved to:\n  %s\n", *htmlPath)
			// Opening it is the only thing this program ever starts, so it
			// happens for the double-click case it exists for, and when asked.
			if shouldOpenReport(*openReport, *noOpen) {
				if err := browse.Open(*htmlPath); err != nil {
					fmt.Printf("Open it in your browser (%v).\n", err)
				} else {
					fmt.Println("Opening it in your browser.")
				}
			} else {
				fmt.Println("Open it in your browser.")
			}
			fmt.Println()
		}
	}

	// Someone who double-clicked has just read the list of what changed and is
	// sitting at the window. Asking here is both the easiest moment to accept
	// and the only one where the answer means anything.
	if supplyResult.HasPending() && !*accept && !*jsonOut && canPrompt(pauseForce, pauseDisable) {
		if confirmAccept(os.Stdin, os.Stdout, supplyResult.Pending) {
			if err := supply.SaveBaseline(supplyResult.BaselinePath, supplyResult.Inventory); err != nil {
				fmt.Fprintln(os.Stderr, "aiexpose: baseline could not be written:", err)
			} else {
				fmt.Printf("Recorded. %d component(s) are now the accepted state.\n",
					len(supplyResult.Inventory.Artifacts))
			}
		} else {
			fmt.Println("Left as they were. Nothing was recorded.")
		}
	}

	if threshold >= 0 {
		for _, f := range r.Findings {
			if f.Severity >= model.Severity(threshold) {
				return 1
			}
		}
	}
	return 0
}

// runCI gates a repository: it inventories the AI components the repo ships,
// applies the committed policy, and exits non-zero when the gate fails.
func runCI(args []string) int {
	fs := flag.NewFlagSet("aiexpose ci", flag.ExitOnError)
	var (
		dir        = fs.String("path", ".", "repository directory to inspect")
		policyPath = fs.String("policy", "", "policy file (default <path>/"+policyFileName+")")
		lockPath   = fs.String("lock", "", "lockfile (default <path>/"+lockFileName+")")
		writeLock  = fs.Bool("write-lock", false, "record the current components as reviewed and write the lockfile")
		sarifPath  = fs.String("sarif", "", "write SARIF 2.1.0 results here for code scanning")
		jsonOut    = fs.Bool("json", false, "print the result as JSON")
		feedPath   = fs.String("feed", "", "use this signed known-bad list instead of the cached one")
		noFeed     = fs.Bool("no-feed", false, "skip known-bad list matching")
		forceColor = fs.Bool("color", false, "force ANSI colour output")
		noColor    = fs.Bool("no-color", false, "disable ANSI colour output")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `%s ci - gate the AI components a repository ships

Inventories the MCP servers, agent skills and workflow nodes declared in a
repository, then applies the policy committed alongside them. Exits 1 when the
gate fails, so it can run as a required check.

Usage:
  %s ci [flags]

Flags:
`, toolName, toolName)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	res, err := ci.Run(ci.Options{
		Dir: *dir, PolicyPath: *policyPath, LockPath: *lockPath,
		WriteLock: *writeLock, FeedPath: *feedPath, NoFeed: *noFeed,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose ci:", err)
		return 2
	}

	if *sarifPath != "" {
		if err := writeFile(*sarifPath, func(f *os.File) error {
			return report.SARIF(f, res, toolName, version)
		}); err != nil {
			fmt.Fprintln(os.Stderr, "aiexpose ci: could not write SARIF:", err)
			return 2
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(os.Stderr, "aiexpose ci:", err)
			return 2
		}
	} else {
		report.CI(os.Stdout, res, report.UseColor(*forceColor, *noColor))
		if *sarifPath != "" {
			fmt.Printf("SARIF written to %s\n\n", *sarifPath)
		}
	}

	if res.Failed() {
		return 1
	}
	return 0
}

// runFeedUpdate is the only path in the program that reaches the network. It
// sends nothing but a GET for two static files, and refuses anything that does
// not verify against the key compiled into this binary.
// runInstallRules verifies a rule file and stores it where scans look, so the
// user does not have to name it again on every run.
// attestation records what produced this report: which build, which rules,
// which corpus. A finding is only as good as the thing that made it, and a
// reader who has to act on one is entitled to know that much.
func attestation(r *model.Report, rules checks.RulesLoaded, sup checks.SupplyResult) model.Attestation {
	a := model.Attestation{
		Tool: toolName, Version: version, Profile: feed.BuildProfile,
		RuleVersion: rules.FeedVersion, RuleOrigin: rules.FeedOrigin,
		HashIndex:  sup.HashIndex,
		Components: len(sup.Inventory.Artifacts),
	}
	if rules.Indicators > 0 || rules.Credentials > 0 {
		a.RuleCounts = fmt.Sprintf("%d code indicator(s), %d credential pattern(s)",
			rules.Indicators, rules.Credentials)
	} else {
		a.RuleCounts = "none loaded"
	}
	if digest, path, err := selfDigest(); err == nil {
		a.SelfDigest, a.ExePath = digest, path
	}
	return a
}

// runBuildHashDB compiles a folder of hash lists into the index a scan reads.
//
// This is a separate command rather than something a scan does on its own for
// two reasons: it reads about 1.5 GB of text and writes about 255 MB, and it is
// the only part of this feature that needs the user to have decided they want
// it. A scan that quietly grew a quarter-gigabyte file in the home directory
// would be a rude surprise.
func runBuildHashDB(srcDir, outPath string) int {
	if outPath == "" {
		outPath = hashdb.DefaultPath()
	}
	files, err := hashdb.SourceFiles(srcDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose: hash list folder could not be read:", err)
		return 2
	}
	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "aiexpose: no .md5 or .md5.txt files in %s\n", srcDir)
		fmt.Fprintln(os.Stderr, "Download the MD5 lists from https://virusshare.com/hashes and put them in that folder.")
		return 2
	}

	fmt.Printf("Building a malware hash index from %d file(s) in %s\n", len(files), srcDir)
	fmt.Println("This reads the lists and writes one sorted index. Nothing is sent anywhere.")

	last := -100
	stats, err := hashdb.Build(srcDir, outPath, func(done, total int, name string) {
		// One line per 5%%, so a build over 500 files does not scroll a
		// console window away.
		pct := done * 100 / total
		if pct/5 != last/5 || done == total {
			last = pct
			fmt.Printf("  %3d%%  %s\n", pct, name)
		}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose:", err)
		return 2
	}

	fmt.Printf("\nIndexed %s hashes from %d file(s) in %s.\n",
		commas(stats.Hashes), stats.SourceFiles, stats.Elapsed)
	if stats.Duplicates > 0 {
		fmt.Printf("%s duplicate hash(es) were collapsed.\n", commas(stats.Duplicates))
	}
	fmt.Printf("Index: %s (%.0f MB)\n", stats.Path, float64(stats.IndexBytes)/(1<<20))
	fmt.Println("\nEvery scan from now on checks installed files against it automatically.")
	fmt.Println("Use --no-hashdb to skip it, or delete the index file to turn it off for good.")
	return 0
}

// commas groups a count so a nine-figure number is readable at a glance.
func commas(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func runInstallRules(path string) int {
	f, err := feed.InstallFromFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose:", err)
		return 2
	}
	creds := 0
	if f.Credentials != nil {
		creds = len(f.Credentials.Patterns)
	}
	fmt.Printf("Detection rules installed: version %s, published %s.\n"+
		"  %d known-bad component(s), %d detection pattern(s), %d credential pattern(s)\n\n"+
		"Signature verified. Every scan from now on uses these; run %s again to see the full report.\n",
		f.Version, f.Updated.Format("2006-01-02"),
		len(f.Entries), len(f.Indicators), creds, toolName)
	return 0
}

func runFeedUpdate(url string) int {
	if url == "" {
		if f, err := feed.Builtin(); err == nil {
			url = f.Source
		}
	}
	f, err := feed.Update(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aiexpose:", err)
		return 2
	}
	fmt.Printf("Detection rules updated: version %s, %d known-bad entries, published %s.\n",
		f.Version, len(f.Entries), f.Updated.Format("2006-01-02"))
	return 0
}

// shouldOpenReport decides whether to show the report without being asked.
//
// Only when someone double-clicked, or said --open. A scan run from a shell,
// from a scheduled task or in CI must not throw a browser window at anyone.
// shouldOpenReport decides whether to show the page as well as name it.
//
// Anyone waiting at a terminal gets it opened, not only a Windows double-click.
// The page is the readable form of the scan and telling someone a file exists
// is a weaker thing than showing it to them.
//
// browse.Available() keeps that from becoming a nuisance: safe mode starts no
// programs, and a session with no graphical desktop -- a server over SSH -- has
// nothing to open into, where xdg-open can hand the file to a terminal browser
// and take over the window the person is reading. Those runs get the path
// printed instead. --open forces it anyway, for an X11-forwarded session this
// cannot detect.
func shouldOpenReport(force, disable bool) bool {
	if disable {
		return false
	}
	if force {
		return true
	}
	return (ownsConsole() || stdoutIsTerminal()) && browse.Available()
}

// defaultReportPath is where a scan leaves its report when the user did not
// name one: the directory they are standing in.
//
// It used to be the directory holding the executable, which is right for the
// Windows case it was written for -- unzip a folder, double-click, the report
// appears beside it -- and wrong everywhere else. A binary installed with
// "go install" lives in ~/go/bin, and nobody looks there for a report. The
// working directory is where a terminal user already is, and for a
// double-click it is the executable's folder anyway, because that is what
// Explorer sets it to.
//
// It used to confirm the folder was writable by creating a hidden file and
// deleting it again. That is a bad thing to do in a folder Windows protects:
// creating and then deleting a file in Desktop or Documents is the canary
// behaviour Controlled Folder Access exists to catch, and it is the shape of
// a ransomware probe. Writing the report and falling back if that fails
// reaches the same answer without ever touching a file we do not mean to
// leave behind.
func defaultReportPath() string {
	const name = "aiexpose-report.html"
	if wd, err := os.Getwd(); err == nil {
		return filepath.Join(wd, name)
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), name)
	}
	return filepath.Join(os.TempDir(), name)
}

// fallbackReportPath is where the report goes when the folder beside the
// executable will not take it -- a read-only download folder, a protected
// location, or a USB stick pulled out mid-scan.
func fallbackReportPath() string {
	return filepath.Join(os.TempDir(), "aiexpose-report.html")
}

func writeFile(path string, fn func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}

func parseSeverity(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return -1, nil
	case "low":
		return int(model.Low), nil
	case "medium", "med":
		return int(model.Medium), nil
	case "high":
		return int(model.High), nil
	case "critical", "crit":
		return int(model.Critical), nil
	}
	return -1, fmt.Errorf("unknown severity %q for --fail-on (use low, medium, high or critical)", s)
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s %s - is your local AI reachable by anyone but you?

Finds the AI services running on this machine (Ollama, LM Studio, ComfyUI,
Open WebUI, vLLM, Jupyter, vector databases and more), then reports which of
them are exposed to your network or the internet, whether their APIs answer
without credentials, and whether your API keys are sitting in plaintext.

It also fingerprints the components that execute code inside your AI stack --
Ollama models, ComfyUI custom nodes, MCP servers, agent skills -- and tells you
when one of them changes after you accepted it. A package that is safe today and
backdoored next month is the failure mode a one-off scan cannot catch.

Everything runs locally, nothing is uploaded, and the tool has no third-party
dependencies. It reads only: it never writes to this machine.

Usage:
  %s [flags]

Flags:
`, toolName, version, toolName)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Examples:
  %s                          scan and print the result
  %s --html report.html       write the page to a path you choose
  %s --no-html                do not write the page at all
  %s --fail-on high           exit 1 if anything high or critical is found
  %s --accept                 accept the current components as known-good
  %s --scan-history           also search shell history for leaked API keys
  %s --scan-docs              also search Desktop, Documents and Downloads for keys in notes
  %s --scan-dir PATH          also search a work or project folder for keys
  %s --no-open                write the page but do not open it
  %s --safe-mode              skip everything security software tends to block
  %s --install-rules FILE     install detection rules from a signed file
  %s --aibom bom.cdx.json     write a CycloneDX AI bill of materials
  %s --build-hashdb DIR       build the offline malware hash index, once
  %s ci --write-lock          record a repository's reviewed components
  %s ci --sarif out.sarif     gate a repository in CI

aiexpose reads. It never changes this machine: every finding names the exact
step that resolves it, and you run it.
`, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName, toolName)
}

// splitPaths turns the --scan-dir value into folders. The platform's own list
// separator is used so a Windows user can pass two drive-letter paths without
// the colon in "C:" splitting them.
func splitPaths(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, string(os.PathListSeparator)) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
