package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ownsConsole reports whether this process was started by double-clicking it,
// rather than from a shell that will still be there when it exits.
//
// It matters because a console program launched from Explorer gets its own
// window, and Windows destroys that window the moment the process ends. The
// output is printed correctly and then vanishes, which every user reads as
// "it did nothing".
func ownsConsole() bool { return consoleIsOurs() }

// canPrompt reports whether there is a person at this window who can answer a
// question. Double-clicking is the case that matters; --pause says so
// explicitly, which is also how this path gets exercised from a shell.
func canPrompt(force, disable bool) bool {
	if disable || !stdinIsTerminal() || !stdoutIsTerminal() {
		return false
	}
	return force || ownsConsole()
}

func stdinIsTerminal() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// confirmAccept asks whether the components that differ from the accepted
// baseline should be recorded as reviewed.
//
// It defaults to no, and it lists what would be accepted first. Accepting a
// baseline is the moment the user vouches for something, so it has to be a
// decision rather than a reflex: everything after it is measured against what
// is agreed here.
func confirmAccept(in io.Reader, out io.Writer, pending []string) bool {
	fmt.Fprintf(out, "\n%d component(s) differ from the state you last accepted:\n", len(pending))
	for i, p := range pending {
		if i >= 12 {
			fmt.Fprintf(out, "    ... and %d more\n", len(pending)-i)
			break
		}
		fmt.Fprintf(out, "    %s\n", p)
	}
	fmt.Fprint(out, "\nRecord these as reviewed, so future changes are measured against them? [y/N] ")

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false // no answer is not a yes
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// confirmScanDocs asks whether to search the personal document folders.
//
// It is asked rather than assumed, and it is asked at the start, because the
// answer decides whether this run reads the person's own writing. Making it
// the silent default for double-click would mean the report's own sentence --
// "not searched by default, because reading every text file in your documents
// is what an information stealer does" -- was false for most of the people
// reading it.
//
// It defaults to no. No answer is not a yes.
func confirmScanDocs(in io.Reader, out io.Writer) bool {
	fmt.Fprint(out, "\nPeople often keep API keys in a note: keys.txt, or a memo in Documents.\n"+
		"Searching for them means reading the text files on your Desktop, in Documents\n"+
		"and in Downloads. Nothing is uploaded, nothing is changed, and any key found is\n"+
		"masked in the report.\n\n"+
		"Search them for leaked API keys? [y/N] ")

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// pauseIfLaunchedByDoubleClick holds the window open so the report can be read.
// It does nothing when output is redirected, or when a shell is waiting.
func pauseIfLaunchedByDoubleClick(force, disable bool) {
	if disable {
		return
	}
	if !force {
		if !ownsConsole() || !stdoutIsTerminal() {
			return
		}
	}
	fmt.Print("\nPress Enter to close this window. ")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func stdoutIsTerminal() bool {
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
