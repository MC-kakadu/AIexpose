// Command feedsign generates the feed signing key and signs a feed document.
//
// The private key never belongs in this repository. Keep it in a secret
// manager and sign as a release step; the public half is compiled into every
// binary, so rotating it means shipping a new release.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	var (
		genKey  = flag.Bool("genkey", false, "generate a new signing keypair and print both halves")
		keyFile = flag.String("key", "", "file holding the hex-encoded private key (or set AIEXPOSE_FEED_KEY)")
		in      = flag.String("in", "", "feed document to sign")
		verify  = flag.String("verify", "", "public key to verify against instead of signing")
	)
	flag.Parse()

	if *genKey {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail(err)
		}
		fmt.Printf("public  %s\nprivate %s\n", hex.EncodeToString(pub), hex.EncodeToString(priv))
		return
	}

	if *in == "" {
		fmt.Fprintln(os.Stderr, "feedsign: -in is required")
		flag.Usage()
		os.Exit(2)
	}
	doc, err := os.ReadFile(*in)
	if err != nil {
		fail(err)
	}

	if *verify != "" {
		sig, err := os.ReadFile(*in + ".sig")
		if err != nil {
			fail(err)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil {
			fail(err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(*verify))
		if err != nil {
			fail(err)
		}
		if !ed25519.Verify(ed25519.PublicKey(key), doc, raw) {
			fmt.Fprintln(os.Stderr, "feedsign: signature does NOT verify")
			os.Exit(1)
		}
		fmt.Println("signature verifies")
		return
	}

	keyHex := os.Getenv("AIEXPOSE_FEED_KEY")
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			fail(err)
		}
		keyHex = string(b)
	}
	if strings.TrimSpace(keyHex) == "" {
		fmt.Fprintln(os.Stderr, "feedsign: no private key given (-key or AIEXPOSE_FEED_KEY)")
		os.Exit(2)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		fail(err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		fail(fmt.Errorf("private key is %d bytes, want %d", len(raw), ed25519.PrivateKeySize))
	}

	sig := ed25519.Sign(ed25519.PrivateKey(raw), doc)
	out := *in + ".sig"
	if err := os.WriteFile(out, []byte(hex.EncodeToString(sig)+"\n"), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("signed %s -> %s\n", *in, out)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "feedsign:", err)
	os.Exit(1)
}
