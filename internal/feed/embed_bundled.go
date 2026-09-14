//go:build bundled

package feed

import _ "embed"

// The bundled build embeds the full rule set, so it works with no network at
// all. It is the right choice for an air-gapped machine and the wrong one for
// a normal laptop: its string table is, character for character, the one an
// information stealer carries, and endpoint protection quarantines it on sight.
//
//go:embed data/feed.json
var builtinDoc []byte

//go:embed data/feed.json.sig
var builtinSig []byte

// BuildProfile names which copy is compiled in, for the report.
const BuildProfile = "bundled"

// RulesBundled reports whether this binary carries rules of its own.
const RulesBundled = true
