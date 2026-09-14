//go:build !bundled

package feed

import _ "embed"

// The default build embeds no detection patterns, no credential patterns and
// no known-bad entries -- only a signed, empty document.
//
// This is not a size optimisation. Measured on a Windows machine running
// Kaspersky and Microsoft Defender, the build that embeds those patterns was
// quarantined within seconds of launching, while this one ran normally. The
// two binaries were the same version, built from the same source with the same
// flags at the same moment; the only difference was the string table. A default
// download that antivirus deletes is not a default.
//
// Rules arrive at runtime: `aiexpose --update-feed` once, or `--feed FILE`.
//
//go:embed data/empty.json
var builtinDoc []byte

//go:embed data/empty.json.sig
var builtinSig []byte

// BuildProfile names which copy is compiled in, for the report.
const BuildProfile = "default"

// RulesBundled reports whether this binary carries rules of its own.
const RulesBundled = false
