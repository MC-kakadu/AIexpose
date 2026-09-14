package feed

// ReleasedWith is the version of the rule file this build was released
// alongside.
//
// It exists because of a failure that looked exactly like success. A release
// shipped with fourteen known-bad entries; the machine it ran on still had the
// three-entry rule file from the previous release sitting beside the binary,
// which verified perfectly and loaded in preference to the default build's
// empty one. The report then said "No installed component appears on the
// known-bad list (3 entries)" -- true, verified, signed, and eleven entries
// short of what that binary was published with. Nothing was broken enough to
// produce an error, so nothing did.
//
// A version string is not a detection pattern, so carrying it costs the default
// build nothing: the whole point of that build is that its string table does
// not look like an information stealer's, and a date-shaped constant does not
// change that. What it buys is the ability to notice that the rules on this
// machine are older than the ones this binary was published with, which no
// amount of signature checking can tell you.
//
// TestReleasedWithMatchesShippedFeed keeps it honest: it fails the build if
// this constant and data/feed.json disagree.
const ReleasedWith = "2026.09.14.2"

// BehindRelease reports whether a loaded feed predates the rule file this build
// shipped with, and returns both versions so the report can name them.
//
// A feed newer than the release is the normal state after --update-feed and is
// not reported. An unversioned or unparseable feed is not reported either:
// there is nothing to compare, and guessing in either direction would be worse
// than staying quiet about it.
func (f Feed) BehindRelease() (behind bool, have, want string) {
	if _, ok := versionParts(f.Version); !ok {
		return false, f.Version, ReleasedWith
	}
	if _, ok := versionParts(ReleasedWith); !ok {
		return false, f.Version, ReleasedWith
	}
	return newerVersion(ReleasedWith, f.Version), f.Version, ReleasedWith
}
