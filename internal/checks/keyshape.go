package checks

import "strings"

// looksLikeKeyMaterial rejects a regex match that cannot be a credential,
// whatever the pattern said.
//
// A vendor prefix plus "twenty or more characters" is not a tight enough
// description of a key. A document that lists identifiers -- sk-contract-
// review-dashboard in a skill catalogue, xoxb-order-status-webhook in a
// design note -- satisfies it, and the report then tells someone to rotate
// five credentials that never existed. That happened, on a real machine, to
// five entries in one file.
//
// The test is entropy expressed in the crudest possible form: a random string
// of thirty-odd characters drawn from an alphanumeric alphabet contains a
// digit or a capital with overwhelming probability. The chance a genuine
// 32-character base62 secret is entirely lowercase letters is about one in a
// trillion. A hyphen-separated phrase of English words is entirely lowercase
// almost by definition.
//
// This is deliberately the weakest rule that separates the two, because a
// clever one would eventually reject somebody's real key, and a missed key is
// recoverable while a false accusation is not: the report tells people to
// rotate credentials and treat the machine as compromised.
func looksLikeKeyMaterial(match string) bool {
	body := keyBody(match)
	if body == "" {
		return false
	}
	var hasDigit, hasUpper, hasLower bool
	for _, r := range body {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		}
	}
	if hasDigit || hasUpper {
		return true
	}
	// All lowercase letters and separators. Nothing random looks like this.
	_ = hasLower
	return false
}

// keyBody strips the vendor prefix so the test runs on the random part. The
// prefix is fixed text -- "sk-proj-", "xoxb-", "ghp_" -- and including it
// would let a lowercase prefix vouch for a lowercase body, or a digit in
// "api03" vouch for a body with none.
func keyBody(match string) string {
	// Everything up to and including the last separator that is part of a
	// known prefix shape. Vendors delimit with "-" or "_" and never use one
	// inside the random part except in the long project-key formats, where
	// the body is far longer than any prefix.
	for _, p := range knownPrefixes {
		if strings.HasPrefix(match, p) {
			return match[len(p):]
		}
	}
	return match
}

// knownPrefixes are matched longest-first, so "sk-ant-api03-" wins over
// "sk-ant-" and the version segment is not mistaken for key material.
var knownPrefixes = []string{
	"sk-ant-api03-", "sk-ant-admin01-", "sk-ant-",
	"sk-svcacct-", "sk-admin-", "sk-proj-", "sk-or-v1-", "sk-",
	"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
	"hf_", "gsk_", "r8_", "AKIA", "AIza",
}
