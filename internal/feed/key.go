package feed

// PublicKeyHex is the Ed25519 public key every feed must be signed with.
//
// Changing this key means shipping a new binary, which is the point: a feed
// served from a compromised host cannot make this tool accuse innocent
// packages, and cannot quietly empty itself to hide a known-bad one.
const PublicKeyHex = "a58730843671e671550621246254bc24d16b635ff23d5c412656135f54896b9c"
