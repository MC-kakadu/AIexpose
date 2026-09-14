// Package subproc holds the one switch that decides whether this scan may
// start another program.
//
// It exists because safe mode makes a promise in the report -- "no helper
// programs were started" -- and that promise has to be true everywhere, not
// just in the one package that happened to implement it first. A single
// exported variable read by every caller is easier to audit than a flag
// threaded through four packages, and an audit is the point: endpoint
// protection software judges this binary by what it spawns.
package subproc

// Allowed reports whether a helper program may be started. Safe mode clears
// it before any check runs.
var Allowed = true
