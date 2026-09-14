//go:build !linux && !darwin && !windows

package netstat

import "github.com/MC-kakadu/AIexpose/internal/model"

func listeners() ([]model.Listener, error) {
	return nil, errUnsupported
}

type unsupportedErr struct{}

func (unsupportedErr) Error() string {
	return "socket enumeration is not implemented for this operating system"
}

var errUnsupported = unsupportedErr{}
