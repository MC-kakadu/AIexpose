package report

import (
	"encoding/json"
	"io"

	"github.com/MC-kakadu/AIexpose/internal/model"
)

// JSON writes the machine-readable report.
func JSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
