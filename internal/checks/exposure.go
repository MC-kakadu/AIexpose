// Package checks turns observed state into findings.
package checks

import (
	"fmt"

	"github.com/MC-kakadu/AIexpose/internal/advice"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

// highValue services grant code execution or bulk data access when reached,
// so any non-loopback binding is treated one step more severely.
var highValue = map[string]bool{
	"Jupyter":       true,
	"Ray Dashboard": true,
	"ComfyUI":       true,
	"n8n":           true,
	"Flowise":       true,
}

// Exposure reports how each discovered service is bound and whether its API
// answers without credentials.
func Exposure(r *model.Report, services []model.Service) {
	for _, s := range services {
		where := fmt.Sprintf("%s on %s:%d", s.Name, s.Listener.Addr, s.Listener.Port)
		proc := s.Listener.Process
		if proc != "" {
			where += fmt.Sprintf(" (pid %d, %s)", s.Listener.PID, truncate(proc, 90))
		}

		switch s.Exposure {
		case model.AllIfaces:
			sev := model.High
			title := s.Name + " is listening on every network interface"
			detail := where + " is bound to a wildcard address, so anything that can route to this machine can reach it: other devices on your Wi-Fi, and the whole internet if this port is forwarded."
			if s.NoAuth {
				sev = model.Critical
				title = s.Name + " is open to the network with no authentication"
				detail = where + " is bound to a wildcard address and answered an API request with no credentials at all. Anyone who can reach this port has the same access you do."
			} else if highValue[s.Name] {
				sev = model.Critical
				title = s.Name + " is exposed on every interface"
				detail = where + " is bound to a wildcard address. This service can execute code or reach your files, so network exposure is equivalent to handing out a shell."
			}
			f := model.Finding{
				ID: "EXP-001", Title: title, Severity: sev, Detail: detail,
				Fix: bindFix(s.Name),
			}
			if s.Name == "Ollama" {
				f.Command = advice.OllamaBind()
				f.Fix += " " + advice.OllamaBindNote()
			}
			r.Add(f)

		case model.LANBound:
			sev := model.Medium
			if s.NoAuth {
				sev = model.High
			}
			r.Add(model.Finding{
				ID:       "EXP-002",
				Title:    s.Name + " is reachable from your local network",
				Severity: sev,
				Detail:   where + " is bound to a non-loopback interface address. Every device on the same network segment can connect, including anything else on a shared or public Wi-Fi.",
				Fix:      bindFix(s.Name),
			})

		default:
			if s.NoAuth {
				f := model.Finding{
					ID:       "EXP-003",
					Title:    s.Name + " accepts unauthenticated requests on loopback",
					Severity: model.Low,
					Detail:   where + " is correctly bound to loopback, but its API needs no credentials. Any process on this machine, and any web page that your browser lets talk to localhost, can drive it.",
					Fix:      "Enable authentication if the service supports it, and narrow which browser origins may reach it.",
				}
				if s.Name == "Ollama" {
					f.Command = advice.OllamaOrigins("")
				}
				r.Add(f)
			} else {
				r.Add(model.Finding{
					ID:       "EXP-000",
					Title:    s.Name + " is bound to loopback only",
					Severity: model.Info,
					Detail:   where + " is only reachable from this machine. This is the correct configuration.",
				})
			}
		}
	}
}

func bindFix(name string) string {
	switch name {
	case "Ollama":
		return "Unset OLLAMA_HOST, or set it to 127.0.0.1:11434, then restart Ollama. If you need remote access, put it behind an authenticating reverse proxy or a private network such as WireGuard or Tailscale."
	case "ComfyUI", "Stable Diffusion WebUI", "text-generation-webui":
		return "Remove --listen (and --share) from the launch command so the server binds to 127.0.0.1. If you need remote access, tunnel it over SSH or a private network rather than exposing the port."
	case "Jupyter":
		return "Bind to 127.0.0.1, keep token or password authentication enabled, and reach remote notebooks over an SSH tunnel."
	case "Qdrant", "Chroma", "Weaviate", "Milvus":
		return "Bind the database to 127.0.0.1 and enable its API key or auth setting. A vector store holds your embedded documents; exposing it exposes their contents."
	default:
		return "Change the service's bind address to 127.0.0.1 and restart it. Use an SSH tunnel or a private network for remote access instead of opening the port."
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
