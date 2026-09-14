package checks

import (
	"net"
	"os"
	"strings"

	"github.com/MC-kakadu/AIexpose/internal/advice"
	"github.com/MC-kakadu/AIexpose/internal/model"
	"github.com/MC-kakadu/AIexpose/internal/procinfo"
)

// riskyFlag is a launch argument that widens exposure.
type riskyFlag struct {
	flag     string
	severity model.Severity
	title    string
	detail   string
	fix      string
}

var riskyFlags = []riskyFlag{
	{
		flag: "--share", severity: model.Critical,
		title:  "A Gradio public share tunnel is active",
		detail: "The process was started with --share, which publishes a *.gradio.live URL that anyone on the internet can open. The link is unlisted, not private, and it bypasses your firewall and router entirely.",
		fix:    "Remove --share from the launch command and restart. Share the interface over SSH port forwarding or a private network instead.",
	},
	{
		flag: "--listen", severity: model.High,
		title:  "A service was launched with --listen",
		detail: "--listen binds the web UI to 0.0.0.0 instead of localhost, making it reachable from every device that can route to this machine.",
		fix:    "Remove --listen and restart. If you need LAN access, bind to a specific interface and put authentication in front of it.",
	},
	{
		flag: "--host 0.0.0.0", severity: model.High,
		title:  "A service was launched with --host 0.0.0.0",
		detail: "The process explicitly binds to all interfaces.",
		fix:    "Change the argument to --host 127.0.0.1 and restart the service.",
	},
	{
		flag: "--server-name 0.0.0.0", severity: model.High,
		title:  "Gradio server-name is set to 0.0.0.0",
		detail: "The Gradio interface binds to every interface rather than loopback.",
		fix:    "Use --server-name 127.0.0.1, or unset GRADIO_SERVER_NAME.",
	},
	{
		flag: "--notebookapp.token=", severity: model.Critical,
		title:  "Jupyter token authentication is disabled",
		detail: "The notebook server was started with an empty token, so anyone who reaches the port gets a Python shell on this machine.",
		fix:    "Remove the empty --NotebookApp.token argument and let Jupyter generate a token, or set a password.",
	},
	{
		flag: "--identitytoken=", severity: model.Critical,
		title:  "Jupyter identity token authentication is disabled",
		detail: "The server was started with an empty identity token, leaving the kernel API unauthenticated.",
		fix:    "Remove the empty --IdentityProvider.token argument and restart with authentication enabled.",
	},
	{
		flag: "--disable-auth", severity: model.High,
		title:  "A service was launched with authentication disabled",
		detail: "An explicit auth-disabling flag was found on the command line.",
		fix:    "Remove the flag and restart the service.",
	},
}

// riskyEnv is an environment variable whose value widens exposure.
type riskyEnv struct {
	name     string
	bad      func(string) bool
	severity model.Severity
	title    string
	detail   string
	fix      string
}

var riskyEnvs = []riskyEnv{
	{
		name:     "OLLAMA_HOST",
		bad:      func(v string) bool { return nonLoopbackValue(v) },
		severity: model.High, title: "OLLAMA_HOST points away from loopback",
		detail: "Ollama is configured to bind somewhere other than 127.0.0.1, which puts its model API on the network. The API has no authentication of any kind.",
		fix:    "Unset OLLAMA_HOST or set it to 127.0.0.1:11434, then restart Ollama.",
	},
	{
		name:     "OLLAMA_ORIGINS",
		bad:      func(v string) bool { return strings.Contains(v, "*") },
		severity: model.Medium, title: "OLLAMA_ORIGINS allows any browser origin",
		detail: "A wildcard origin lets any web page you visit issue cross-origin requests to your local Ollama: listing your models, running inference on your hardware, and reading the responses.",
		fix:    "Replace the wildcard with the specific origins you actually use, for example http://localhost:3000.",
	},
	{
		name:     "GRADIO_SERVER_NAME",
		bad:      func(v string) bool { return nonLoopbackValue(v) },
		severity: model.High, title: "GRADIO_SERVER_NAME binds Gradio to the network",
		detail: "Gradio apps launched in this shell will listen on a non-loopback address.",
		fix:    "Unset GRADIO_SERVER_NAME or set it to 127.0.0.1.",
	},
	{
		name:     "COMFYUI_LISTEN",
		bad:      func(v string) bool { return nonLoopbackValue(v) },
		severity: model.High, title: "COMFYUI_LISTEN binds ComfyUI to the network",
		detail: "ComfyUI will bind to a non-loopback address, and its API can queue arbitrary workflows.",
		fix:    "Unset COMFYUI_LISTEN or set it to 127.0.0.1.",
	},
	{
		name:     "JUPYTER_TOKEN",
		bad:      func(v string) bool { return strings.TrimSpace(v) == "" },
		severity: model.High, title: "JUPYTER_TOKEN is set but empty",
		detail: "An empty token disables notebook authentication.",
		fix:    "Unset JUPYTER_TOKEN, or give it a long random value.",
	},
}

// nonLoopbackValue reports whether a host or host:port setting points anywhere
// other than this machine. It must handle bare hosts ("0.0.0.0"), host:port
// ("127.0.0.1:11434") and bracketed IPv6 ("[::1]:8080") alike.
// envCommand is the exact line that resolves an environment variable finding
// on this operating system.
func envCommand(name string) string {
	switch name {
	case "OLLAMA_HOST":
		return advice.OllamaBind()
	case "OLLAMA_ORIGINS":
		return advice.OllamaOrigins("")
	}
	return advice.UnsetEnv(name)
}

func nonLoopbackValue(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return false
	}
	host := v
	if h, _, err := net.SplitHostPort(v); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "localhost":
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	return true
}

// LaunchFlags inspects the command lines of discovered services.
func LaunchFlags(r *model.Report, services []model.Service) {
	reported := map[string]bool{}
	for _, s := range services {
		cmd := s.Listener.Process
		if full := procinfo.FullCommand(s.Listener.PID); len(full) > len(cmd) {
			cmd = full
		}
		if cmd == "" {
			continue
		}
		lower := strings.ToLower(strings.Join(strings.Fields(cmd), " "))
		for _, rf := range riskyFlags {
			if !strings.Contains(lower, rf.flag) || reported[rf.flag+s.Name] {
				continue
			}
			reported[rf.flag+s.Name] = true
			r.Add(model.Finding{
				ID:       "CFG-001",
				Title:    rf.title + " (" + s.Name + ")",
				Severity: rf.severity,
				Detail:   rf.detail + "\nCommand: " + truncate(cmd, 200),
				Fix:      rf.fix,
			})
		}
	}
}

// Environment inspects the environment this scan is running in. Values are
// never printed, only the variable name and the reason it is risky.
func Environment(r *model.Report) {
	for _, re := range riskyEnvs {
		v, present := os.LookupEnv(re.name)
		if !present || !re.bad(v) {
			continue
		}
		r.Add(model.Finding{
			ID:       "CFG-002",
			Title:    re.title,
			Severity: re.severity,
			Detail:   re.detail + "\nVariable: " + re.name + " (value not shown)",
			Fix:      re.fix,
			Command:  envCommand(re.name),
		})
	}
}
