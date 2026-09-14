package checks

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MC-kakadu/AIexpose/internal/advice"
	"github.com/MC-kakadu/AIexpose/internal/model"
)

// PortMapping is one forwarding rule read from the local router.
type PortMapping struct {
	ExternalPort   int
	InternalPort   int
	InternalClient string
	Protocol       string
	Description    string
	Enabled        bool
}

const (
	ssdpAddr    = "239.255.255.250:1900"
	ssdpTimeout = 3 * time.Second
	maxMappings = 80
)

var wanServiceTypes = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// PortForwarding asks the local gateway, over the LAN only, which ports it
// forwards from the internet. Nothing is sent outside the local network.
// PortForwarding reports router rules that expose a discovered AI service.
func PortForwarding(r *model.Report, services []model.Service) {
	mappings, err := discoverMappings()
	if err != nil {
		r.Note("Router port forwarding was not read: " + err.Error() +
			". Rules added by hand are never visible over UPnP, so check the router's admin page too.")
		return
	}
	if len(mappings) == 0 {
		r.Add(model.Finding{
			ID: "NAT-000", Title: "No UPnP port forwarding rules found on the router",
			Severity: model.Info,
			Detail: "The gateway answered the port-mapping query and reported no active mappings, so nothing is " +
				"currently forwarded from the internet.\n" +
				"It answering at all means UPnP is switched on: any program on this network can open a port " +
				"through the router without asking you, and this check only sees the result afterwards. " +
				"Rules added by hand in the router's admin page are never visible over UPnP, so check there too.",
		})
		return
	}

	byPort := map[int][]model.Service{}
	for _, s := range services {
		byPort[s.Listener.Port] = append(byPort[s.Listener.Port], s)
	}

	matched := 0
	for _, m := range mappings {
		hits := byPort[m.InternalPort]
		if len(hits) == 0 {
			continue
		}
		matched++
		names := make([]string, 0, len(hits))
		noAuth := false
		for _, h := range hits {
			names = append(names, h.Name)
			if h.NoAuth {
				noAuth = true
			}
		}
		sev := model.Critical
		title := fmt.Sprintf("Your router forwards the internet to %s", strings.Join(names, ", "))
		detail := fmt.Sprintf(
			"The gateway has a UPnP mapping: external %s port %d -> %s:%d (%q). That means this service is reachable from the public internet, not just your home network.",
			m.Protocol, m.ExternalPort, m.InternalClient, m.InternalPort, m.Description)
		if noAuth {
			detail += " The service also answered an API request with no credentials."
		}
		r.Add(model.Finding{
			ID: "NAT-001", Title: title, Severity: sev, Detail: detail,
			Fix: advice.DeletePortForward(m.Protocol, m.ExternalPort, m.InternalClient, m.InternalPort),
		})
	}

	if matched == 0 {
		r.Add(model.Finding{
			ID: "NAT-002", Title: fmt.Sprintf("Router has %d UPnP port forwarding rule(s)", len(mappings)),
			Severity: model.Low,
			Detail:   "None of them point at a discovered AI service, but UPnP lets any program on your network open a hole in the firewall without asking you.",
			Evidence: describe(mappings),
			Fix:      "Review these rules in the router admin page and turn UPnP off unless something you rely on needs it.",
		})
	}
}

// describe lists every mapping the gateway reported.
func describe(ms []PortMapping) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, fmt.Sprintf("%s %d -> %s:%d  %q",
			m.Protocol, m.ExternalPort, m.InternalClient, m.InternalPort, m.Description))
	}
	return out
}

func discoverMappings() ([]PortMapping, error) {
	locations, err := ssdpSearch()
	if err != nil {
		return nil, err
	}
	if len(locations) == 0 {
		return nil, fmt.Errorf("no UPnP gateway answered on the local network")
	}
	for _, loc := range locations {
		ctrl, svcType, err := controlURL(loc)
		if err != nil || ctrl == "" {
			continue
		}
		if ms, err := listMappings(ctrl, svcType); err == nil {
			return ms, nil
		}
	}
	// An M-SEARCH for ssdp:all answers from televisions, printers and speakers
	// as well as routers, so "devices replied but none was a router" is the
	// normal result when UPnP is switched off at the gateway -- which is the
	// safer configuration, not a fault.
	return nil, fmt.Errorf("%d UPnP device(s) replied but none exposed a router port-mapping service, "+
		"which usually means UPnP is turned off on your router (a good thing)", len(locations))
}

// ssdpSearch multicasts an M-SEARCH and collects LOCATION headers.
func ssdpSearch() ([]string, error) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []string
	for _, st := range []string{"urn:schemas-upnp-org:device:InternetGatewayDevice:1", "ssdp:all"} {
		msg := "M-SEARCH * HTTP/1.1\r\n" +
			"HOST: " + ssdpAddr + "\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n" +
			"ST: " + st + "\r\n\r\n"
		if _, err := conn.WriteTo([]byte(msg), dst); err != nil {
			continue
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(ssdpTimeout))
	buf := make([]byte, 8192)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		for _, line := range strings.Split(string(buf[:n]), "\n") {
			if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "LOCATION:") {
				continue
			}
			loc := strings.TrimSpace(line[strings.Index(line, ":")+1:])
			if loc != "" && !seen[loc] {
				seen[loc] = true
				out = append(out, loc)
			}
		}
	}
	return out, nil
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

type upnpRoot struct {
	Device upnpDevice `xml:"device"`
}

func controlURL(location string) (string, string, error) {
	base, err := url.Parse(location)
	if err != nil {
		return "", "", err
	}
	c := &http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get(location)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return "", "", err
	}
	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return "", "", err
	}
	ctrl, st := findWAN(root.Device)
	if ctrl == "" {
		return "", "", fmt.Errorf("no WAN connection service in device description")
	}
	ref, err := url.Parse(ctrl)
	if err != nil {
		return "", "", err
	}
	return base.ResolveReference(ref).String(), st, nil
}

func findWAN(d upnpDevice) (string, string) {
	for _, s := range d.Services {
		for _, want := range wanServiceTypes {
			if strings.EqualFold(strings.TrimSpace(s.ServiceType), want) {
				return s.ControlURL, want
			}
		}
	}
	for _, sub := range d.Devices {
		if c, st := findWAN(sub); c != "" {
			return c, st
		}
	}
	return "", ""
}

// errEndOfTable means the gateway answered correctly and there is no entry at
// this index. At index 0 that is an empty mapping table, which is a result --
// UPnP is enabled and forwarding nothing -- and not a broken service.
var errEndOfTable = errors.New("end of mapping table")

// upnpFault is the error the UPnP spec defines for "no such index". Routers
// return it as a SOAP fault with HTTP 500, so the status code alone cannot
// tell an empty table from a gateway that does not speak this profile.
const indexInvalidCode = "713"

type mappingEnvelope struct {
	ExternalPort   string `xml:"Body>GetGenericPortMappingEntryResponse>NewExternalPort"`
	Protocol       string `xml:"Body>GetGenericPortMappingEntryResponse>NewProtocol"`
	InternalPort   string `xml:"Body>GetGenericPortMappingEntryResponse>NewInternalPort"`
	InternalClient string `xml:"Body>GetGenericPortMappingEntryResponse>NewInternalClient"`
	Description    string `xml:"Body>GetGenericPortMappingEntryResponse>NewPortMappingDescription"`
	Enabled        string `xml:"Body>GetGenericPortMappingEntryResponse>NewEnabled"`
}

func listMappings(ctrl, svcType string) ([]PortMapping, error) {
	c := &http.Client{Timeout: 4 * time.Second}
	var out []PortMapping
	for i := 0; i < maxMappings; i++ {
		env, err := getMapping(c, ctrl, svcType, i)
		if err != nil {
			// An empty table at index 0 is an answer, not a failure. Treating
			// it as a failure made the report tell users with UPnP switched on
			// and no forwards that "UPnP is turned off on your router (a good
			// thing)" -- reassurance for the opposite of what was true.
			if i == 0 && !errors.Is(err, errEndOfTable) {
				return nil, err
			}
			break
		}
		ext, _ := strconv.Atoi(strings.TrimSpace(env.ExternalPort))
		in, _ := strconv.Atoi(strings.TrimSpace(env.InternalPort))
		if ext == 0 && in == 0 {
			break
		}
		out = append(out, PortMapping{
			ExternalPort:   ext,
			InternalPort:   in,
			InternalClient: strings.TrimSpace(env.InternalClient),
			Protocol:       strings.TrimSpace(env.Protocol),
			Description:    strings.TrimSpace(env.Description),
			Enabled:        strings.TrimSpace(env.Enabled) == "1",
		})
	}
	return out, nil
}

func getMapping(c *http.Client, ctrl, svcType string, index int) (*mappingEnvelope, error) {
	body := `<?xml version="1.0"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:GetGenericPortMappingEntry xmlns:u="` + svcType + `">` +
		`<NewPortMappingIndex>` + strconv.Itoa(index) + `</NewPortMappingIndex>` +
		`</u:GetGenericPortMappingEntry></s:Body></s:Envelope>`

	req, err := http.NewRequest(http.MethodPost, ctrl, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+svcType+`#GetGenericPortMappingEntry"`)

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if bytes.Contains(raw, []byte(indexInvalidCode)) || bytes.Contains(raw, []byte("SpecifiedArrayIndexInvalid")) {
			return nil, errEndOfTable
		}
		return nil, fmt.Errorf("gateway returned %d", resp.StatusCode)
	}
	var env mappingEnvelope
	if err := xml.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if strings.TrimSpace(env.ExternalPort) == "" && strings.TrimSpace(env.InternalClient) == "" {
		return nil, errEndOfTable
	}
	return &env, nil
}
