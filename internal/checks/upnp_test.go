package checks

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const indexInvalidFault = `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">` +
	`<s:Body><s:Fault><faultcode>s:Client</faultcode><detail>` +
	`<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>713</errorCode>` +
	`<errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError>` +
	`</detail></s:Fault></s:Body></s:Envelope>`

func mappingEntry(index int) string {
	return `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>` +
		`<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">` +
		`<NewExternalPort>818` + string(rune('0'+index)) + `</NewExternalPort><NewProtocol>TCP</NewProtocol>` +
		`<NewInternalPort>8188</NewInternalPort><NewInternalClient>192.168.1.5</NewInternalClient>` +
		`<NewEnabled>1</NewEnabled><NewPortMappingDescription>ComfyUI</NewPortMappingDescription>` +
		`</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`
}

// A router with UPnP enabled and an empty mapping table answers index 0 with a
// 713 SOAP fault. That used to be read as "this gateway has no port-mapping
// service", and the report then told the user "UPnP is turned off on your
// router (a good thing)" -- the opposite of the truth, since the router had
// just answered a UPnP query.
func TestEmptyMappingTableIsAnAnswerNotAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(indexInvalidFault))
	}))
	defer srv.Close()

	ms, err := listMappings(srv.URL, wanServiceTypes[0])
	if err != nil {
		t.Fatalf("an empty table reported an error: %v", err)
	}
	if len(ms) != 0 {
		t.Fatalf("got %d mapping(s) from an empty table", len(ms))
	}
}

// And the fault must still end the loop rather than be collected as an entry.
func TestFaultEndsTheMappingTable(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		if calls == 0 {
			calls++
			_, _ = w.Write([]byte(mappingEntry(0)))
			return
		}
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(indexInvalidFault))
	}))
	defer srv.Close()

	ms, err := listMappings(srv.URL, wanServiceTypes[0])
	if err != nil {
		t.Fatalf("listMappings: %v", err)
	}
	if len(ms) != 1 {
		t.Fatalf("got %d mapping(s), want 1", len(ms))
	}
	if ms[0].InternalPort != 8188 || ms[0].InternalClient != "192.168.1.5" {
		t.Errorf("mapping parsed wrong: %+v", ms[0])
	}
}

// A gateway that is genuinely broken must still be reported as broken, not as
// an empty table, or a real failure would read as "nothing is forwarded".
func TestBrokenGatewayIsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("no such service"))
	}))
	defer srv.Close()

	if _, err := listMappings(srv.URL, wanServiceTypes[0]); err == nil {
		t.Fatal("a 404 from the control URL was accepted as an empty mapping table")
	} else if errors.Is(err, errEndOfTable) {
		t.Fatal("a broken gateway was reported as an empty table")
	} else if !strings.Contains(err.Error(), "404") {
		t.Errorf("error does not name the status: %v", err)
	}
}
