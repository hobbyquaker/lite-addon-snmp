// Package addonpkg tests the package files the addon ships.
package addonpkg

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit/fragment"
	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit/manifest"
)

// The manifest as the system validates it at install, through the kit's strict load.
// The kit's subset does not know port_info's proto yet (occulited's format has it: tcp/udp,
// informational), so it is left out of the copy the kit validates.
func TestManifest(t *testing.T) {
	b, err := os.ReadFile("../../addon/openccu-lite.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, pi := range raw["runtime"].(map[string]any)["port_info"].(map[string]any) {
		delete(pi.(map[string]any), "proto")
	}
	b, _ = json.Marshal(raw)
	tmp := t.TempDir() + "/openccu-lite.json"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Load(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != "snmp" || m.Undeclared() || m.Runtime == nil || !m.Runtime.Daemon {
		t.Fatalf("manifest: %+v", m)
	}
	if len(m.Runtime.Capabilities) != 1 || m.Runtime.Capabilities[0] != "CAP_NET_BIND_SERVICE" {
		t.Errorf("capabilities %v", m.Runtime.Capabilities)
	}
	for _, s := range m.Runtime.APIScopes {
		if strings.HasSuffix(s, ":write") || s == "rpc:operate" || s == "rpc:configure" || s == "rpc:admin" {
			t.Errorf("a read-only agent asks for %s", s)
		}
	}
	if m.Description["de"] == "" || m.Description["en"] == "" {
		t.Error("the description in both languages")
	}
}

// The declared port is UDP 161 with a label.
func TestPort(t *testing.T) {
	var m struct {
		Runtime struct {
			Ports    []int `json:"ports"`
			PortInfo map[string]struct {
				Proto string            `json:"proto"`
				Label map[string]string `json:"label"`
			} `json:"port_info"`
		} `json:"runtime"`
	}
	b, _ := os.ReadFile("../../addon/openccu-lite.json")
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	pi := m.Runtime.PortInfo["161"]
	if len(m.Runtime.Ports) != 1 || m.Runtime.Ports[0] != 161 || pi.Proto != "udp" || pi.Label["de"] == "" || pi.Label["en"] == "" {
		t.Errorf("ports %+v", m.Runtime)
	}
}

// The manifest's images are tracked at the path the catalogue reads them from.
func TestImagesTracked(t *testing.T) {
	for _, p := range []string{"addon/snmp/www/icon.svg", "addon/snmp/www/icon-dark.svg"} {
		if out, err := exec.Command("git", "-C", "../..", "ls-files", "--error-unmatch", "--", p).CombinedOutput(); err != nil {
			t.Errorf("%s not tracked: %v %s", p, err, out)
		}
	}
}

// The proxy rule is what the kit's renderer writes (apart from the comment lines).
func TestFragment(t *testing.T) {
	want, err := fragment.Render(fragment.Fragment{ID: "snmp", Port: 8296, ErrorfilePrefix: "/usr/local/addons/snmp/www/lighttpd-error-"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile("../../addon/snmp/etc/lighttpd.conf")
	strip := func(s string) string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, "#") && strings.TrimSpace(l) != "" {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n")
	}
	if strip(string(got)) != strip(want) {
		t.Errorf("etc/lighttpd.conf:\n%s\nwant:\n%s", got, want)
	}
}

// The 503 page names the addon.
func TestErrorPage(t *testing.T) {
	for _, p := range []string{"../../addon/static/lighttpd-error-503.html", "../../addon/snmp/www/lighttpd-error-503.html"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "<title>SNMP</title>") {
			t.Errorf("%s does not name SNMP", p)
		}
	}
}
