package mibs

import (
	"bytes"
	"testing"
)

// The shipped module is the template rendered with this release's parameters.
func TestRendered(t *testing.T) {
	b, err := Render(Current)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, File) {
		t.Fatal("LITE-SNMP-MIB.txt is stale: go generate ./mibs")
	}
	if !bytes.Contains(File, []byte("PROVISIONAL")) {
		t.Error("the MIB must say the root is provisional")
	}
}
