package hostmib

import (
	"testing"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/mib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
)

func TestLiveSmoke(t *testing.T) {
	s := NewSampler(DefaultFS)
	h := &Host{FS: DefaultFS, Sampler: s, Config: func() System { return System{} }, ObjectID: snmp.MustOID("1.3.6.1.4.1.8072.9999.9999.47621.4.1"), Started: time.Now()}
	tr := mib.New()
	h.Register(tr)
	all := tr.Walk(snmp.OID{1})
	if len(all) < 50 {
		t.Fatalf("only %d", len(all))
	}
	if testing.Verbose() {
		for _, vb := range all {
			t.Log(vb.OID, vb.Value)
		}
	}
}
