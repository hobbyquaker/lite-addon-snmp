// gen renders LITE-SNMP-MIB.txt from its template (go generate in mibs/).
package main

import (
	"log"
	"os"

	"github.com/hobbyquaker/lite-addon-snmp/mibs"
)

func main() {
	b, err := mibs.Render(mibs.Current)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(mibs.FileName, b, 0o644); err != nil {
		log.Fatal(err)
	}
}
