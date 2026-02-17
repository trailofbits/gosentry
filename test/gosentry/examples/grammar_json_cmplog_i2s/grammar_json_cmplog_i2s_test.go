package grammar_json_cmplog_i2s

import (
	"encoding/json"
	"testing"
)

type payload struct {
	A string `json:"a"`
	B string `json:"b"`
}

const (
	wantA = "MAGICONE"
	wantB = "MAGICTWO"
)

func FuzzGrammarJSONCmpLogI2S(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p payload
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}

		if p.A == wantA {
			if p.B == wantB {
				panic("GOSENTRY_NAUTILUS_CMPLOG_I2S_OK")
			}
		}

		// Make reaching each constraint a distinct coverage milestone, regardless
		// of the order in which the fuzzer satisfies them.
		if p.B == wantB {
			return
		}
	})
}
