package grammar_json

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func FuzzGrammarJSON(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()

		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			t.Fatalf("invalid JSON: trailing data")
		}
	})
}
