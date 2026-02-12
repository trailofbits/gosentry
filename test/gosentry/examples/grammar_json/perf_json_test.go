package grammar_json

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func FuzzJSONUnmarshal(f *testing.F) {
	f.Add([]byte(`null`))
	f.Add([]byte(`{"a":1,"b":[true,false,null],"c":"x"}`))
	f.Add([]byte(`[{"k":"v"},{"n":123}]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			return
		}
	})
}

func FuzzJSONDecoder(f *testing.F) {
	f.Add([]byte(`null`))
	f.Add([]byte(`{"a":1,"b":[true,false,null],"c":"x"}`))
	f.Add([]byte(`[{"k":"v"},{"n":123}]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()

		var v any
		if err := dec.Decode(&v); err != nil {
			return
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			return
		}
	})
}

