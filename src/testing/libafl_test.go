// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testing

import (
	"math"
	"reflect"
	"slices"
)

func TestLibAFLMarshalUnmarshal_OneArgBytesPassThrough(t *T) {
	types := []reflect.Type{reflect.TypeFor[[]byte]()}
	orig := []byte{0, 1, 2, 3, 250, 255}
	values := []any{slices.Clone(orig)}

	encoded, ok := libaflMarshalInputs(values, types)
	if !ok {
		t.Fatal("marshal failed")
	}
	if !slices.Equal(encoded, orig) {
		t.Fatalf("encoded bytes mismatch: got %v want %v", encoded, orig)
	}

	args := libaflUnmarshalArgs(encoded, types)
	if len(args) != 1 {
		t.Fatalf("unexpected args length: %d", len(args))
	}
	got := args[0].Interface().([]byte)
	if !slices.Equal(got, orig) {
		t.Fatalf("round-trip mismatch: got %v want %v", got, orig)
	}
}

func TestLibAFLMarshalUnmarshal_OneArgStringPassThrough(t *T) {
	types := []reflect.Type{reflect.TypeFor[string]()}
	values := []any{"hello libafl"}

	encoded, ok := libaflMarshalInputs(values, types)
	if !ok {
		t.Fatal("marshal failed")
	}

	args := libaflUnmarshalArgs(encoded, types)
	if len(args) != 1 {
		t.Fatalf("unexpected args length: %d", len(args))
	}
	got := args[0].Interface().(string)
	if got != values[0].(string) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, values[0].(string))
	}
}

func TestLibAFLMarshalUnmarshal_RoundTripScalars(t *T) {
	types := []reflect.Type{
		reflect.TypeFor[int32](),
		reflect.TypeFor[uint16](),
		reflect.TypeFor[bool](),
		reflect.TypeFor[float64](),
		reflect.TypeFor[string](),
	}
	values := []any{int32(-123), uint16(42), true, float64(1.25), "abc"}

	encoded, ok := libaflMarshalInputs(values, types)
	if !ok {
		t.Fatal("marshal failed")
	}

	args := libaflUnmarshalArgs(encoded, types)
	if len(args) != len(types) {
		t.Fatalf("unexpected args length: %d", len(args))
	}

	if got := args[0].Interface().(int32); got != values[0].(int32) {
		t.Fatalf("int32 mismatch: got %d want %d", got, values[0].(int32))
	}
	if got := args[1].Interface().(uint16); got != values[1].(uint16) {
		t.Fatalf("uint16 mismatch: got %d want %d", got, values[1].(uint16))
	}
	if got := args[2].Interface().(bool); got != values[2].(bool) {
		t.Fatalf("bool mismatch: got %v want %v", got, values[2].(bool))
	}
	if got := args[3].Interface().(float64); math.Float64bits(got) != math.Float64bits(values[3].(float64)) {
		t.Fatalf("float64 mismatch: got %v want %v", got, values[3].(float64))
	}
	if got := args[4].Interface().(string); got != values[4].(string) {
		t.Fatalf("string mismatch: got %q want %q", got, values[4].(string))
	}
}

func TestLibAFLMarshalUnmarshal_RoundTripCompositeAndUnexported(t *T) {
	type inner struct {
		x int16
		Y []uint8
	}
	type outer struct {
		A *inner
		b string // unexported: must be set via unsafe path in libaflDecodeValue
		C [3]uint16
		D []inner
	}

	v := outer{
		A: &inner{x: -7, Y: []uint8{1, 2, 3}},
		b: "secret",
		C: [3]uint16{10, 11, 12},
		D: []inner{
			{x: 1, Y: nil},
			{x: 2, Y: []uint8{9}},
		},
	}

	types := []reflect.Type{reflect.TypeFor[outer]()}
	values := []any{v}

	encoded, ok := libaflMarshalInputs(values, types)
	if !ok {
		t.Fatal("marshal failed")
	}

	args := libaflUnmarshalArgs(encoded, types)
	if len(args) != 1 {
		t.Fatalf("unexpected args length: %d", len(args))
	}
	got := args[0].Interface().(outer)
	if !reflect.DeepEqual(got, v) {
		t.Fatalf("round-trip mismatch:\n got: %#v\nwant: %#v", got, v)
	}
}
