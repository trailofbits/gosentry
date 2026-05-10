// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 && goexperiment.simd

package maps

import (
	"simd/archsimd"
	"unsafe"
)

const memHashUsesVAES = true

func memHash32AES(p unsafe.Pointer, seed uintptr) uintptr {
	var state archsimd.Uint64x2
	state = state.SetElem(0, uint64(seed)).SetElem(1, uint64(*(*uint32)(p)))

	hash := state.
		AsUint8x16().
		AESEncryptOneRound(archsimd.LoadUint32x4((*[4]uint32)(unsafe.Pointer(&aeskeysched[0])))).
		AESEncryptOneRound(archsimd.LoadUint32x4((*[4]uint32)(unsafe.Pointer(&aeskeysched[16])))).
		AESEncryptOneRound(archsimd.LoadUint32x4((*[4]uint32)(unsafe.Pointer(&aeskeysched[32])))).
		AsUint64x2().
		GetElem(0)
	return uintptr(hash)
}

func memHash64AES(p unsafe.Pointer, seed uintptr) uintptr {
	var state archsimd.Uint64x2
	state = state.SetElem(0, uint64(seed)).SetElem(1, *(*uint64)(p))

	hash := state.
		AsUint8x16().
		AESEncryptOneRound(archsimd.LoadUint32x4((*[4]uint32)(unsafe.Pointer(&aeskeysched[0])))).
		AESEncryptOneRound(archsimd.LoadUint32x4((*[4]uint32)(unsafe.Pointer(&aeskeysched[16])))).
		AESEncryptOneRound(archsimd.LoadUint32x4((*[4]uint32)(unsafe.Pointer(&aeskeysched[32])))).
		AsUint64x2().
		GetElem(0)
	return uintptr(hash)
}

// TODO: Both strHashAES and memHashAES use aeshashbody that is quite large.
// So there is no point in rewriting them using simd intrinsics, since they won't be inlinable.
// Maybe in future we can do it for better maitanability.
//
//go:noescape
func memHashAES(p unsafe.Pointer, h, s uintptr) uintptr

//go:noescape
func strHashAES(p unsafe.Pointer, h uintptr) uintptr
