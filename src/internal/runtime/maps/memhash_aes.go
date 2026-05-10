// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 || arm64 || 386

package maps

import (
	"unsafe"
)

const memHashAESImplemented = true

func MemHash(p unsafe.Pointer, h, s uintptr) uintptr {
	if UseAeshash {
		return memHashAES(p, h, s)
	}
	return memHashFallback(p, h, s)
}

func MemHash32(p unsafe.Pointer, h uintptr) uintptr {
	if UseAeshash {
		return memHash32AES(p, h)
	}
	return memHash32Fallback(p, h)
}

func MemHash64(p unsafe.Pointer, h uintptr) uintptr {
	if UseAeshash {
		return memHash64AES(p, h)
	}
	return memHash64Fallback(p, h)
}

func StrHash(p unsafe.Pointer, h uintptr) uintptr {
	if UseAeshash {
		return strHashAES(p, h)
	}
	return strHashFallback(p, h)
}
