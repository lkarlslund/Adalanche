package collect

import "unsafe"

// Assert the x64 ABI even when tests are only cross-compiled.
var (
	_ [88]byte = [unsafe.Sizeof(logonDataPrefix{})]byte{}
	_ [4]byte  = [unsafe.Offsetof(logonDataPrefix{}.ID)]byte{}
	_ [16]byte = [unsafe.Offsetof(logonDataPrefix{}.User)]byte{}
	_ [32]byte = [unsafe.Offsetof(logonDataPrefix{}.Domain)]byte{}
	_ [48]byte = [unsafe.Offsetof(logonDataPrefix{}.Authentication)]byte{}
	_ [64]byte = [unsafe.Offsetof(logonDataPrefix{}.Type)]byte{}
	_ [68]byte = [unsafe.Offsetof(logonDataPrefix{}.Session)]byte{}
	_ [72]byte = [unsafe.Offsetof(logonDataPrefix{}.SID)]byte{}
	_ [80]byte = [unsafe.Offsetof(logonDataPrefix{}.Time)]byte{}
)
