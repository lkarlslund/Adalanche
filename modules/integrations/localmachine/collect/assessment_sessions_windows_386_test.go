package collect

import "unsafe"

// Assert the x86 ABI even when tests are only cross-compiled.
var (
	_ [56]byte = [unsafe.Sizeof(logonDataPrefix{})]byte{}
	_ [4]byte  = [unsafe.Offsetof(logonDataPrefix{}.ID)]byte{}
	_ [12]byte = [unsafe.Offsetof(logonDataPrefix{}.User)]byte{}
	_ [20]byte = [unsafe.Offsetof(logonDataPrefix{}.Domain)]byte{}
	_ [28]byte = [unsafe.Offsetof(logonDataPrefix{}.Authentication)]byte{}
	_ [36]byte = [unsafe.Offsetof(logonDataPrefix{}.Type)]byte{}
	_ [40]byte = [unsafe.Offsetof(logonDataPrefix{}.Session)]byte{}
	_ [44]byte = [unsafe.Offsetof(logonDataPrefix{}.SID)]byte{}
	_ [48]byte = [unsafe.Offsetof(logonDataPrefix{}.Time)]byte{}
)
