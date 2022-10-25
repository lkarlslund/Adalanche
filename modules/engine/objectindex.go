package engine

import (
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

var RememberedObjects, NukedObjects uint64

// var idToObject gsync.MapOf[uint32, uintptr]

var idToObject []uintptr
var idToObjectLen uint32
var idToObjectLock sync.RWMutex

func onDestroyObject(f *Object) {
	idToObjectLock.Lock()
	atomic.StoreUintptr(&idToObject[f.id], 0)
	atomic.AddUint64(&NukedObjects, 1)
	idToObjectLock.Unlock()
}

func onAddObject(newObject *Object) {
	idToObjectLock.Lock()
	for idToObjectLen <= newObject.id {
		newlen := newObject.id + 4096
		newObjects := make([]uintptr, newlen)

		copy(newObjects, idToObject)
		idToObject = newObjects

		atomic.StoreUint32(&idToObjectLen, newlen)
	}
	idToObject[newObject.id] = uintptr(unsafe.Pointer(newObject))
	atomic.AddUint64(&RememberedObjects, 1)
	runtime.SetFinalizer(newObject, onDestroyObject)
	idToObjectLock.Unlock()
}

func IDtoOBject(id uint32) *Object {
	idToObjectLock.RLock()
	objectPtr := atomic.LoadUintptr(&idToObject[id])
	if objectPtr == 0 {
		panic("Asked to resolve an Object I forgot about")
	}
	idToObjectLock.RUnlock()
	return (*Object)(unsafe.Pointer(objectPtr))
}
