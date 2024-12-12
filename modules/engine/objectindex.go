package engine

type ObjectID uint32

// var idToObject gsync.MapOf[uint32, uintptr]

/*
const IDBUCKETSIZE = 65536

type idBucket struct {
	inuse   int32
	objects [IDBUCKETSIZE]uintptr
}

var idToObject [65536]atomic.Pointer[idBucket]

func onDestroyObject(o *Object) {
	o.edges[In].Range(func(o *Object, eb EdgeBitmap) bool {
		panic("Object " + o.Label() + " is pointing to us")
	})
	o.edges[Out].Range(func(o *Object, eb EdgeBitmap) bool {
		panic("Object " + o.Label() + " is pointing to us")
	})
	if o.parent != nil {
		panic("Object " + o.Label() + " has a parent")
	}
	if o.children.Len() > 0 {
		panic("Object " + o.Label() + " has children")
	}

	bucketindex, index := idToIndex(o.id)
	bucket := idToObject[bucketindex].Load()

	atomic.StoreUintptr(&bucket.objects[index], ^uintptr(0))
	inuse := atomic.AddInt32(&bucket.inuse, -1)
	if inuse == 0 {
		idToObject[bucketindex].Store(nil)
	}
	atomic.AddUint64(&NukedObjects, 1)
}

func idToIndex(id ObjectID) (int, int) {
	return int(id / IDBUCKETSIZE), int(id % IDBUCKETSIZE)
}

func onAddObject(newObject *Object) {
	bucketindex, index := idToIndex(newObject.id)
	bucket := idToObject[bucketindex].Load()
	if bucket == nil {
		bucket = &idBucket{}
		if !idToObject[bucketindex].CompareAndSwap(nil, bucket) {
			// Someone else beat us to it
			bucket = idToObject[bucketindex].Load()
		}
	}
	atomic.AddInt32(&bucket.inuse, 1)
	if !atomic.CompareAndSwapUintptr(&bucket.objects[index], 0, uintptr(unsafe.Pointer(newObject))) {
		panic("Parallel universe error")
	}

	runtime.SetFinalizer(newObject, onDestroyObject)
	atomic.AddUint64(&RememberedObjects, 1)
}

func (id ObjectID) Object() *Object {
	bucketindex, index := idToIndex(id)
	bucket := idToObject[bucketindex].Load()
	if bucket == nil {
		panic("No bucket for object mapping")
	}

	objectPtr := atomic.LoadUintptr(&bucket.objects[index])
	if objectPtr == 0 {
		panic("Asked to resolve an Object I've never heard of")
	} else if objectPtr == ^uintptr(0) {
		ui.Error().Msg("Asked to resolve an Object I forgot about")
		objectPtr = 0
		// panic("Asked to resolve an Object I forgot about")
	}
	return (*Object)(unsafe.Pointer(objectPtr))
}

func (id ObjectID) ObjectNoHardfailure() (*Object, bool) {
	bucketindex, index := idToIndex(id)
	bucket := idToObject[bucketindex].Load()
	if bucket == nil {
		return nil, false
	}

	objectPtr := atomic.LoadUintptr(&bucket.objects[index])
	if objectPtr == 0 {
		return nil, false
	} else if objectPtr == ^uintptr(0) {
		return nil, false
	}
	return (*Object)(unsafe.Pointer(objectPtr)), true
}
*/
