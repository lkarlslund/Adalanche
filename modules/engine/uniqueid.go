package engine

import "github.com/gofrs/uuid"

var UniqueID = NewAttribute("UniqueID").Flag(Single, Hidden).SetDescription("Internal unique identifier for the object")

type InternalLoader struct {
}

func (il InternalLoader) Init() error {
	return nil
}

func (il InternalLoader) Name() string {
	return "Adalanche Engine"
}

func (il InternalLoader) Load(path string, pb ProgressCallbackFunc) error {
	return ErrUninterested
}

func (il InternalLoader) Close() ([]*IndexedGraph, error) {
	return nil, nil
}

var internalLoader = AddLoader(func() Loader {
	return InternalLoader{}
})

func init() {
	internalLoader.AddProcessor(func(ao *IndexedGraph) {
		ao.Iterate(func(o *Node) bool {
			o.set(UniqueID, NewAttributeValueGUID(uuid.Must(uuid.NewV4())))
			return true
		})
	},
		"Set random UniqueID on all objects",
		AfterMergeFinal)
}
