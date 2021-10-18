package engine

// Loads, processes and merges everything. It's magic, just in code
func Run(path string) (*Objects, error) {
	objs, err := Load(path)
	if err != nil {
		return nil, err
	}
	return ProcessAndMerge(objs)
}
