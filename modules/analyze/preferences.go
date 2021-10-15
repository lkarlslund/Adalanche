package analyze

import (
	"encoding/json"
	"io/ioutil"
	"sync"
)

type Prefs struct {
	data map[string]interface{}
}

var prefmutex sync.Mutex

func (p *Prefs) Load() error {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	p.data = make(map[string]interface{})

	rawprefs, err := ioutil.ReadFile("preferences.json")
	if err != nil {
		return err
	}
	err = json.Unmarshal(rawprefs, &p.data)
	return err
}

func (p *Prefs) Save() error {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	rawprefs, err := json.Marshal(p.data)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("preferences.json", rawprefs, 0600)
	return err
}

func (p *Prefs) Set(key string, val interface{}) {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	p.data[key] = val
}

func (p *Prefs) Get(key string) interface{} {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	return p.data[key]
}
