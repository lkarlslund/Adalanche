package analyze

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"sync"
)

type Prefs struct {
	data map[string]any
}

var prefmutex sync.Mutex

func (p *Prefs) Load() error {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	p.data = make(map[string]any)

	rawprefs, err := ioutil.ReadFile("preferences.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
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

func (p *Prefs) Set(key string, val any) {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	p.data[key] = val
}

func (p *Prefs) Get(key string) any {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	return p.data[key]
}
