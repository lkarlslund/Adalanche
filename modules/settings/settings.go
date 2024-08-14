package settings

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type prefs struct {
	data map[string]any
}

var loaded prefs

var prefmutex sync.Mutex

func init() {
	Load()
}

func Load() error {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	loaded.data = make(map[string]any)

	rawprefs, err := os.ReadFile("preferences.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	err = json.Unmarshal(rawprefs, &loaded.data)
	return err
}

func Save() error {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	rawprefs, err := json.Marshal(loaded.data)
	if err != nil {
		return err
	}
	err = os.WriteFile("preferences.json", rawprefs, 0600)
	return err
}

func Set(key string, val any) {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	loaded.data[key] = val
}

func Get(key string) any {
	prefmutex.Lock()
	defer prefmutex.Unlock()
	return loaded.data[key]
}

func All() map[string]any {
	return loaded.data
}
