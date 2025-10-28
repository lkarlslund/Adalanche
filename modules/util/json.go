package util

import (
	"encoding/json"
	"os"
)

// Takes a filename and any object and writes its JSON representation to the file, returns an error if it fails.
func WriteJSON(filename string, obj any) (err error) {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "\t")
	err = encoder.Encode(obj)
	return err
}

// Takes a filename and reads the JSON representation of an object into it, returns an error if it fails.
func ReadJSON(filename string, obj any) (err error) {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(obj)
	return err
}
