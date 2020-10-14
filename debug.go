// +build pprof
package main

import (
	"log"
	"net/http"
	_ "net/http/pprof" // register debug routes on default mux
)

func init() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}
