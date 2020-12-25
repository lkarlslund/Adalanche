// +build pprof

package main

import (
	"net/http"
	_ "net/http/pprof" // register debug routes on default mux

	"github.com/rs/zerolog/log"
)

func init() {
	go func() {
		err := http.ListenAndServe("localhost:6060", nil)
		if err != nil {
			log.Error().Msgf("Profiling listener failed: %v", err)
		}
	}()
}
