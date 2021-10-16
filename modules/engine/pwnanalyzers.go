package engine

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

var pwnAnalyzers []PwnAnalyzer

func AddAnalyzers(pa ...PwnAnalyzer) {
	pwnAnalyzers = append(pwnAnalyzers, pa...)
}

func Analyze(ao *Objects, cb ProgressCallbackFunc) {
	objectslice := ao.Slice()
	max := len(objectslice) * len(pwnAnalyzers)
	div := max / 1000
	cb(0, max)

	timings := make([]time.Time, len(pwnAnalyzers))

	SetThreadsafe(true)
	ao.SetThreadsafe(true)

	starttime := time.Now()
	var wait sync.WaitGroup

	for i, an := range pwnAnalyzers {
		wait.Add(1)
		go func(li int, lan PwnAnalyzer) {
			cur := 0
			for _, o := range objectslice {
				lan.ObjectAnalyzer(o, ao)
				cur++
				if cur%div == 0 {
					cb(-1000, -1)
				}
			}
			timings[li] = time.Now()
			cb(-cur%div, -1) // Add the final items to progressbar
			wait.Done()
		}(i, an)
	}
	wait.Wait()
	cb(max, max)
	endtime := time.Now()

	SetThreadsafe(false)
	ao.SetThreadsafe(false)

	for i, _ := range pwnAnalyzers {
		log.Info().Msgf("Elapsed %vms for analysis %v", timings[i].Sub(starttime).Milliseconds(), pwnAnalyzers[i].Description)
	}
	log.Info().Msgf("Total elapsed %vms for analysis", endtime.Sub(starttime).Milliseconds())
}

type ProgressCallbackFunc func(progress int, totalprogress int)

type PreProcessorFunc func(ao *Objects)

type ppfInfo struct {
	description string
	ppf         PreProcessorFunc
	post        bool
}

var preProcessors []ppfInfo

func AddPreprocessor(ppf PreProcessorFunc, description string) {
	preProcessors = append(preProcessors, ppfInfo{
		description: description,
		ppf:         ppf,
	})
}

func AddPostprocessor(ppf PreProcessorFunc, description string) {
	preProcessors = append(preProcessors, ppfInfo{
		description: description,
		ppf:         ppf,
		post:        true,
	})
}

func Preprocess(ao *Objects, cb ProgressCallbackFunc) {
	for _, ppf := range preProcessors {
		if !ppf.post {
			log.Info().Msgf("Preprocessing %v ...", ppf.description)
			ppf.ppf(ao)
		}
	}
}

func Postprocess(ao *Objects, cb ProgressCallbackFunc) {
	for _, ppf := range preProcessors {
		if ppf.post {
			log.Info().Msgf("Postprocessing %v ...", ppf.description)
			ppf.ppf(ao)
		}
	}
}
