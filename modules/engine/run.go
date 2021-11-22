package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
)

// Loads, processes and merges everything. It's magic, just in code
func Run(path string) (*Objects, error) {
	// Load everything
	loadbar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("Loading data"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("tidbits"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	objs, err := Load(path, func(cur, max int) {
		loadbar.ChangeMax(max)
		loadbar.Set(cur)
	})
	if err != nil {
		return nil, err
	}
	loadbar.Finish()

	for i, loaderobjs := range objs {
		// Do preprocessing
		prebar := progressbar.NewOptions(int(len(loaderobjs.Slice())),
			progressbar.OptionSetDescription(fmt.Sprintf("Preprocessing %v ...", loaders[i].Name())),
			progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
			progressbar.OptionThrottle(time.Second*1),
		)

		Process(loaderobjs, func(cur, max int) {
			prebar.ChangeMax(max)
			prebar.Set(cur)
		}, LoaderID(i), BeforeMergeLow)

		Process(loaderobjs, func(cur, max int) {
			prebar.ChangeMax(max)
			prebar.Set(cur)
		}, LoaderID(i), BeforeMerge)

		Process(loaderobjs, func(cur, max int) {
			prebar.ChangeMax(max)
			prebar.Set(cur)
		}, LoaderID(i), BeforeMergeHigh)

		prebar.Finish()
	}

	// Analyze Pwn relationships
	for i, loaderobjs := range objs {
		pwnbar := progressbar.NewOptions(int(len(loaderobjs.Slice())),
			progressbar.OptionSetDescription(fmt.Sprintf("Analyzing %v ...", loaders[i].Name())),
			progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
			progressbar.OptionThrottle(time.Second*1),
		)

		Analyze(loaderobjs, func(cur, max int) {
			if max >= 0 {
				pwnbar.ChangeMax(max)
			}
			if cur > 0 {
				pwnbar.Set(cur)
			} else {
				pwnbar.Add(-cur)
			}
		}, LoaderID(i))
		pwnbar.Finish()
	}

	// Merging
	ao, err := Merge(objs)

	// Do global post-processing
	postbar := progressbar.NewOptions(int(len(ao.Slice())),
		progressbar.OptionSetDescription("Postprocessing merged objects ..."),
		progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	for i := range objs {
		Process(ao, func(cur, max int) {
			postbar.ChangeMax(max)
			postbar.Set(cur)
		}, LoaderID(i), AfterMergeLow)

		Process(ao, func(cur, max int) {
			postbar.ChangeMax(max)
			postbar.Set(cur)
		}, LoaderID(i), AfterMerge)

		Process(ao, func(cur, max int) {
			postbar.ChangeMax(max)
			postbar.Set(cur)
		}, LoaderID(i), AfterMergeHigh)
	}
	postbar.Finish()

	var statarray []string
	for stat, count := range ao.Statistics() {
		if stat == 0 {
			continue
		}
		statarray = append(statarray, fmt.Sprintf("%v: %v", ObjectType(stat).String(), count))
	}
	log.Info().Msg(strings.Join(statarray, ", "))

	// Show debug counters
	var pwnarray []string
	for pwn, count := range PwnPopularity {
		if count == 0 {
			continue
		}
		pwnarray = append(pwnarray, fmt.Sprintf("%v: %v", PwnMethod(pwn).String(), count))
	}
	log.Debug().Msg(strings.Join(pwnarray, ", "))

	return ao, err
}
