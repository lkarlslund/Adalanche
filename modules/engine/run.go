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
	loadbar := progressbar.NewOptions(0,
		progressbar.OptionSetDescription("Loading data"),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("tidbits"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	loaderobjects, err := Load(path, func(cur, max int) {
		if max > 0 {
			loadbar.ChangeMax(max)
		} else if max < 0 {
			loadbar.ChangeMax(loadbar.GetMax() + (-max))
		}
		if cur > 0 {
			loadbar.Set(cur)
		} else {
			loadbar.Add(-cur)
		}
	})
	if err != nil {
		return nil, err
	}
	loadbar.Finish()

	for _, lobj := range loaderobjects {
		// Do preprocessing
		prebar := progressbar.NewOptions(lobj.Objects.Len(),
			progressbar.OptionSetDescription(fmt.Sprintf("Preprocessing %v ...", lobj.Loader.Name())),
			progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
			progressbar.OptionThrottle(time.Second*1),
		)

		var loaderid LoaderID
		for i, loader := range loaders {
			if loader == lobj.Loader {
				loaderid = LoaderID(i)
				break
			}
		}

		Process(lobj.Objects, func(cur, max int) {
			prebar.ChangeMax(max)
			prebar.Set(cur)
		}, loaderid, BeforeMergeLow)

		Process(lobj.Objects, func(cur, max int) {
			prebar.ChangeMax(max)
			prebar.Set(cur)
		}, loaderid, BeforeMerge)

		Process(lobj.Objects, func(cur, max int) {
			prebar.ChangeMax(max)
			prebar.Set(cur)
		}, loaderid, BeforeMergeHigh)

		prebar.Finish()
	}

	// Analyze Pwn relationships
	for _, lobj := range loaderobjects {
		pwnbar := progressbar.NewOptions(lobj.Objects.Len(),
			progressbar.OptionSetDescription(fmt.Sprintf("Analyzing %v ...", lobj.Loader.Name())),
			progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
			progressbar.OptionOnCompletion(func() { fmt.Println() }),
			progressbar.OptionThrottle(time.Second*1),
		)

		var loaderid LoaderID
		for i, loader := range loaders {
			if loader == lobj.Loader {
				loaderid = LoaderID(i)
				break
			}
		}

		Analyze(lobj.Objects, func(cur, max int) {
			if max >= 0 {
				pwnbar.ChangeMax(max)
			}
			if cur > 0 {
				pwnbar.Set(cur)
			} else {
				pwnbar.Add(-cur)
			}
		}, loaderid)
		pwnbar.Finish()
	}

	// Merging
	objs := make([]*Objects, len(loaderobjects))
	for i, lobj := range loaderobjects {
		objs[i] = lobj.Objects
	}
	ao, err := Merge(objs)

	// Do global post-processing
	postbar := progressbar.NewOptions(ao.Len(),
		progressbar.OptionSetDescription("Postprocessing merged objects ..."),
		progressbar.OptionShowCount(), progressbar.OptionShowIts(), progressbar.OptionSetItsString("objects"),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
		progressbar.OptionThrottle(time.Second*1),
	)

	for i := range loaders {
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
		if count == 0 {
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
