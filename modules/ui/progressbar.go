package ui

import (
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid"
	"github.com/gookit/color"
	"github.com/pterm/pterm"
)

type progressBar struct {
	ID                  uuid.UUID
	Title               string
	titleStyle          *pterm.Style
	barStyle            *pterm.Style
	Current, Total      int64   // Absolute done and total
	Percent             float32 // Percentage done
	RoundingFactor      time.Duration
	Started, Lastupdate time.Time
	mutex               sync.Mutex
	barCharacter        string
	lastCharacter       string
	barFiller           string

	lastReport int64
	Done       bool

	writer io.Writer
}

var (
	pbLock       sync.Mutex
	progressbars = map[*progressBar]struct{}{}
)

func GetProgressBars() []*progressBar {
	pbLock.Lock()
	pbs := make([]*progressBar, len(progressbars))
	var i int
	for pb, _ := range progressbars {

		if pb.Done && pb.lastReport == pb.Current {
			delete(progressbars, pb)
			continue
		}
		pb.lastReport = pb.Current

		pbs[i] = pb
		i++
	}

	pbLock.Unlock()
	return pbs[:i]
}

func ProgressBar(title string, max int) *progressBar {
	if max == 0 {
		max = 1 // avoid division by zero in pterm
	}

	id, _ := uuid.NewV7()
	pb := progressBar{
		ID:    id,
		Title: title,

		Total:          int64(max),
		RoundingFactor: time.Second,
		barCharacter:   "█",
		lastCharacter:  "█",
		barFiller:      " ",
	}
	if pb.titleStyle == nil {
		pb.titleStyle = pterm.NewStyle()
	}
	if pb.barStyle == nil {
		pb.barStyle = pterm.NewStyle()
	}

	pb.Start()

	// Save it
	pbLock.Lock()
	progressbars[&pb] = struct{}{}
	pbLock.Unlock()

	return &pb
}

func (pb *progressBar) ChangeMax(newmax int) {
	if newmax == 0 {
		Fatal().Msg("Cannot set max to 0")
	}
	pb.Total = int64(newmax)
}

func (pb *progressBar) GetMax() int {
	return int(pb.Total)
}

func (pb *progressBar) Start() {
	pb.Started = time.Now()
}

func (pb *progressBar) Add(i int) {
	atomic.AddInt64(&pb.Current, int64(i))
	pb.update()
}

func (pb *progressBar) Set(i int) {
	atomic.StoreInt64(&pb.Current, int64(i))
	pb.update()
}

func (pb *progressBar) Finish() {
	// Save it
	pbLock.Lock()
	delete(progressbars, pb)
	pbLock.Unlock()

	pb.Done = true
}

func (pb *progressBar) update() {
	if time.Since(pb.Lastupdate) < 1*time.Second {
		return
	}

	outputMutex.Lock()

	clearneeded = true
	pb.Lastupdate = time.Now()

	var before string
	var after string

	width := pterm.GetTerminalWidth()

	var currentPercentage float32
	if pb.Total > 0 {
		currentPercentage = float32(pb.Current) * 100 / float32(pb.Total)
	}

	if currentPercentage > 100 {
		currentPercentage = 100
	}

	pb.Percent = currentPercentage

	decoratorCount := pterm.Gray("[") + pterm.LightWhite(pb.Current) + pterm.Gray("/") + pterm.LightWhite(pb.Total) + pterm.Gray("]")

	decoratorCurrentPercentage := color.RGB(pterm.NewRGB(255, 0, 0).Fade(0, float32(pb.Total), float32(pb.Current), pterm.NewRGB(0, 255, 0)).GetValues()).
		Sprint(fmt.Sprintf("%.2f%%", currentPercentage))

	decoratorTitle := pb.titleStyle.Sprint(pb.Title)

	before += decoratorTitle + " "
	before += decoratorCount + " "

	after += " "

	after += decoratorCurrentPercentage + " "
	after += "| " + time.Since(pb.Started).Round(pb.RoundingFactor).String()

	barMaxLength := width - len(pterm.RemoveColorFromString(before)) - len(pterm.RemoveColorFromString(after)) - 1

	barCurrentLength := int(math.Round(float64(currentPercentage * float32(barMaxLength) / 100)))

	var barFiller string
	if barMaxLength-barCurrentLength > 0 {
		barFiller = strings.Repeat(pb.barFiller, barMaxLength-barCurrentLength)
	}

	var bar string
	if pb.Total > 0 && barCurrentLength > 0 {
		bar = pb.barStyle.Sprint(strings.Repeat(pb.barCharacter, barCurrentLength)+pb.lastCharacter) + barFiller
	} else {
		bar = ""
	}

	pterm.Fprinto(pb.writer, before+bar+after)

	outputMutex.Unlock()
}
