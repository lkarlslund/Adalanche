package ui

import (
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gookit/color"
	"github.com/pterm/pterm"
)

type progressBar struct {
	title               string
	titleStyle          *pterm.Style
	barStyle            *pterm.Style
	current, total      int64
	roundingfactor      time.Duration
	started, lastupdate time.Time
	mutex               sync.Mutex
	barCharacter        string
	lastCharacter       string
	barFiller           string

	writer io.Writer
}

func ProgressBar(title string, max int) progressBar {
	if max == 0 {
		max = 1 // avoid division by zero in pterm
	}
	pb := progressBar{
		title: title,

		total:          int64(max),
		roundingfactor: time.Second,
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
	return pb
}

func (pb *progressBar) ChangeMax(newmax int) {
	if newmax == 0 {
		Fatal().Msg("Cannot set max to 0")
	}
	pb.total = int64(newmax)
}

func (pb *progressBar) GetMax() int {
	return int(pb.total)
}

func (pb *progressBar) Start() {
	pb.started = time.Now()
}

func (pb *progressBar) Add(i int) {
	atomic.AddInt64(&pb.current, int64(i))
	pb.update()
}

func (pb *progressBar) Set(i int) {
	atomic.StoreInt64(&pb.current, int64(i))
	pb.update()
}

func (pb *progressBar) Finish() {
	// Some cleanup?
}

func (pb *progressBar) update() {
	if time.Since(pb.lastupdate) < 1*time.Second {
		return
	}

	outputMutex.Lock()

	clearneeded = true
	pb.lastupdate = time.Now()

	var before string
	var after string
	var width int

	width = pterm.GetTerminalWidth()

	currentPercentage := 0
	if pb.total > 0 {
		currentPercentage = int((pb.current * 100) / pb.total)
	}

	if currentPercentage > 100 {
		currentPercentage = 100
	}

	decoratorCount := pterm.Gray("[") + pterm.LightWhite(pb.current) + pterm.Gray("/") + pterm.LightWhite(pb.total) + pterm.Gray("]")

	decoratorCurrentPercentage := color.RGB(pterm.NewRGB(255, 0, 0).Fade(0, float32(pb.total), float32(pb.current), pterm.NewRGB(0, 255, 0)).GetValues()).
		Sprint(strconv.Itoa(currentPercentage) + "%")

	decoratorTitle := pb.titleStyle.Sprint(pb.title)

	before += decoratorTitle + " "
	before += decoratorCount + " "

	after += " "

	after += decoratorCurrentPercentage + " "
	after += "| " + time.Since(pb.started).Round(pb.roundingfactor).String()

	barMaxLength := width - len(pterm.RemoveColorFromString(before)) - len(pterm.RemoveColorFromString(after)) - 1

	barCurrentLength := (currentPercentage * barMaxLength) / 100

	var barFiller string
	if barMaxLength-barCurrentLength > 0 {
		barFiller = strings.Repeat(pb.barFiller, barMaxLength-barCurrentLength)
	}

	var bar string
	if pb.total > 0 {
		bar = pb.barStyle.Sprint(strings.Repeat(pb.barCharacter, barCurrentLength)+pb.lastCharacter) + barFiller
	} else {
		bar = ""
	}

	pterm.Fprinto(pb.writer, before+bar+after)

	outputMutex.Unlock()
}
