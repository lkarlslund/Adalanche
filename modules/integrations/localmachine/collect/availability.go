package collect

import "time"

var (
	amonthago = time.Now().Add(-30 * 24 * time.Hour)
	aweekago  = time.Now().Add(-7 * 24 * time.Hour)
	adayago   = time.Now().Add(-1 * 24 * time.Hour)
)

func registertimes(start, stop time.Time, month, week, day *time.Duration) {
	if start.Before(amonthago) {
		start = amonthago
	}
	if (start.Equal(amonthago) || start.After(amonthago)) && start.Before(stop) {
		*month += stop.Sub(start)
	}

	if start.Before(aweekago) {
		start = aweekago
	}
	if (start.Equal(aweekago) || start.After(aweekago)) && start.Before(stop) {
		*week += stop.Sub(start)
	}

	if start.Before(adayago) {
		start = adayago
	}
	if (start.Equal(aweekago) || start.After(aweekago)) && start.Before(stop) {
		*day += stop.Sub(start)
	}
}
