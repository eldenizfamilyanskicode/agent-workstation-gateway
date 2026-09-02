package executionrun

import "time"

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now()
}

type systemTimerFactory struct{}

func (systemTimerFactory) NewTimer(duration time.Duration) Timer {
	return systemTimer{timer: time.NewTimer(duration)}
}

type systemTimer struct {
	timer *time.Timer
}

func (timer systemTimer) Channel() <-chan time.Time {
	return timer.timer.C
}

func (timer systemTimer) Stop() bool {
	return timer.timer.Stop()
}
