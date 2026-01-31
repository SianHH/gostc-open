package utils

import "time"

func Timeout(duration time.Duration, f func(done func()) error) (err error) {
	wait := make(chan struct{}, 1)
	var done = func() {
		wait <- struct{}{}
	}
	ticker := time.NewTicker(duration)
	defer ticker.Stop()
	go func() {
		err = f(done)
	}()
	select {
	case <-wait:
		return err
	case <-ticker.C:
		return nil
	}
}
