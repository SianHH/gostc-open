package utils

import "time"

func Retry(fn func() error, maxRetry int, interval time.Duration) error {
	if maxRetry < 0 {
		maxRetry = 0
	}
	var err error
	for attempt := 0; attempt <= maxRetry; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		if attempt < maxRetry {
			time.Sleep(interval)
		}
	}
	return err
}
