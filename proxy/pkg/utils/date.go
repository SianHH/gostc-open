package utils

import "time"

func DateFormatLayout(layout string, times ...string) (times1 []time.Time, ok bool) {
	for _, t := range times {
		location, err := time.ParseInLocation(layout, t, time.Local)
		if err != nil {
			return nil, false
		}
		times1 = append(times1, location)
	}
	return times1, true
}

func DateRangeSplit(start, end time.Time) (times1 []time.Time, times2 []string) {
	var i = 0
	for {
		var date = start.AddDate(0, 0, i)
		times1 = append(times1, date)
		times2 = append(times2, date.Format(time.DateOnly))
		if date.Unix() >= end.Unix() {
			break
		}
		i++
	}
	return times1, times2
}
