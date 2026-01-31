package utils

import (
	"time"
)

// GetVerErr 处理错误信息

func FormatTimes(layout string, times ...string) (list []time.Time, ok bool) {
	for _, item := range times {
		t, err := time.ParseInLocation(layout, item, time.Local)
		if err != nil {
			return nil, false
		}
		list = append(list, t)
	}
	return list, true
}
