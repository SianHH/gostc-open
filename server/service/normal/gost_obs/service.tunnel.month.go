package service

import (
	"server/pkg/utils"
	"server/service/common/cache"
	"time"
)

type TunnelMonthReq struct {
	Code  string `binding:"required" json:"code"`
	Start string `json:"start"`
	End   string `json:"end"`
}

type Item struct {
	Date string `json:"date"`
	In   int64  `json:"in"`
	Out  int64  `json:"out"`
}

func (service *service) TunnelMonth(req TunnelMonthReq) (result []Item) {
	times, ok := utils.DateFormatLayout(time.DateOnly, req.Start, req.End)
	var start, end time.Time
	if ok {
		start = times[0]
		end = times[1]
	} else {
		start = time.Now().AddDate(0, 0, -29)
		end = time.Now()
	}
	_, times2 := utils.DateRangeSplit(start, end)
	for _, date := range times2 {
		summary := cache.GetTunnelObs(date, req.Code)
		result = append(result, Item{
			Date: date,
			In:   summary.InputBytes,
			Out:  summary.OutputBytes,
		})
	}
	return result
}
