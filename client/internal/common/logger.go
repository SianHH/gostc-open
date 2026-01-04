package common

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

var Logger = NewCircularLogger(1000)

type LogEntry struct {
	Timestamp time.Time
	Type      string
	Message   string
}

type CircularLogger struct {
	mu      sync.Mutex
	logs    []LogEntry
	maxSize int
	console bool
}

func (cl *CircularLogger) Write(p []byte) (n int, err error) {
	cl.AddLog("FRP", string(p))
	return len(p), nil
}

func NewCircularLogger(maxSize int) *CircularLogger {
	return &CircularLogger{
		logs:    make([]LogEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (cl *CircularLogger) AddLog(tp, message string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Message:   message,
		Type:      tp,
	}
	
	if strings.HasSuffix(message, "\n") {
		fmt.Print(fmt.Sprintf("[GOSTC LOG] %s", message))
	} else {
		fmt.Println(fmt.Sprintf("[GOSTC LOG] %s", message))
	}

	if len(cl.logs) < cl.maxSize {
		cl.logs = append(cl.logs, entry)
	} else {
		// 移除最早的日志，添加新的日志
		cl.logs = append(cl.logs[1:], entry)
	}
}

func (cl *CircularLogger) GetLogs() []LogEntry {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	logs := make([]LogEntry, len(cl.logs))
	copy(logs, cl.logs)
	return logs
}

func (cl *CircularLogger) ClearLogs() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.logs = make([]LogEntry, 0, cl.maxSize)
}

func (cl *CircularLogger) Console(b bool) {
	cl.console = b
}
