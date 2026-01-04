package service

import (
	"fmt"
	"gostc-sub/internal/common"
	"gostc-sub/internal/common/system"
	"gostc-sub/pkg/env"
	"io"
	"log"

	frpLog "github.com/SianHH/frp-package/pkg/util/log"
	log2 "github.com/fatedier/golib/log"
	"github.com/lesismal/arpc/codec"
	arpcLog "github.com/lesismal/arpc/log"
	"gopkg.in/yaml.v3"
)

func init() {
	loggerFile := env.GetEnv("GOSTC_CLIENT_LOGGER_FILE", "")
	loggerLevel := env.GetEnv("GOSTC_CLIENT_LOGGER_LEVEL", "")

	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	var arpcLoggerLevel = arpcLog.LevelError
	var frpLoggerLevel = log2.ErrorLevel
	switch loggerLevel {
	case "error":
		arpcLoggerLevel = arpcLog.LevelError
		frpLoggerLevel = log2.ErrorLevel
	case "debug":
		arpcLoggerLevel = arpcLog.LevelDebug
		frpLoggerLevel = log2.DebugLevel
	default:
		arpcLoggerLevel = arpcLog.LevelDebug
		frpLoggerLevel = log2.InfoLevel
	}

	var writers = []io.Writer{common.Logger}
	if loggerFile != "" {
		writer := log2.NewRotateFileWriter(log2.RotateFileConfig{
			FileName: loggerFile,
			MaxDays:  30,
		})
		writer.Init()
		writers = append(writers, writer)
	}
	w := io.MultiWriter(writers...)
	arpcLog.Output = w

	system.EnableCompatibilityMode()
	// ARPC序列化
	codec.SetCodec(&YAMLCodec{})
	// ARPC日志
	arpcLog.SetLevel(arpcLoggerLevel)

	// FRP日志
	frpLog.Logger = frpLog.Logger.WithOptions(log2.WithOutput(w), log2.WithLevel(frpLoggerLevel))
	fmt.Println("VERSION：", common.VERSION)
}

type YAMLCodec struct {
}

func (y *YAMLCodec) Marshal(v interface{}) ([]byte, error) {
	return yaml.Marshal(v)
}

func (y *YAMLCodec) Unmarshal(data []byte, v interface{}) error {
	return yaml.Unmarshal(data, v)
}
