package global

import (
	"fmt"
	"os"
	"path/filepath"
)

func Init() {
	// 模式
	if FLAG_DEV {
		MODE = "dev"
	} else {
		MODE = "prod"
	}
	if BASE_PATH != "" {
		BASE_PATH = filepath.Dir(BASE_PATH)
	} else {
		BASE_PATH, _ = os.Executable()
	}
	BASE_PATH = filepath.Dir(BASE_PATH)
	LOGGER_FILE_PATH = BASE_PATH + "/data/gostc.log"

	fmt.Printf(`
BASE_CONFIG:
MODE=%s
VERSION=%s
BASE_PATH: %s
LOGGER_FILE_PATH=%s
LOGGER_LEVEL=%s
========================================
`, MODE, VERSION, BASE_PATH, LOGGER_FILE_PATH, LOGGER_LEVEL)
}

var (
	VERSION   = "v2.0.10-fix.2" // 版本
	BASE_PATH = ""              // 基础目录
	/*
		prod:生产模式，程序运行根路径和程序的所在目录保持一致
		dev:开发模式，程序运行根路径和pwd输出的目录保持一致
	*/
	FLAG_DEV         = true
	MODE             = "dev"
	LOGGER_FILE_PATH = ""     // 日志文件路径
	LOGGER_LEVEL     = "info" // 日志等级
	MaxNodeNum       = 2      // 最大节点数量
	LICENCE          string
	LICENCE_URL      string
	LICENCE_FILE     string
	LICENCE_PROXY    string
)
