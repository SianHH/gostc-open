package bootstrap

import (
	"os"
	"proxy/configs"
	"proxy/global"
	"proxy/service"
	"time"

	"github.com/radovskyb/watcher"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func InitWatcher() {
	path := global.BASE_PATH
	configFilePath := path + "/data/config.yaml"

	w := watcher.New()
	w.SetMaxEvents(1)
	w.FilterOps(watcher.Write)

	delay := 3 * time.Second // 延迟更新时间，避免反复更新导致配置出现遗漏
	var delayTimer *time.Timer

	go func() {
		for {
			select {
			case <-w.Event:
				global.Logger.Info("watch config reload", zap.String("path", configFilePath))
				if delayTimer != nil {
					delayTimer.Stop()
				}
				delayTimer = time.AfterFunc(delay, func() {
					configFileBytes, err := os.ReadFile(configFilePath)
					if err != nil {
						global.Logger.Error("read new config fail", zap.String("path", configFilePath), zap.Error(err))
						return
					}
					var newConfig = configs.Config{}
					if err := yaml.Unmarshal(configFileBytes, &newConfig); err != nil {
						global.Logger.Error("unmarshal new config fail", zap.String("path", configFilePath), zap.Error(err))
						return
					}

					global.Logger.Info("reload onebox-agent config success")
					global.Config = &newConfig

					service.UpdateHttpProxy(*global.Config)
				})
			case _ = <-w.Error:
				return
			case <-w.Closed:
				return
			}
		}
	}()
	if err := w.Add(configFilePath); err != nil {
		global.Logger.Warn("watcher config file failed", zap.Error(err))
		return
	}
	if err := w.Start(time.Second); err != nil {
		global.Logger.Warn("watcher config file failed", zap.Error(err))
		return
	}
	global.Logger.Info("watcher config file success")
	releaseFunc = append(releaseFunc, func() {
		w.Close()
	})
}
