package bootstrap

import (
	"os"
	"path/filepath"
	"proxy/configs"
	"proxy/global"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func InitConfig() {
	configFilePath := global.BASE_PATH + "/data/config.yaml"
	_ = os.MkdirAll(filepath.Dir(configFilePath), 0666)

	global.Logger.Info("init config", zap.String("path", configFilePath))
	stat, err := os.Stat(configFilePath)
	if err != nil {
		global.Logger.Warn("stat config fail", zap.String("path", configFilePath), zap.Error(err))
		if err = writeConfigFile(configFilePath); err != nil {
			global.Logger.Fatal("write config fail", zap.String("path", configFilePath), zap.Error(err))
		} else {
			global.Logger.Info("init config finish", zap.String("path", configFilePath))
		}
		return
	}
	if stat.IsDir() {
		global.Logger.Fatal("config is dir", zap.String("path", configFilePath), zap.String("path", configFilePath))
	}
	configFileBytes, err := os.ReadFile(configFilePath)
	if err != nil {
		global.Logger.Fatal("config read fail", zap.String("path", configFilePath), zap.Error(err))
	}
	if err := yaml.Unmarshal(configFileBytes, &global.Config); err != nil {
		global.Logger.Fatal("config serialize fail", zap.String("path", configFilePath), zap.Error(err))
	}
}

func writeConfigFile(path string) error {
	global.Config = &configs.Config{
		HTTPAddr:  "0.0.0.0:80",
		HTTPSAddr: "0.0.0.0:443",
		Certs:     global.BASE_PATH + "/data/certs",
		ApiAddr:   "0.0.0.0:8080",
		Default: configs.DomainConfig{
			Target: "http://127.0.0.1:8080",
			Cert:   global.BASE_PATH + "/data/certs/default.pem",
			Key:    global.BASE_PATH + "/data/certs/default.key",
		},
		Domains: map[string]configs.DomainConfig{
			"www.example.com": {
				Target: "http://127.0.0.1:8080",
				Cert:   "",
				Key:    "",
			},
		},
	}
	marshal, _ := yaml.Marshal(global.Config)
	return os.WriteFile(path, marshal, 0666)
}
