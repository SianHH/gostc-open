package global

import (
	"proxy/configs"
	"proxy/pkg/proxy"

	"go.uber.org/zap"
)

var Config *configs.Config
var Logger *zap.Logger
var Proxy *proxy.Proxy
