package bootstrap

import (
	"net"
	"proxy/global"
	"proxy/pkg/proxy"
	"proxy/pkg/utils"
	"proxy/service"

	"go.uber.org/zap"
)

func InitServer() {
	httpListen, httpPort, _ := net.SplitHostPort(global.Config.HTTPAddr)
	httpsListen, httpsPort, _ := net.SplitHostPort(global.Config.HTTPSAddr)

	var listen = ""
	if httpListen != "" {
		listen = httpListen
	} else {
		listen = httpsListen
	}

	var err error
	global.Proxy, err = proxy.NewProxy(proxy.ProxyConfig{
		Listen:           listen,
		HttpPort:         utils.StrMustInt(httpPort),
		HttpsPort:        utils.StrMustInt(httpsPort),
		AutoCertCacheDir: global.BASE_PATH + "/data/autocert",
	})
	if err != nil {
		Release()
		global.Logger.Fatal("init proxy error", zap.Error(err))
	}
	if err := global.Proxy.Start(); err != nil {
		Release()
		global.Logger.Fatal("start proxy error", zap.Error(err))
	}
	releaseFunc = append(releaseFunc, func() {
		global.Proxy.Stop()
	})

	service.UpdateHttpProxy(*global.Config)
}
