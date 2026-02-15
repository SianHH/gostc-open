package service

import (
	"proxy/configs"
	"proxy/global"
	"proxy/pkg/proxy"
	"sync"
)

var httpProxyServiceLock = &sync.Mutex{}

func UpdateHttpProxy(c configs.Config) {
	httpProxyServiceLock.Lock()
	defer httpProxyServiceLock.Unlock()
	var proxyRouteList []proxy.LoadRouteConfig
	var certs []proxy.LoadCertConfig
	for host, r := range c.Domains {
		proxyRouteList = append(proxyRouteList, proxy.LoadRouteConfig{
			Host:     host,
			Target:   r.Target,
			Rewrite:  true,
			Sni:      "",
			Origin:   "",
			AutoTLS:  r.ForceHttps,
			AutoCert: global.Config.AutoSetCert,
		})
		certs = append(certs, proxy.LoadCertConfig{
			Host:     host,
			CertFile: r.Cert,
			KeyFile:  r.Key,
		})
	}
	global.Proxy.LoadRoutes(proxyRouteList)
	global.Proxy.LoadCerts(certs)
}
