package bootstrap

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"proxy/configs"
	"proxy/global"
	"proxy/pkg/middleware"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func verifyCertificateAndKey(cert, key string) error {
	_, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return fmt.Errorf("证书对验证失败: %v", err)
	}
	return nil
}

func InitApi() {
	if global.Config.ApiAddr == "" {
		return
	}

	if global.MODE == "dev" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.Default()
	engine.Use(middleware.Logger(global.Logger, true, func(c *gin.Context) bool {
		return true
	}))

	engine.POST("/domain", Domain)

	svc := &http.Server{
		Addr:    global.Config.ApiAddr,
		Handler: engine,
	}

	var err error
	go func() {
		err = svc.ListenAndServe()
	}()
	time.Sleep(time.Second)
	if err != nil {
		global.Logger.Warn("api server listen on address: "+global.Config.ApiAddr, zap.Error(err))
		Release()
		os.Exit(1)
	}
	global.Logger.Info("api server listen on address: " + global.Config.ApiAddr)
}

type DomainReq struct {
	Domain     string `json:"domain"`
	Target     string `json:"target"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	ForceHttps int    `json:"forceHttps"`
}

func Domain(c *gin.Context) {
	var req DomainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.String(500, err.Error())
		return
	}
	if req.Domain == "" {
		return
	}

	var certFile = fmt.Sprintf("%s/data/certs/%s.pem", global.BASE_PATH, req.Domain)
	var keyFile = fmt.Sprintf("%s/data/certs/%s.key", global.BASE_PATH, req.Domain)
	if req.Cert != "" && req.Key != "" {
		if err := verifyCertificateAndKey(req.Cert, req.Key); err != nil {
			global.Logger.Warn("cert valid fail", zap.Error(err))
			return
		}
		_ = os.WriteFile(certFile, []byte(req.Cert), 0644)
		_ = os.WriteFile(keyFile, []byte(req.Key), 0644)
	} else {
		certFile = ""
		keyFile = ""
	}

	if global.Config.Domains == nil {
		global.Config.Domains = make(map[string]configs.DomainConfig)
	}
	global.Config.Domains[req.Domain] = configs.DomainConfig{
		Target:       req.Target,
		Cert:         certFile,
		Key:          keyFile,
		ForceHttps:   req.ForceHttps == 1,
		DisableHttps: false,
	}
	marshal, err := yaml.Marshal(global.Config)
	if err != nil {
		global.Logger.Error("yaml.Marshal config fail", zap.String("config path", global.BASE_PATH+"/data/config.yaml"), zap.Error(err))
		return
	}
	if err := os.WriteFile(global.BASE_PATH+"/data/config.yaml", marshal, 0644); err != nil {
		global.Logger.Error("save config fail", zap.String("config path", global.BASE_PATH+"/data/config.yaml"), zap.Error(err))
	}
}
