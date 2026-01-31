package program

import (
	"proxy/bootstrap"
	"time"

	"github.com/kardianos/service"
)

var SvcCfg = &service.Config{
	Name:        "gostc-proxy",
	DisplayName: "GOSTC-PROXY",
	Description: "GOSTC的代理网关，用于扩展自定义域名功能",
	Option:      make(service.KeyValue),
}

var Program = &program{
	stopChan: make(chan struct{}),
}

type program struct {
	stopChan chan struct{}
}

func (p *program) run() {
	bootstrap.InitLogger()
	bootstrap.InitConfig()
	bootstrap.InitServer()
	go bootstrap.InitWatcher()
	bootstrap.InitApi()

	<-p.stopChan
}

func (p *program) Run() error {
	p.run()
	return nil
}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}
func (p *program) Stop(s service.Service) error {
	p.stopChan <- struct{}{}
	bootstrap.Release()
	time.Sleep(time.Second)
	return nil
}
