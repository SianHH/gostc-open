package service

import (
	"errors"
	"gostc-sub/internal/common"
	service2 "gostc-sub/internal/service"
	"gostc-sub/pkg/utils"
	"gostc-sub/webui/backend/global"
	"gostc-sub/webui/backend/model"
	"strconv"
)

type UpdateReq struct {
	Name      string `binding:"required" json:"name"`
	Address   string `binding:"required" json:"address"`
	Port      string `binding:"required" json:"port"`
	Tls       int    `binding:"required" json:"tls"`
	Key       string `binding:"required" json:"key"`
	AutoStart int    `json:"autoStart"`
}

func (*service) Update(req UpdateReq) error {
	if !utils.ValidatePort(req.Port) {
		return errors.New("本地端口格式错误")
	}
	port, err := strconv.Atoi(req.Port)
	if err != nil {
		return errors.New("端口格式错误")
	}
	if utils.IsUse(port) {
		return errors.New("本地端口已被占用")
	}
	if common.State.Get(req.Key) {
		return errors.New("P2P隧道正在运行中，请停止运行后修改")
	}
	if err := global.P2PFS.Update(req.Key, model.P2P{
		Key:       req.Key,
		Name:      req.Name,
		Port:      req.Port,
		Address:   req.Address,
		Tls:       req.Tls,
		AutoStart: req.AutoStart,
	}); err != nil {
		return err
	}
	p2p := service2.NewP2P(common.GenerateHttpUrl(req.Tls == 1, req.Address), req.Key, req.Port)
	global.P2PMap.Store(req.Key, p2p)
	return nil
}
