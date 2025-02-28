package gost_client_forward

import (
	"github.com/gin-gonic/gin"
	"server/pkg/bean"
	"server/service/admin/gost_client_forward"
)

var svr = service.Service

func Create(c *gin.Context) {
	var req service.CreateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bean.Response.Param(c, err)
		return
	}
	if err := svr.Create(req); err != nil {
		bean.Response.Fail(c, err.Error())
		return
	}
	bean.Response.Ok(c)
}

func Config(c *gin.Context) {
	var req service.ConfigReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bean.Response.Param(c, err)
		return
	}
	if err := svr.Config(req); err != nil {
		bean.Response.Fail(c, err.Error())
		return
	}
	bean.Response.Ok(c)
}

func Delete(c *gin.Context) {
	var req service.DeleteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bean.Response.Param(c, err)
		return
	}
	if err := svr.Delete(req); err != nil {
		bean.Response.Fail(c, err.Error())
		return
	}
	bean.Response.Ok(c)
}

func Page(c *gin.Context) {
	var req service.PageReq
	if err := c.ShouldBindJSON(&req); err != nil {
		bean.Response.Param(c, err)
		return
	}
	list, total := svr.Page(req)
	bean.Response.OkData(c, bean.NewPage(list, total))
}
