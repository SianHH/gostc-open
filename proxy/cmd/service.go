package cmd

import (
	"fmt"
	"os"
	"proxy/cmd/program"
	"proxy/global"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

var ServiceCmd = cobra.Command{
	Use: "service",
	Run: func(cmd *cobra.Command, args []string) {
		global.Init()
		if len(args) == 0 {
			fmt.Println(`./gostc-proxy service install/uninstall/start/stop/restart ["--log-level debug -d"]`)
			os.Exit(1)
		}

		var svrArgs []string
		if len(os.Args) > 3 {
			svrArgs = os.Args[3:]
		}
		svrArgs = append([]string{"service", "run"}, svrArgs...)
		program.SvcCfg.Arguments = append(program.SvcCfg.Arguments, svrArgs...)
		svr, err := service.New(program.Program, program.SvcCfg)
		if err != nil {
			fmt.Println("build service fail", err)
			os.Exit(1)
		}
		switch args[0] {
		case "install":
			_ = svr.Stop()
			_ = svr.Uninstall()
			if err := svr.Install(); err != nil {
				fmt.Println("install service fail", err)
				os.Exit(1)
			}
			fmt.Println("install service success")
			return
		case "uninstall":
			_ = svr.Stop()
			if err := svr.Uninstall(); err != nil {
				fmt.Println("uninstall service fail", err)
				os.Exit(1)
			}
			fmt.Println("uninstall service success")
			return
		case "start", "stop", "restart":
			if err := service.Control(svr, args[0]); err != nil {
				fmt.Println(args[0]+" service fail", err)
				os.Exit(1)
			}
			fmt.Println(args[0] + " service success")
			return
		case "run":
			_ = svr.Run()
		default:
			fmt.Println("./gostc-proxy service install/uninstall/start/stop/restart")
			os.Exit(1)
		}
	},
}
