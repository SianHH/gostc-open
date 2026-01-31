package cmd

import (
	"fmt"
	"os"
	"proxy/cmd/program"
	"proxy/global"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"
)

// [SOURCE] https://patorjk.com/software/taag/#p=display&h=0&v=0&f=ANSI%20Shadow&t=GOSTC
func init() {
	fmt.Println(`
 ██████╗  ██████╗ ███████╗████████╗ ██████╗      ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
██╔════╝ ██╔═══██╗██╔════╝╚══██╔══╝██╔════╝      ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
██║  ███╗██║   ██║███████╗   ██║   ██║     █████╗██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ 
██║   ██║██║   ██║╚════██║   ██║   ██║     ╚════╝██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  
╚██████╔╝╚██████╔╝███████║   ██║   ╚██████╗      ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   
 ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
`)
}

func init() {
	RootCmd.AddCommand(&VersionCmd)
	RootCmd.AddCommand(&ServiceCmd)
	for _, cmd := range []*cobra.Command{
		&RootCmd,
		&VersionCmd,
		&ServiceCmd,
	} {
		cmd.Flags().StringVarP(&global.BASE_PATH, "path", "p", "", "app run dir")
		cmd.Flags().StringVarP(&global.LOGGER_LEVEL, "log-level", "", "warn", "log level debug|info|warn|error|fatal")
		cmd.Flags().BoolVarP(&global.FLAG_DEV, "dev", "d", false, "app run dev")
	}
}

var RootCmd = cobra.Command{
	Use: "",
	Run: func(cmd *cobra.Command, args []string) {
		global.Init()

		program.SvcCfg.Arguments = append(program.SvcCfg.Arguments, args...)
		svr, err := service.New(program.Program, program.SvcCfg)
		if err != nil {
			fmt.Println("build service fail", err)
			os.Exit(1)
		}

		if err := svr.Run(); err != nil {
			fmt.Println("server run fail", err)
			os.Exit(1)
		}
	},
}
