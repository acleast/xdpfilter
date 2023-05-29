package attach

import (
//   "fmt"
  "log"
  "xdpfilter/pkg/xdp"
  "github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Attaches the XDP program on the specified device",
		Run: func(cmd *cobra.Command, args []string) {
			dev, _ := cmd.Flags().GetString("dev")
			hook, err := xdp.NewHook()
			if err != nil {
				log.Fatal(err)
			}
			if err = hook.Attach(dev); err != nil {
				log.Fatal(err)
			}
			log.Println("XDP program successfully attached to %s device", dev)
		},
	}
	return cmd
}