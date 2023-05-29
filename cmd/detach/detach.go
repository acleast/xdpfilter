package detach

import (
//   "fmt"
  "github.com/spf13/cobra"
  "xdpfilter/pkg/xdp"
  "log"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detach",
		Short: "Removes the XDP program from the specified device",
		Run: func(cmd *cobra.Command, args []string) {
			dev, _ := cmd.Flags().GetString("dev")
			hook, err := xdp.NewHook()
			if err != nil {
				log.Fatal(err)
			}
			defer hook.Close()
			if err := hook.Remove(dev); err != nil {
				log.Fatal(err)
			}
			log.Println("XDP program successfully unloaded from %s device", dev)
		},
	}
	return cmd
}