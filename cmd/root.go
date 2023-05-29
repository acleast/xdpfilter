package cmd

import (
	// "errors"
	"github.com/spf13/cobra"
	"xdpfilter/cmd/add"
	"xdpfilter/cmd/list"
	"xdpfilter/cmd/remove"
	"xdpfilter/cmd/attach"
	"xdpfilter/cmd/detach"
	"xdpfilter/cmd/show"
)

var rootCmd = &cobra.Command {
	Use: "xdpfilter",
	Short: "xdpfilter is a packet filter program.",
	Long: "xdpfilter is an ACL software written based on eBPF, which can help you filter packets.",
	// Run: func(cmd *cobra.Command, args []string) {
	//   Error(cmd, args, errors.New("unrecognized command"))
	// },
  }
  
func Execute() {
	rootCmd.Execute()
}

func init() {
	// logger = logrus.New()
	// logger.SetFormatter(&logrus.TextFormatter{
	// 	DisableTimestamp: true,
	// })
	attachCmd := attach.NewCommand()
	attachCmd.Flags().StringP("dev", "d", "eth0", "network device to attach the XDP program")
	detachCmd := detach.NewCommand()
	detachCmd.Flags().StringP("dev", "d", "eth0", "network device to detach the XDP program")
	addCmd := add.NewCommand()
	addCmd.Flags().StringP("dst", "d", "0.0.0.0", "destination IP address to add to the blacklist")
	addCmd.Flags().StringP("src", "s", "0.0.0.0", "source IP address to add to the blacklist")
	addCmd.Flags().StringP("dstport", "t", "0", "destination port to add to the blacklist")
	addCmd.Flags().StringP("srcport", "r", "0", "source port to add to the blacklist")
	addCmd.Flags().StringP("protocol", "p", "0", "protocol type to add to the blacklist")
	rmCmd := remove.NewCommand()
	rmCmd.Flags().StringP("number", "n", "", "the number rule to remove from the blacklist")
	listCmd := list.NewCommand()
	showCmd := show.NewCommand()
	rootCmd.AddCommand(attachCmd)
	rootCmd.AddCommand(detachCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
}