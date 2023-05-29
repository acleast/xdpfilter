package remove

import (
//   "fmt"

  "github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Removes an rules from the blacklist",
		// Run: func(cmd *cobra.Command, args []string) {
		// 	number, _ := cmd.Flags().GetString("number")
		// 	m, err := blacklist.NewMap()
		// 	if err != nil {
		// 		log.Fatal(err)
		// 	}
		// 	// IP range is specified in CIDR notation
		// 	if strings.Contains(ip, "/") {
		// 		addrs, err := iprange.FromCIDR(ip)
		// 		if err != nil {
		// 			logger.Fatal(err)
		// 		}
		// 		for _, addr := range addrs {
		// 			if m.Remove(net.ParseIP(addr)); err != nil {
		// 				logger.Warnf("fail to remove %s IP address from the blacklist", addr)
		// 				continue
		// 			}
		// 		}
		// 		logger.Infof("%d addresses removed from the blacklist", len(addrs))
		// 		return
		// 	}
		// 	if m.Remove(net.ParseIP(ip)); err != nil {
		// 		logger.Error(err)
		// 		return
		// 	}
		// 	logger.Infof("%s address removed from the blacklist", ip)
		// },
	}
	return cmd
}