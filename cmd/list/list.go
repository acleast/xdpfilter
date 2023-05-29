package list

import (
  "fmt"
  "github.com/spf13/cobra"
  "xdpfilter/cmd/add"
  "os"
  "encoding/gob"
  "log"
  "bytes"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show all rules in the blacklist",
		Run: func(cmd *cobra.Command, args []string) {
			var rules []add.Rule
			data, err := os.ReadFile("../../pkg/xdp/obj/rules")
			if err != nil {
				log.Fatal(err)
			}
			dec := gob.NewDecoder(bytes.NewReader(data))
			err = dec.Decode(rules)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(rules)
		},
	}
	return cmd
}
