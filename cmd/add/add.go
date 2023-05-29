package add

import (
//   "fmt"
  "github.com/spf13/cobra"
  "log"
  "net"
  "xdpfilter/pkg/blacklist"
  "strconv"
  "strings"
//  "os"
  //"bytes"
  //"encoding/gob"
)

const (
	icmp = 1
	tcp = 6
	udp = 17
)

type Rule struct {
	number     uint64
	src        string
	dst        string
	protocol   string
	sport      string
	dport      string
	pkts       uint64
}

func fromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); nextIP(ip) {
		addrs = append(addrs, ip.String())
	}
	// remove network/broadcast addresses
	return addrs[1 : len(addrs)-1], nil
}

func nextIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Append a new packet loss rule to the blacklist",
		Run: func(cmd *cobra.Command, args []string) {
			dip, _ := cmd.Flags().GetString("dst")
			sip, _ := cmd.Flags().GetString("src")
			prot, _ := cmd.Flags().GetString("protocol")
			dport, _ := cmd.Flags().GetString("dstport")
			sport, _ := cmd.Flags().GetString("srcport")
			m, err := blacklist.NewMap()
			if err != nil {
				log.Fatal(err)
			}

			number := m.GetNumber()
			// IP range is specified in CIDR notation
			if strings.Contains(dip, "/") {
				daddrs, err := fromCIDR(dip)
				if err != nil {
					log.Fatal(err)
				}
				for _, daddr := range daddrs {
					if err = m.DipAdd(net.ParseIP(daddr), number); err != nil {
						log.Fatal(err)
					}
				}
			}else if err = m.DipAdd(net.ParseIP(dip), number); err != nil {
				log.Fatal(err)
			}
			if strings.Contains(sip, "/") {
				saddrs, err := fromCIDR(sip)
				if err != nil {
					log.Fatal(err)
				}
				for _, saddr := range saddrs {
					if err = m.SipAdd(net.ParseIP(saddr), number); err != nil {
						log.Fatal(err)
					}
				}
			}else if err = m.SipAdd(net.ParseIP(sip), number); err != nil {
				log.Fatal(err)
			}
			if prot == "icmp" {
				if err = m.ProAdd(icmp, number); err != nil {
					log.Fatal(err)
				}
			}
			if prot == "tcp" {
				if err = m.ProAdd(tcp, number); err != nil {
					log.Fatal(err)
				}
			}
			if prot == "udp" {
				if err = m.ProAdd(udp, number); err != nil {
					log.Fatal(err)
				}
			}
			if prot == "0" {
				if err = m.ProAdd(0, number); err != nil {
					log.Fatal(err)
				}
			}
			dport_i, err := strconv.ParseUint(dport, 10, 16)
			if err != nil {
				log.Fatal(err)
			}
			if err = m.DportAdd(uint16(dport_i), number); err != nil {
				log.Fatal(err)
			}
			sport_i, err := strconv.ParseUint(sport, 10, 16)
			if err != nil {
				log.Fatal(err)
			}
			if err = m.SportAdd(uint16(sport_i), number); err != nil {
				log.Fatal(err)
			}
			if err = m.ActAdd(number); err != nil {
				log.Fatal(err)
			}
			/*
			var rules []Rule
			
			data, err := os.ReadFile("pkg/xdp/obj/rules")
			if err != nil {
				_, err := os.Create("pkg/xdp/obj/rules")
				if err != nil {
					log.Fatal(err)
				}
			} else {			
				dec := gob.NewDecoder(bytes.NewReader(data))
				err = dec.Decode(rules)
				if err != nil {
					log.Fatal(err)
				}				
			} 
			var rule Rule
			rule.number = number
			rule.src = sip
			rule.dst = dip
			rule.protocol = prot
			rule.sport = sport
			rule.dport = dport
			rules = append(rules, rule)
			buffer := new(bytes.Buffer)
			encoder := gob.NewEncoder(buffer)
			err = encoder.Encode(rules)
			if err != nil{
				log.Fatal(err)
			}
			err = os.WriteFile("pkg/xdp/obj/rules", buffer.Bytes(), 0666)
			if err != nil{
				log.Fatal(err)
			}*/
			log.Println("rule added to the blacklist")
		},
	}
	return cmd
}