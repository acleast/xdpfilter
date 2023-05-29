package blacklist

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	libbpf "github.com/iovisor/gobpf/elf"
	"xdpfilter/pkg/xdp"
	"net"
	"unsafe"
	"log"
)

const (
	srcMap = "srcMap"
	dstMap = "dstMap"
	protoMap = "protoMap"
	sportMap = "sportMap"
	dportMap = "dportMap"
	actionMap = "actionMap"
)

// Map is responsible for controlling the IP addresses that are part of blacklist map.
type Map struct {
	mod *libbpf.Module
	sip_m   *libbpf.Map
	dip_m   *libbpf.Map
	pro_m   *libbpf.Map
	sport_m *libbpf.Map
	dport_m *libbpf.Map
	act_m   *libbpf.Map
}

// NewMap constructs a new instance of map for manipulating/consulting the blacklist entries.
func NewMap() (*Map, error) {
	mod := libbpf.NewModuleFromReader(bytes.NewReader(xdp.LoadXDPBytecode()))
	if mod == nil {
		return nil, errors.New("ELF module is not initialized")
	}
	if err := mod.Load(nil); err != nil {
		return nil, err
	}
	var bitmap uint64 = 0
	var value uint64
	sip_m := mod.Map(srcMap)
	if sip_m == nil {
		return nil, fmt.Errorf("unable to find %q map in ELF sections", srcMap)
	}
	var default_sip uint32 = 0
	if err := mod.LookupElement(sip_m, unsafe.Pointer(&default_sip), unsafe.Pointer(&value)); err != nil {
		if err := mod.UpdateElement(sip_m, unsafe.Pointer(&default_sip), unsafe.Pointer(&bitmap), 0); err != nil {
			log.Fatal(err)
		}
	}
	dip_m := mod.Map(dstMap)
	if dip_m == nil {
		return nil, fmt.Errorf("unable to find %q map in ELF sections", dstMap)
	}
	var default_dip uint32 = 0
	if err := mod.LookupElement(dip_m, unsafe.Pointer(&default_dip), unsafe.Pointer(&value)); err != nil {
		if err := mod.UpdateElement(dip_m, unsafe.Pointer(&default_dip), unsafe.Pointer(&bitmap), 0); err != nil {
			log.Fatal(err)
		}
	}
	pro_m := mod.Map(protoMap)
	if pro_m == nil {
		return nil, fmt.Errorf("unable to find %q map in ELF sections", protoMap)
	}
	var default_pro uint8 = 0
	if err := mod.LookupElement(pro_m, unsafe.Pointer(&default_pro), unsafe.Pointer(&value)); err != nil {
		if err := mod.UpdateElement(pro_m, unsafe.Pointer(&default_pro), unsafe.Pointer(&bitmap), 0); err != nil {
			log.Fatal(err)
		}
	}
	sport_m := mod.Map(sportMap)
	if sport_m == nil {
		return nil, fmt.Errorf("unable to find %q map in ELF sections", sportMap)
	}
	var default_sport uint16 = 0
	if err := mod.LookupElement(sport_m, unsafe.Pointer(&default_sport), unsafe.Pointer(&value)); err != nil {
		if err := mod.UpdateElement(sport_m, unsafe.Pointer(&default_sport), unsafe.Pointer(&bitmap), 0); err != nil {
			log.Fatal(err)
		}
	}
	dport_m := mod.Map(dportMap)
	if dport_m == nil {
		return nil, fmt.Errorf("unable to find %q map in ELF sections", dportMap)
	}
	var default_dport uint16 = 0
	if err := mod.LookupElement(dport_m, unsafe.Pointer(&default_dport), unsafe.Pointer(&value)); err != nil {
		if err := mod.UpdateElement(dport_m, unsafe.Pointer(&default_dport), unsafe.Pointer(&bitmap), 0); err != nil {
			log.Fatal(err)
		}
	}
	act_m := mod.Map(actionMap)
	if act_m == nil {
		return nil, fmt.Errorf("unable to find %q map in ELF sections", actionMap)
	}
	return &Map{mod: mod, sip_m: sip_m, dip_m: dip_m, pro_m: pro_m, sport_m: sport_m, dport_m: dport_m, act_m: act_m}, nil
}

func (m *Map) GetNumber() uint64 {
	var counter uint64
	var number uint64 = 1
	for {
		if err := m.mod.LookupElement(m.act_m, unsafe.Pointer(&number), unsafe.Pointer(&counter)); err != nil {
			break
		}else {
			number = number << 1
		}
	}
	return number
}

// Add appends a new IP address to the blacklist.
func (m *Map) SipAdd(ip net.IP, number uint64) error {
	var value, bitmap uint64
	addr := convertIPToNumber(ip)
	if addr != 0 {
		if err := m.mod.LookupElement(m.sip_m, unsafe.Pointer(&addr), unsafe.Pointer(&value)); err != nil {
			var key uint32 = 0
			if err = m.mod.LookupElement(m.sip_m, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
				log.Fatal(err)
			}
		}
		bitmap = number | value
		if err := m.mod.UpdateElement(m.sip_m, unsafe.Pointer(&addr), unsafe.Pointer(&bitmap), 0); err != nil {
			return fmt.Errorf("couldn't add %s address to srcMap: %v", ip, err)
		}
	}
	if addr == 0 {
		var key uint32
		var nextKey uint32
		for {
			hasNext, err := m.mod.LookupNextElement(m.sip_m, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
			if err != nil {
				log.Fatal(err)
			}
			bitmap = number | value
			if err = m.mod.UpdateElement(m.sip_m, unsafe.Pointer(&key), unsafe.Pointer(&bitmap), 0); err != nil {
				log.Fatal(err)
			}
			if !hasNext {
				break
			}
			key = nextKey
		}
	}
	return nil
}

func (m *Map) DipAdd(ip net.IP, number uint64) error {
	var value, bitmap uint64
	addr := convertIPToNumber(ip)
	if addr != 0 {
		if err := m.mod.LookupElement(m.dip_m, unsafe.Pointer(&addr), unsafe.Pointer(&value)); err != nil {
			var key uint32 = 0
			if err = m.mod.LookupElement(m.dip_m, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
				log.Fatal(err)
			}
		}
		bitmap = number | value
		if err := m.mod.UpdateElement(m.dip_m, unsafe.Pointer(&addr), unsafe.Pointer(&bitmap), 0); err != nil {
			return fmt.Errorf("couldn't add %s address to dstMap: %v", ip, err)
		}
	}
	if addr == 0 {
		var key uint32
		var nextKey uint32
		for {
			hasNext, err := m.mod.LookupNextElement(m.dip_m, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
			if err != nil {
				log.Fatal(err)
			}
			bitmap = number | value
			if err = m.mod.UpdateElement(m.dip_m, unsafe.Pointer(&key), unsafe.Pointer(&bitmap), 0); err != nil {
				log.Fatal(err)
			}
			if !hasNext {
				break
			}
			key = nextKey
		}
	}
	return nil
}

func (m *Map) ProAdd(proto uint8, number uint64) error {
	var value, bitmap uint64
	if proto != 0 {
		if err := m.mod.LookupElement(m.pro_m, unsafe.Pointer(&proto), unsafe.Pointer(&value)); err != nil {
			var key uint8 = 0
			if err = m.mod.LookupElement(m.pro_m, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
				log.Fatal(err)
			}
		}
		bitmap = number | value
		if err := m.mod.UpdateElement(m.pro_m, unsafe.Pointer(&proto), unsafe.Pointer(&bitmap), 0); err != nil {
			return fmt.Errorf("couldn't add protocol to protoMap: %v", err)
		}
	}
	if proto == 0 {
		var key uint8
		var nextKey uint8
		for {
			hasNext, err := m.mod.LookupNextElement(m.pro_m, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
			if err != nil {
				log.Fatal(err)
			}
			bitmap = number | value
			if err = m.mod.UpdateElement(m.pro_m, unsafe.Pointer(&key), unsafe.Pointer(&bitmap), 0); err != nil {
				log.Fatal(err)
			}
			if !hasNext {
				break
			}
			key = nextKey
		}
	}
	return nil
}

func (m *Map) SportAdd(sport uint16, number uint64) error {
	var value, bitmap uint64
	if sport != 0 {
		if err := m.mod.LookupElement(m.sport_m, unsafe.Pointer(&sport), unsafe.Pointer(&value)); err != nil {
			var key uint16 = 0
			if err = m.mod.LookupElement(m.sport_m, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
				log.Fatal(err)
			}
		}
		bitmap = number | value
		if err := m.mod.UpdateElement(m.sport_m, unsafe.Pointer(&sport), unsafe.Pointer(&bitmap), 0); err != nil {
			return fmt.Errorf("couldn't add %v port to sportMap: %v", sport, err)
		}
	}
	if sport == 0 {
		var key uint16
		var nextKey uint16
		for {
			hasNext, err := m.mod.LookupNextElement(m.sport_m, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
			if err != nil {
				log.Fatal(err)
			}
			bitmap = number | value
			if err = m.mod.UpdateElement(m.sport_m, unsafe.Pointer(&key), unsafe.Pointer(&bitmap), 0); err != nil {
				log.Fatal(err)
			}
			if !hasNext {
				break
			}
			key = nextKey
		}
	}
	return nil
}

func (m *Map) DportAdd(dport uint16, number uint64) error {
	var value, bitmap uint64
	if dport != 0 {
		if err := m.mod.LookupElement(m.dport_m, unsafe.Pointer(&dport), unsafe.Pointer(&value)); err != nil {
			var key uint16 = 0
			if err = m.mod.LookupElement(m.dport_m, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
				log.Fatal(err)
			}
		}
		bitmap = number | value
		if err := m.mod.UpdateElement(m.dport_m, unsafe.Pointer(&dport), unsafe.Pointer(&bitmap), 0); err != nil {
			return fmt.Errorf("couldn't add %v port to dportMap: %v", dport, err)
		}
	}
	if dport == 0 {
		var key uint16
		var nextKey uint16
		for {
			hasNext, err := m.mod.LookupNextElement(m.dport_m, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
			if err != nil {
				log.Fatal(err)
			}
			bitmap = number | value
			if err = m.mod.UpdateElement(m.dport_m, unsafe.Pointer(&key), unsafe.Pointer(&bitmap), 0); err != nil {
				log.Fatal(err)
			}
			if !hasNext {
				break
			}
			key = nextKey
		}
	}
	return nil
}

func (m *Map) ActAdd(number uint64) error {
	var counter uint64 = 0
	if err := m.mod.UpdateElement(m.act_m, unsafe.Pointer(&number), unsafe.Pointer(&counter), 0); err != nil {
		return fmt.Errorf("couldn't add action to actMap: %v", err)
	}
	return nil
}

// Remove deletes an IP address from the blacklist.
// func (m *Map) Remove(ip net.IP) error {
// 	addr := convertIPToNumber(ip)
// 	if err := m.mod.DeleteElement(m.m, unsafe.Pointer(&addr)); err != nil {
// 		return fmt.Errorf("couldn't remove %s address from blacklist map: %v", ip, err)
// 	}
// 	return nil
// }

// // List lists all IP addresses in the blacklist map.
// func (m *Map) List() []net.IP {
// 	var key uint32
// 	var nextKey uint32
// 	var value uint32
// 	addrs := make([]net.IP, 0)
// 	for {
// 		hasNext, _ := m.mod.LookupNextElement(m.m, unsafe.Pointer(&key), unsafe.Pointer(&nextKey), unsafe.Pointer(&value))
// 		if !hasNext {
// 			break
// 		}
// 		key = nextKey
// 		buffer := bytes.NewBuffer([]byte{})
// 		err := binary.Write(buffer, binary.LittleEndian, key)
// 		if err != nil {
// 			continue
// 		}
// 		addrs = append(addrs, buffer.Bytes()[:4])
// 	}
// 	return addrs
// }

// Close the map and disposes all allocated resources.
func (m *Map) Close() {
	m.mod.Close()
}

// convertIPToNumber converts the native IP address to numeric representation.
func convertIPToNumber(ip net.IP) uint32 {
	var num uint32
	binary.Read(bytes.NewBuffer(ip.To4()), binary.LittleEndian, &num)
	return num
}
