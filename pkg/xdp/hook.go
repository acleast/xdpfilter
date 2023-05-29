package xdp

import (
	"bytes"
	"errors"
	"fmt"
	libbpf "github.com/iovisor/gobpf/elf"
	"net"
	"os"
	"log"
)

const (
	progName = "xdp/xdp_ip_filter"
)

// Hook provides a set of operations that allow for managing the execution of the XDP program
// including attaching it on the network interface, harvesting various statistics or removing
// the program from the interface.
type Hook struct {
	mod *libbpf.Module
}

// NewHook constructs a new instance of the XDP hook from provided XDP code.
func NewHook() (*Hook, error) {
	mod := libbpf.NewModuleFromReader(bytes.NewReader(LoadXDPBytecode()))
	if mod == nil {
		return nil, errors.New("ELF module is not initialized")
	}
	if err := mod.Load(nil); err != nil {
		return nil, err
	}
	return &Hook{mod: mod}, nil
}

// Attach loads the XDP program to specified interface.
func (h *Hook) Attach(dev string) error {
	// before we proceed with attaching make sure that the
	// provided device (interface) is present on the machine
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("couldn't obtain the list of interfaces: %v", err)
	}
	ok := false
	for _, i := range ifaces {
		if i.Name == dev {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("%s interface is not present. Please run `ip a` to list available interfaces", dev)
	}
	// attempt attach the XDP program
	if err := h.mod.AttachXDP(dev, progName); err != nil {
		return err
	}
	return nil
}

// Remove unloads the XDP program from the interface.
func (h *Hook) Remove(dev string) error {
	if err := h.mod.RemoveXDP(dev); err != nil {
		return fmt.Errorf("couldn't unload XDP program from %s interface", dev)
	}
	return nil
}

// Close closes the underlying eBPF module by disposing any allocated resources.
func (h *Hook) Close() error {
	h.mod.Close()
	return nil
}

// LoadXDPBytecode loads XDP byte code from
func LoadXDPBytecode() []byte {
	data, err := os.ReadFile("pkg/xdp/prog/xdp.o")
	if err != nil {
		log.Fatal(err)
	}
	return data
}
