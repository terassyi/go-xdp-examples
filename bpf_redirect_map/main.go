package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --cc clang XdpTest ./bpf/xdp.c -- -I../header


type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_test"`
	IfRedirect *ebpf.Map `ebpf:"if_redirect"`
}

var ifList string

func main() {
	flag.StringVar(&ifList, "iflist", "", "interfaces to attach xdp program to. comma separated.")
	flag.Parse()

	if ifList == "" {
		fmt.Println("interfaces is not specified.")
		os.Exit(1)
	}
	infList := strings.Split(strings.Replace(ifList, " ", "", 0), ",")

	spec, err := LoadXdpTest()
	if err != nil {
		panic(err)
	}
	var collect = &Collect{}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}

	if err := Attach(infList, collect.Prog, collect.IfRedirect); err != nil {
		panic(err)
	}
	defer Detach(infList)

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	for {
		select {
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

func Attach(infList []string, prog *ebpf.Program, ifRedirect *ebpf.Map) error {
	for _, inf := range infList {
		link, err := netlink.LinkByName(inf)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
			return err
		}
		if err := ifRedirect.Put(uint32(link.Attrs().Index), uint32(link.Attrs().Index)); err != nil {
			return err
		}
	}
	return nil
}

func Detach(infList []string) error {
	for _, inf := range infList {
		link, err := netlink.LinkByName(inf)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE); err != nil {
			return err
		}
	}
	return nil
}
