package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpProg ./bpf/xdp.c -- -I../header

var iface string

type Collect struct {
	Prog *ebpf.Program `ebpf:"packet_count"`
	Protocols *ebpf.Map `ebpf:"protocols"`
}

func main() {
	flag.StringVar(&iface, "iface", "", "interface attached xdp program")
	flag.Parse()

	if iface == "" {
		fmt.Println("iface is not specified.")
		os.Exit(1)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}
	var collect = &Collect{}
	spec, err := LoadXdpProg()
	if err != nil {
		panic(err)
	}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		panic(err)
	}
	defer func() {
		netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE)
	}()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	ticker := time.NewTicker(time.Second * 1)
	for {
		select {
		case <-ticker.C:
			var v []uint64
			var i uint32
			for i = 0; i < 32; i++ {
				if err := collect.Protocols.Lookup(&i, &v); err != nil {
					panic(err)
				}
				if v[1] > 0 {
					fmt.Printf("%s : %v", getProtoName(i), v[1])
				} else if v[0] > 0 {
					fmt.Printf("%s : %v", getProtoName(i), v[0])
				}
			}
			fmt.Printf("\r")
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

func getProtoName(proto uint32) string {
	switch proto {
	case syscall.IPPROTO_ENCAP:
		return "IPPROTO_ENCAP"
	case syscall.IPPROTO_GRE:
		return "IPPROTO_GRE"
	case syscall.IPPROTO_ICMP:
		return "IPPROTO_ICMP"
	case syscall.IPPROTO_IGMP:
		return "IPPROTO_IGMP"
	case syscall.IPPROTO_IPIP:
		return "IPPROTO_IPIP"
	case syscall.IPPROTO_SCTP:
		return "IPPROTO_SCTP"
	case syscall.IPPROTO_TCP:
		return "IPPROTO_TCP"
	case syscall.IPPROTO_UDP:
		return "IPPROTO_UDP"
	default:
		return fmt.Sprintf("%v", proto)
	}
}
