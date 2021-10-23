package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpDump ./bpf/xdp_dump.c -- -I../header

var iface string

const (
	METADATA_SIZE = 12
)

type Collect struct {
	Prog *ebpf.Program `ebpf:"xdp_dump"`
	PerfMap *ebpf.Map `ebpf:"perfmap"`
}

type perfEventItem struct {
	SrcIp uint32
	DstIp uint32
	SrcPort uint16
	DstPort uint16
}

func main() {
	flag.StringVar(&iface, "iface", "", "interface attached xdp program")
	flag.Parse()

	if iface == "" {
		fmt.Println("interface is not specified.")
		os.Exit(1)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}

	spec, err := LoadXdpDump()
	if err != nil {
		panic(err)
	}
	var collect = &Collect{}
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
	perfEvent, err := perf.NewReader(collect.PerfMap, 4096)
	if err != nil {
		panic(err)
	}
	fmt.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
	fmt.Println()
	var (
		received int = 0
		lost int = 0
	)

	go func() {
		var event perfEventItem
		for {
			evnt, err := perfEvent.Read()
			if err != nil {
				if errors.Unwrap(err) == perf.ErrClosed {
					break
				}
				panic(err)
			}
			reader := bytes.NewReader(evnt.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
				panic(err)
			}
			fmt.Printf("TCP: %v:%d -> %v:%d\n",
				intToIpv4(event.SrcIp), ntohs(event.SrcPort),
				intToIpv4(event.DstIp), ntohs(event.DstPort),
			)
			if len(evnt.RawSample) - METADATA_SIZE > 0 {
				fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
			}
			received += len(evnt.RawSample)
			lost += int(evnt.LostSamples)
		}
	}()
	<-ctrlC
	perfEvent.Close()
	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", received)
	fmt.Printf("\t%d Event(s) Lost(e.g. small buffer, delays in processing)\n", lost)
	fmt.Println("\nDetaching program and exit...")
}

func intToIpv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8 ) | (value >> 8)
}
