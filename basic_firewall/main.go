package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --cc clang XdpFw ./bpf/xdp_fw.c -- -I../header

type ipAddressList []string

var (
	iface string
	ipList ipAddressList
)

type Collect struct {
	Prog *ebpf.Program `ebpf:"firewall"`
	Matches *ebpf.Map `ebpf:"matches"`
	Blacklist *ebpf.Map `ebpf:"blacklist"`
}

type lpmTrieKey struct {
	prefixlen uint32
	addr uint32
}

func main() {
	flag.StringVar(&iface, "iface", "", "interface attached xdp program.")
	flag.Var(&ipList, "drop", "IPv4 or CIDR to DROP traffic from, repeatable")
	flag.Parse()
	if iface == "" {
		fmt.Println("interface is not specified.")
		os.Exit(1)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		panic(err)
	}
	var collect = &Collect{}
	spec, err := LoadXdpFw()
	if err != nil {
		panic(err)
	}
	// spec.Maps["fw_blacklist"] = &ebpf.MapSpec {
	// 	Name: "fw_blacklist",
	// 	Type: ebpf.LPMTrie,
	// 	Flags: unix.BPF_F_NO_PREALLOC,
	// 	KeySize: 8,
	// 	ValueSize: 4,
	// 	MaxEntries: 16,
	// }
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		panic(err)
	}
	fmt.Println("Blacklisting IPv4 Addresses...")
	for index, ip := range ipList {
		fmt.Printf("\t%s\n", ip)
		k := ipNetToUint64(createLPMTrieKey(ip))
		if err := collect.Blacklist.Put(k, uint32(index)); err != nil {
			panic(err)
		}
	}
	fmt.Println()
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
			for i = 0; i < uint32(len(ipList)); i++ {
				if err := collect.Matches.Lookup(&i, &v); err != nil {
					panic(err)
				}
				if v[0] != 0 {
					fmt.Printf("%18s\t%d\n", ipList[i], v[0])
				} else if v[1] != 0 {
					fmt.Printf("%18s\t%d\n", ipList[i], v[1])
				}
			}
			fmt.Println()
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

func (i *ipAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

func (i *ipAddressList) Set(value string) error {
	if len(*i) == 16 {
		return errors.New("Up to 16 IPv4 addresses supported.")
	}
	if !strings.Contains(value, "/") {
		value+= "/32"
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s is not an IPv4 address", value)
	}
	if _, _, err := net.ParseCIDR(value); err != nil {
		return err
	}
	*i = append(*i, value)
	return nil
}

func createLPMTrieKey(s string) *net.IPNet {
	var ipnet *net.IPNet
	if strings.Contains(s, "/") {
		_, ipnet, _ = net.ParseCIDR(s)
	} else {
		if strings.Contains(s, ":") {
			// ipv6
			_, ipnet, _ = net.ParseCIDR(s + "/128")
		} else {
			_, ipnet, _ = net.ParseCIDR(s + "/32")
		}
	}
	return ipnet
}

// keySize and valueSize need to be sizeof(struct{u32 + u8}) + 1 + padding = 8
func ipNetToUint64(ipnet *net.IPNet) *lpmTrieKey {
	prefixlen, _ := ipnet.Mask.Size()
	addr := binary.LittleEndian.Uint32(ipnet.IP)
	key := &lpmTrieKey {
		prefixlen: uint32(prefixlen),
		addr: addr,
	}
	return key
}

