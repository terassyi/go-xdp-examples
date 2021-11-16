#!/bin/bash

BUILD="build"
CLEAN="clean"

if [ "$BUILD" = "$1" ]; then
	ip netns add node1
	ip netns add node2
	ip link add veth0 type veth peer veth1
	ip link add veth2 type veth peer veth3
	ip link set veth1 netns node1
	ip link set veth2 netns node1
	ip link set veth3 netns node2
	ip addr add 192.168.0.3/24 dev veth0
	ip netns exec node1 ip addr add 192.168.0.2/24 dev veth1
	ip netns exec node1 ip addr add 192.168.1.4/24 dev veth2
	ip netns exec node2 ip addr add 192.168.1.5/24 dev veth3
	ip link set up dev veth0
	ip netns exec node1 ip link set up dev veth1
	ip netns exec node1 ip link set up dev veth2
	ip netns exec node1 ip link set up dev lo
	ip netns exec node2 ip link set up dev veth3
	ip netns exec node2 ip link set up dev lo
	ip netns exec node1 ip route add 192.168.1.0/24 via 192.168.1.4 dev veth2
	ip route add 192.168.1.0/24 via 192.168.0.2

elif [ "$CLEAN" = "$1" ]; then
	ip netns del node1
	ip netns del node2
else
	echo "help:"
	echo "	build: build a network to test with netns"
	echo "	clean: clean up a network"
fi


