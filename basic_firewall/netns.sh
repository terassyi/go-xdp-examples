#!/bin/bash

BUILD="build"
CLEAN="clean"

if [ "$BUILD" = "$1" ]; then
	ip netns add node1
	ip link add veth0 type veth peer veth1
	ip link set veth1 netns node1
	ip addr add 192.168.0.3/24 dev veth0
	ip netns exec node1 ip addr add 192.168.0.2/24 dev veth1
	ip link set up dev veth0
	ip netns exec node1 ip link set up dev veth1
	ip netns exec node1 ip link set up lo

elif [ "$CLEAN" = "$1" ]; then
	ip netns del node1
else
	echo "help:"
	echo "	build: build a network to test with netns"
	echo "	clean: clean up a network"
fi


