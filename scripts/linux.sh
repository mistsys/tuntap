#!/bin/bash

LOCAL_IPV4_ADR=192.168.1.22
REMOTE_IPV4_ADR=192.168.1.21

LOCAL_TUN_IPV4_ADR=10.0.0.1
REMOTE_TUN_IPV4_ADR=10.0.0.2

PHYS_DEV=wlp8s0
TUN_DEV=tun0

MODE=ipip

# remove any pre-existing tunnel interface
ip link set $TUN_DEV down
ip tunnel del $TUN_DEV

# setup a new tunnel interface
ip tunnel add $TUN_DEV mode $MODE local $LOCAL_IPV4_ADR remote $REMOTE_IPV4_ADR dev $PHYS_DEV
ip addr add $LOCAL_TUN_IPV4_ADR/24 dev $TUN_DEV
ip link set $TUN_DEV mtu 1500 up
