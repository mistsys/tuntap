#!/bin/sh

LOCAL_IPV4_ADR=192.168.1.21
REMOTE_IPV4_ADR=192.168.1.22

LOCAL_TUN_IPV4_ADR=10.0.0.2
REMOTE_TUN_IPV4_ADR=10.0.0.1

TUN_DEV=gif0

# remove any pre-existing tunnel interface
ifconfig $TUN_DEV down
ifconfig $TUN_DEV destroy

# setup a new tunnel interface
ifconfig $TUN_DEV create
ifconfig $TUN_DEV tunnel $LOCAL_IPV4_ADR $REMOTE_IPV4_ADR
ifconfig $TUN_DEV $LOCAL_TUN_IPV4_ADR netmask 255.255.255.0 $REMOTE_TUN_IPV4_ADR
ifconfig $TUN_DEV mtu 1500 up
