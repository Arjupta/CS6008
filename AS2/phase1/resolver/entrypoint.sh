#!/bin/bash
set -e
ip route add 172.16.3.0/24 via 172.16.2.3
ip route add 172.16.1.0/24 via 172.16.2.2
exec named -g -c /etc/bind/named.conf

