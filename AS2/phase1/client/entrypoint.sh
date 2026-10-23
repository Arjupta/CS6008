#!/bin/bash
set -e
ip route add 172.16.2.0/24 via 172.16.1.2
tail -f /dev/null

