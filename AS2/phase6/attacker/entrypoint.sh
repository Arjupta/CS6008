#!/bin/bash
set -e
rm -f /tmp/forge_enabled
cd /opt/attacker
exec ./interceptor eth0 172.16.1.10 example.com. 172.16.1.30 /tmp/forge_enabled
