#!/bin/bash
set -e
# Unlike Phases 2/4/6/7's interceptor, this attacker never relies on
# diverted traffic -- it originates its own queries straight to domain-ns,
# so it needs an ordinary static route to the authoritative subnet, same
# as any other non-router node reaching an off-subnet address (see the
# assignment's privilege policy: only the routers forward; everyone else
# just needs a route through one).
ip route add 172.16.3.0/24 via 172.16.2.3   # authoritative subnet, via core-router
tail -f /dev/null
