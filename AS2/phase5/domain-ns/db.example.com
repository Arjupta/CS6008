$TTL 86400
@       IN  SOA domain-ns.cs6008.local. admin.cs6008.local. (
                2026102001 3600 900 604800 86400 )
        IN  NS  domain-ns.example.com.
domain-ns.example.com.     IN A 172.16.3.30

@       IN  A   172.16.1.20
www     IN  A   172.16.1.20

; Internal names: not advertised anywhere (no other record links to them,
; no hint in example.com's visible content that they exist), representing
; the kind of internal-service hostnames an operator might put in a zone
; without meaning to publish them. The only way to learn these from the
; outside, short of guessing, is to walk the zone's own NSEC chain.
vpn     IN  A   172.16.1.40
db1     IN  A   172.16.1.41
mail    IN  A   172.16.1.42
dev     IN  A   172.16.1.43
staging IN  A   172.16.1.44
