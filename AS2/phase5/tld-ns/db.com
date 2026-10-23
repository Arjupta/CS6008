$TTL 86400
@       IN  SOA tld-ns.cs6008.local. admin.cs6008.local. (
                2026102001 3600 900 604800 86400 )
        IN  NS  tld-ns.com.
tld-ns.com.                IN A 172.16.3.20

; Delegation to example.com, with glue.
; NOTE: in-bailiwick NS target (under example.com, which is itself
; under com) so dnssec-signzone doesn't strip this glue as
; out-of-zone data.
example.com.               IN  NS  domain-ns.example.com.
domain-ns.example.com.     IN  A   172.16.3.30
