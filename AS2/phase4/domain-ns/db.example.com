$TTL 86400
@       IN  SOA domain-ns.cs6008.local. admin.cs6008.local. (
                2026102001 3600 900 604800 86400 )
        IN  NS  domain-ns.example.com.
domain-ns.example.com.     IN A 172.16.3.30

@       IN  A   172.16.1.20
www     IN  A   172.16.1.20
