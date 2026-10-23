$TTL 86400
@       IN  SOA tld-ns.com. admin.com. (
                2026102001 ; serial
                3600       ; refresh
                900        ; retry
                604800     ; expire
                86400 )    ; minimum
        IN  NS  tld-ns.com.
tld-ns.com.                IN A 172.16.3.20

example.com.                IN  NS  domain-ns.example.com.
domain-ns.example.com.      IN  A   172.16.3.30

