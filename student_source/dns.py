import dnslib.fixedresolver
import dnslib.server


def dns_server(ip):
    resolver = dnslib.fixedresolver.FixedResolver(f". 60 IN A {ip}")
    server = dnslib.server.DNSServer(resolver, port=10053, address="0.0.0.0")
    server.start_thread()
    return server


def dns_server_dns_challenge(challenge):
    resolver = dnslib.fixedresolver.FixedResolver(f". 60 IN TXT {challenge}")
    server = dnslib.server.DNSServer(resolver, port=10053, address="0.0.0.0")
    server.start_thread()
    return server
