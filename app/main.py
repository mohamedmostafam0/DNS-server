import threading
import logging
from resolver import Resolver
from tld_cache import TLDCache
from name_cache import NameCache
from resolver_cache import ResolverCache
from Server import Server
from authoritative import AuthoritativeServer
from root import RootServer
from tld import TLDServer
from udp_transport import UDPTransport
from tcp_transport import TCPTransport
from queue import Queue
from utils import parse_dns_query


# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    filename='C:/Users/moham/Documents/uni/semesters/fall 2025/networks/Networks-project/app/app.log',       # Logs will be saved to "app.log"
    filemode='w',             # Overwrite the file each time the script runs
    format='%(asctime)s - %(levelname)s - %(message)s'  # Custom log format
)

logging.debug("Debugging details")
logging.info("Info message")
logging.warning("Warning message")
logging.error("Error message")
logging.critical("Critical error")# DNS server configuration

DNS_SERVER_IP = "0.0.0.0"  # Allow access from any device on the local network
DNS_SERVER_UDP_PORT = 1053
DNS_SERVER_TCP_PORT = 1053




def process_queries(queue, server, resolver, tld_cache, authoritative_cache, resolver_cache, root_server, tld_server, authoritative_server):
    """
    Continuously processes DNS queries from the queue.
    """
    if tld_cache:
        logging.info("TLD cache initialized.")
    while True:
        query_data = queue.get()
        if not query_data:
            continue  # Skip if the queue has invalid data
        
        query_raw = query_data.get('raw_query')
        if not query_raw:
            logging.warning("Received empty raw query data.")
            continue

        try:
            # Parse the DNS query
            _, domain_name, _, _ = parse_dns_query(query_raw)

            # Validate the query format
            try:
                transaction_id, domain_name, qtype, qclass = server.validate_query(query_raw)
                logging.debug(f"Received query for domain: {domain_name}, qtype: {qtype}, qclass: {qclass}")
            except ValueError as e:
                logging.error(f"Invalid query: {e}")
                return server.build_error_response(query_raw, rcode=1)  # Format error (RCODE 1)

            # Resolve the query
            response = resolver.resolve_query(
                query_raw,
                server,
                tld_cache, 
                authoritative_cache,
                resolver_cache,
                root_server,
                tld_server,
                authoritative_server,
                recursive=True,
                is_tcp=False,
            )

            # Send the response if valid
            if response:
                query_data['respond'](response)
            else:
                logging.warning(f"No response generated for query: {domain_name}")

        except ValueError as ve:
            logging.error(f"ValueError while processing query: {ve}")
        except Exception as e:
            logging.error(f"Unexpected error while processing query: {e}")


def start_dns_server():
    """
    Starts the DNS server that listens for queries over UDP and TCP.
    """
    # Initialize components
    tld_cache = TLDCache(redis_host="localhost", redis_port=6381)
    authoritative_cache = NameCache(redis_host="localhost", redis_port=6380)  # Authoritative server cache
    resolver_cache = ResolverCache(redis_host="localhost", redis_port=6379)  # Resolver cache
    if(authoritative_cache is None or resolver_cache is None or tld_cache is None):
        logging.error("Failed to initialize caches")
    resolver = Resolver()
    server = Server()
    authoritative_server = AuthoritativeServer(authoritative_cache)  # Handle authoritative queries    root_server = RootServer()  # Initialize RootServer
    root_server = RootServer()  # Initialize RootServer
    tld_server = TLDServer(tld_cache)    # Initialize TLDServer
    
    query_queue = Queue()
    # Start UDP transport
    udp_transport = UDPTransport(DNS_SERVER_UDP_PORT, query_queue)
    udp_transport.listen()

    # Start TCP transport
    tcp_transport = TCPTransport(DNS_SERVER_TCP_PORT, query_queue)
    tcp_transport.listen()

    logging.info(f"DNS server is running on {DNS_SERVER_IP}:{DNS_SERVER_UDP_PORT} for UDP...")
    logging.info(f"DNS server is running on {DNS_SERVER_IP}:{DNS_SERVER_TCP_PORT} for TCP...")

        # Start periodic saving of master files
    save_thread = threading.Thread(target=authoritative_server.periodic_save, args=(authoritative_server,), daemon=True)
    save_thread.start()

    udp_thread = threading.Thread(target=process_queries, args=(query_queue, server, resolver, tld_cache, authoritative_cache, resolver_cache, root_server, tld_server, authoritative_server))
    udp_thread.start()

    return authoritative_cache, resolver_cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread




def main():
    logging.info("Starting the DNS Server Agent...")

    authoritative_cache, resolver_cache, authoritative_server, tld_server, root_server, udp_transport, tcp_transport, udp_thread = start_dns_server()
    
    if authoritative_server is None:
        logging.error("Failed to start DNS server.")
    else:
        try:
            logging.info("DNS Server is running.")

        except KeyboardInterrupt:
            print("\nShutting down the DNS Server. Goodbye!")
            logging.info("Shutting down DNS server...")
            
            # Save master files on shutdown
            authoritative_server.save_master_files()            
            
            # Close resources
            udp_transport.close()
            tcp_transport.close()
            udp_thread.join()

if __name__ == "__main__":
    main()
    