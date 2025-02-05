import socket
import threading
from utils import parse_dns_query
import logging
from authoritative import AuthoritativeServer
class UDPTransport:
    """
    Handles UDP communication for DNS queries.
    """
    def __init__(self, port, queue):
        self.port = port
        self.queue = queue
        self.server = None

    def listen(self):
        """
        Starts listening for UDP queries.
        """
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("0.0.0.0", self.port))  # Bind to all network interfaces
        
        # Get the server's IP address
        host_ip = socket.gethostbyname(socket.gethostname())
        print(f"UDP transport listening on {host_ip}:{self.port}")

        # Start a thread to handle incoming requests
        threading.Thread(target=self._handle_queries, daemon=True).start()

    def _handle_queries(self):
        """
        Handles incoming DNS queries from the UDP socket.
        """
        while True:
            try:
                data, client_addr = self.server.recvfrom(512)  # 512 bytes is max for DNS over UDP
                threading.Thread(target=self._handle_udp_query, args=(data, client_addr), daemon=True).start()
            except Exception as e:
                logging.info(f"Error reading from UDP socket: {e}")

    def _handle_udp_query(self, query_data, client_addr):
        logging.info(f"query data is {query_data}")
        try:
            query_raw = query_data  
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query_raw)
            logging.info(f"Parsed DNS query for domain: {domain_name} from {client_addr} with transaction ID: {transaction_id}")

            self.queue.put({
                "domain_name": domain_name,
                "transaction_id": transaction_id,
                "qtype": qtype,
                "qclass": qclass,
                "respond": lambda response: self.server.sendto(response, client_addr),
                "raw_query": query_raw  # Ensure this is the raw query bytes
            })

        except Exception as e:
            logging.info(f"Error unpacking DNS query from {client_addr}: {e}")

    def close(self):
        """
        Closes the UDP socket.
        """
        if self.server:
            self.server.close()
            AuthoritativeServer.save_master_files()            
            logging.info("UDP transport closed")
