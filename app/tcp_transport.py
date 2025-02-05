import socket
import threading
from utils import parse_dns_query
import logging


class TCPTransport:
    """
    Handles TCP communication for DNS queries.
    """
    def __init__(self, port, queue):
        self.port = port
        self.queue = queue
        self.server = None

    def listen(self):
        """
        Starts listening for TCP queries.
        """
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("0.0.0.0", self.port))  # Bind to all network interfaces
        self.server.listen(5)  # Listen for up to 5 connections
        host_ip = socket.gethostbyname(socket.gethostname())
        logging.info(f"TCP transport listening on port {host_ip}:{self.port}")

        # Start a thread to accept incoming connections
        threading.Thread(target=self._accept_connections, daemon=True).start()

    def _accept_connections(self):
        """
        Accepts incoming TCP connections.
        """
        while True:
            try:
                conn, addr = self.server.accept()
                threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
            except Exception as e:
                logging.info(f"Error accepting TCP connection: {e}")

    def _handle_connection(self, conn, client_addr):
        """
        Handles individual TCP connections.
        """
        with conn:
            while True:
                try:
                    # Read the length of the incoming DNS query
                    length_bytes = conn.recv(2)
                    if not length_bytes:
                        break

                    query_length = int.from_bytes(length_bytes, "big")
                    query_data = conn.recv(query_length)

                    # Parse the query using the same utility as UDP
                    transaction_id, domain_name, qtype, qclass = parse_dns_query(query_data)
                    logging.info(f"Parsed DNS query for domain: {domain_name} from {client_addr} with transaction ID: {transaction_id}")

                    # Add query data to the queue
                    self.queue.put({
                        "domain_name": domain_name,
                        "transaction_id": transaction_id,
                        "qtype": qtype,
                        "qclass": qclass,
                        "respond": lambda response: conn.sendall(len(response).to_bytes(2, "big") + response),
                        "raw_query": query_data
                    })

                except Exception as e:
                    logging.info(f"Error handling TCP query from {client_addr}: {e}")
                    break

    def close(self):
        """
        Closes the TCP socket.
        """
        if self.server:
            self.server.close()
            logging.info("TCP transport closed")
