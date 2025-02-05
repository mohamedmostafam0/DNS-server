# DNS-server-agent

This project implements a DNS server agent that adheres to the specifications laid out in RFC 1034, RFC 1035, and RFC 2181. It is designed to handle various DNS query types (A, NS, MX, SOA, and PTR) and provide accurate responses according to the standards. The server is capable of processing different RCODEs (0 to 10) and includes an authoritative server cache to optimize query resolution.

Key Features:
Handles All RCODEs: 0 to 10, as specified in RFC 1035
## Setup & Usage
Ensure Docker is downloaded.
1. docker build .
2. docker-compose run
3. Run main.py
   
## Contributing

Contributions are welcome! Please feel free to fork, create branches, and open pull requests.
