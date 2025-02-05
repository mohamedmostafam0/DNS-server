# DNS Server Agent

This project implements a DNS server agent that adheres to the specifications laid out in RFC 1034, RFC 1035, and RFC 2181. It is designed to handle various DNS query types (A, NS, MX, SOA, PTR) and provide accurate responses according to the standards. The server is capable of processing different RCODEs (0 to 10) and includes an authoritative server cache to optimize query resolution.

## Key Features
- **Handles All RCODEs**: Supports RCODE values from 0 to 10, as specified in RFC 1035.
- **Supports Multiple Query Types**: Processes query types such as A, NS, MX, SOA, PTR, and more.
- **Caching Mechanism**: Utilizes Redis for caching DNS responses to improve performance and reduce latency.
- **Authoritative Server**: Manages DNS records for specific domains efficiently.
- **Recursive and Iterative Resolution**: Provides both recursive and iterative DNS query resolution capabilities.
- **UDP and TCP Transport**: Handles DNS queries over both UDP and TCP protocols.

## Directory Structure
```
└── mohamedmostafam0-dns-server/
    ├── README.md
    ├── docker-compose.yml
    ├── dockerfile
    ├── requirements.txt
    ├── app/
    │   ├── BaseCache.py
    │   ├── Server.py
    │   ├── Updateroute.py
    │   ├── authoritative.py
    │   ├── clear_cache.py
    │   ├── main.py
    │   ├── name_cache.py
    │   ├── resolver.py
    │   ├── resolver_cache.py
    │   ├── root.py
    │   ├── tcp_transport.py
    │   ├── tld.py
    │   ├── tld_cache.py
    │   ├── udp_transport.py
    │   ├── utils.py
    │   └── __pycache__/
    └── master_files/
        ├── example_com.zone
        ├── government_gov.zone
        ├── innovators_tech.zone
        ├── mywebsite_com.zone
        ├── networking_net.zone
        ├── opensource_org.zone
        ├── techstartup_io.zone
        └── university_edu.zone
```

## Setup & Usage

### Prerequisites
- Docker installed on your machine.
- Python 3.11 or higher.

### Steps to Run the DNS Server
1. **Build the Docker Image**:
   ```bash
   docker build -t dns-server .
   ```

2. **Run the Docker Containers**:
   ```bash
   docker-compose up
   ```

3. **Run the DNS Server**:
   ```bash
   python app/main.py
   ```

4. **Clear Redis Cache (Optional)**:
   If you need to clear the Redis cache, run:
   ```bash
   python app/clear_cache.py
   ```

### Configuration
- **Redis Instances**: The server uses three Redis instances for caching:
  - `redis-server-1`: Port 6379 (Resolver Cache)
  - `redis-server-2`: Port 6380 (Authoritative Cache)
  - `redis-server-3`: Port 6381 (TLD Cache)

- **DNS Server Ports**:
  - UDP: 1053
  - TCP: 1053

## Contributing
Contributions are welcome! Please feel free to fork, create branches, and open pull requests.


## Acknowledgments
- This project is based on the DNS standards defined in RFC 1034, RFC 1035, and RFC 2181.


