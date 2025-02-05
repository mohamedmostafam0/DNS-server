Directory structure:
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


Files Content:

================================================
File: README.md
================================================
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


================================================
File: docker-compose.yml
================================================
services:
  redis1:
      image: "redis:latest"
      container_name: "redis-server-1"
      ports:
        - "6379:6379"
      command: redis-server --databases 3  # Configures Redis to use 2 databases
      restart: always

  redis2:
      image: "redis:latest"
      container_name: "redis-server-2"
      ports:
        - "6380:6379"  # Maps to a different port for the second Redis instance
      command: redis-server --databases 3  # Configures Redis to use 2 databases
      restart: always

  redis3:
      image: "redis:latest"
      container_name: "redis-server-3"
      ports:
        - "6381:6379"  # Maps to a different port for the second Redis instance
      command: redis-server --databases 3  # Configures Redis to use 2 databases
      restart: always

  python-dns:
    build: .
    container_name: "python-dns-resolver"
    ports:
      - "1053:1053"
    environment:
      - REDIS_HOST1=redis1
      - REDIS_HOST2=REDIS_HOST2
    depends_on:
      - redis1
      - redis2
    restart: always


================================================
File: dockerfile
================================================
# Base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && apt-get clean \
    && update-ca-certificates

# Copy the requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY ./app /app

# Expose the DNS port
EXPOSE 1053

# Command to run the application
ENTRYPOINT ["python", "main.py"]


================================================
File: requirements.txt
================================================
requests
pyyaml
dnslib
redis
dnspython
tldextract


================================================
File: app/BaseCache.py
================================================
import redis
import time
import pickle
from typing import Optional
import hashlib
import logging
from utils import parse_question_section, parse_dns_query


class BaseCache:
    def __init__(self, redis_host, redis_port, db):
        """
        Initializes the Redis cache connection.
        """
        self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
        # print("Cache connection initialized")

    def get(self, cache_key: tuple, transaction_id: int) -> Optional[bytes]:
            """
            Retrieves the DNS query response from the cache if it exists and is still valid (TTL not expired),
            ensuring the transaction ID matches the client's query.
            """
            # Serialize the cache key to a string
            key_string = self._serialize_cache_key(cache_key)
            cached_data = self.client.get(key_string)
            logging.info(f"Cache key: {key_string}, cached_data: {cached_data}")

            if cached_data:
                try:
                    cached_response = pickle.loads(cached_data)
                except Exception as e:
                    logging.error(f"Error deserializing cache data: {e}")
                    return None

                if cached_response['ttl'] > time.time():
                    try:
                        # Parse the cached response to extract details and ensure integrity
                        cached_transaction_id, domain_name, qtype, qclass = parse_dns_query(cached_response['response'])
                        # logging.info(f"Cached transaction ID: {cached_transaction_id}, Domain: {domain_name}, Qtype: {qtype}, Qclass: {qclass}")


                        # Modify the cached response to include the new transaction ID
                        response = bytearray(cached_response['response'])  # Convert to mutable bytearray
                        response[0:2] = transaction_id.to_bytes(2, byteorder='big')  # Update transaction ID

                        # logging.info(f"Updated transaction ID in response for domain: {domain_name}")
                        return bytes(response)  # Convert back to bytes and return
                    except ValueError as e:
                        logging.error(f"Error parsing cached DNS response: {e}")
                        return None
                else:
                    # Cache entry expired, delete it
                    self.client.delete(key_string)
                    logging.info(f"Cache expired for key: {key_string}")

            return None

    def store(self, response: bytes):
        # logging.info(f"storing response in cache")
        ttl = 3600
        try:
            qname, qtype, qclass, _ = parse_question_section(response, 12)
            qname = qname.lower()  # Normalize domain to lowercase
            cache_key = (qname, qtype, qclass)

            key_string = self._serialize_cache_key(cache_key)

            cache_entry = {
                'response': response,
                'ttl': time.time() + ttl
            }

            self.client.setex(key_string, ttl, pickle.dumps(cache_entry))
#            logging.info(f"Stored in cache: Key={key_string}, TTL={ttl}, Entry={cache_entry}")
        except Exception as e:
            logging.error(f"Error storing response in cache: {e}")

    def _serialize_cache_key(self, cache_key: tuple) -> str:
        """
        Serializes a tuple cache key into a string format suitable for Redis.

        Parameters:
            cache_key (tuple): The cache key as (domain_name, qtype, qclass).

        Returns:
            str: A serialized string suitable for Redis.
        """
        return f"dns:{hashlib.sha256(':'.join(map(str, cache_key)).encode()).hexdigest()}"


================================================
File: app/Server.py
================================================
import logging
import struct
import random
import socket
from utils import parse_dns_query

class Server:
    """
    Parent class for DNS servers (Root, TLD, Authoritative).
    Provides common methods and properties for DNS query handling.
    """


    QTYPE_MAPPING = {
        1: "A",       # A host address (IPv4 addresses)
        2: "NS",      # Name Server
        5: "CNAME",   # Canonical Name
        6: "SOA",     # Start of Authority
        7: "MB",      # Mailbox Domain Name
        8: "MG",      # Mail Group Member
        9: "MR",      # Mail Rename Domain Name
        10: "NULL",   # Null Resource Record
        11: "WKS",    # Well Known Service Description
        12: "PTR",    # Domain Name Pointer (Reverse DNS)
        13: "HINFO",  # Host Information
        14: "MINFO",  # Mailbox or Mail List Information
        15: "MX",     # Mail Exchange
        16: "TXT",    # Text Strings
        252: "AXFR",  # Authoritative Zone Transfer
        253: "MAILB", # Mailbox-related Record
        254: "MAILA"  # Mail Agent Record
    }


    def __init__(self):
        self.records = {}


    def build_response(self, query, record_type):
        """
        Constructs a DNS response for a valid query.
        """
        try:
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
            logging.info(f"Query: {query}, domain: {domain_name}, qtype: {qtype}, qclass: {qclass}")

            if domain_name not in self.records or record_type not in self.records[domain_name]:
                return self.build_error_response(query, rcode=3)  # NXDOMAIN

            header = self.build_dns_header(transaction_id, flags=0x8180, qd_count=1, an_count=len(self.records[domain_name][record_type]))

            question = self.build_question_section(domain_name, qtype, qclass)
            
            answer = self.build_answer_section(domain_name, record_type, qtype, qclass)

            response = header + question + answer
            # logging.info(f"Response built: {response}")
            return response

        except Exception as e:
            logging.error(f"Error building DNS response: {e}")
            return self.build_error_response(query, rcode=2)  # Server failure

    def build_dns_header(self, transaction_id, flags, qd_count, an_count, ns_count=0, ar_count=0):
        """
        Constructs the DNS header.
        """
        return struct.pack("!HHHHHH", transaction_id, flags, qd_count, an_count, ns_count, ar_count)

    def build_question_section(self, domain_name, qtype, qclass):
        """
        Constructs the DNS question section.
        """
        question = b"".join(bytes([len(label)]) + label.encode('ascii') for label in domain_name.split('.')) + b'\x00'
        question += struct.pack("!HH", qtype, qclass)
        return question

    def build_answer_section(self, domain_name, record_type, qtype, qclass):
        """
        Constructs the DNS answer section.
        """
        answer = b""
        for record in self.records[domain_name][record_type]:
            answer += self.build_rr(domain_name, qtype, qclass, ttl=3600, rdata=record)
        return answer

    def build_rr(self, name, rtype, rclass, ttl, rdata):
        """
        Builds a resource record.
        """
        rr = b"".join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\x00'
        rr += struct.pack("!HHI", rtype, rclass, ttl)
        rr += struct.pack("!H", len(rdata)) + rdata
        return rr

    def build_error_response(self, query, rcode):
        """
        Constructs a DNS response with an error (e.g., NXDOMAIN or NOTIMP).
        """
        try:
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
            flags = 0x8180 | rcode  # Set QR (response) flag and RCODE
            header = self.build_dns_header(transaction_id, flags, qd_count=1, an_count=0, ns_count=0, ar_count=0)
            question = self.build_question_section(domain_name, qtype, qclass)
            return header + question
        except Exception as e:
            logging.error(f"Failed to build error response: {e}")
            return b''  # Return an empty response on failure


    def validate_query(self, query):
        """
        Validates a DNS query for compliance with RFC standards.
        """
        if len(query) < 12:
            raise ValueError("Invalid DNS query: Query too short")

        transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
        logging.debug(f"Validating query: {domain_name}, qtype: {qtype}, qclass: {qclass}")
        if qtype not in self.QTYPE_MAPPING:
            # Handle unsupported query types
            raise ValueError(f"Unsupported query type: {qtype}")

        if qclass != 1:  # Only support IN class
            raise ValueError("Unsupported query class")
        return transaction_id, domain_name, qtype, qclass
    
    def query_type_to_string(self, qtype):
        """
        Converts a numeric query type to its string representation.
        """
        return self.QTYPE_MAPPING.get(qtype)

    def query_type_to_int(self, record_type):
        """
        Converts a string query type to its numeric representation.
        """
        reverse_mapping = {v: k for k, v in self.QTYPE_MAPPING.items()}
        return reverse_mapping.get(record_type)


    def ip_to_bytes(self, ip_address):
        """
        Converts a dotted-quad IPv4 address to 4 bytes.
        """
        return socket.inet_aton(ip_address)

    def bytes_to_ip(self, ip_bytes):
        """
        Converts 4 bytes into a dotted-quad IPv4 address.
        """
        return socket.inet_ntoa(ip_bytes)

    def extract_ip_from_answer(self, answer_section):
        """
        Extract the IP address from the answer section of a DNS response.
        """
        try:
            parts = answer_section.split()
            if len(parts) >= 4 and parts[2] == 'A':
                return parts[3]
            return None
        except Exception as e:
            logging.error(f"Error extracting IP address: {e}")
            return None

    @staticmethod
    def set_ra_flag(response):
        """
        Set the RA (Recursion Available) flag in the DNS header.
        """
        header = response[:2] + struct.pack("!H", struct.unpack("!H", response[2:4])[0] | 0x0080) + response[4:]
        return header
    
    def extract_referred_ip(self, response):
        """
        Extracts the referred IP address from a DNS response (Additional section).
        """
        # Locate the additional section (last part of the response)
        try:
            # Find the start of the additional section (example assumes one Authority and one Additional record)
            # Skip the header (12 bytes) + Question (domain name + 4 bytes for QTYPE/QCLASS) + Authority section
            question_end = response.find(b'\x00\x01\x00\x01') + 4  # End of Question
            additional_section = response[question_end:]

            # Locate the RDATA for the additional record
            rdata_offset = additional_section.rfind(b'\x00\x04')  # Look for A record with RDLENGTH of 4 bytes
            if rdata_offset == -1:
                raise ValueError("RDATA for A record not found in the additional section")

            # Extract the 4-byte IP address
            ip_bytes = additional_section[rdata_offset + 2: rdata_offset + 6]  # Skip the RDLENGTH
            if len(ip_bytes) != 4:
                raise ValueError(f"Invalid IP bytes length: {len(ip_bytes)} (expected 4)")

            return self.bytes_to_ip(ip_bytes)
        except Exception as e:
            raise ValueError(f"Failed to extract referred IP: {e}")
        


================================================
File: app/authoritative.py
================================================
import struct
import logging
from name_cache import NameCache  # Import the Cache class
from utils import parse_dns_query
import os
import socket
from Server import Server
import time

logging.basicConfig(level=logging.DEBUG)

class AuthoritativeServer(Server): 
    def __init__(self, cache: NameCache):
        """
        Initializes the authoritative DNS server with some predefined DNS records.
        """
        self.cache = cache  # Use the passed-in cache instance
        self.records = {
            "example.com": {
                "A": ["93.184.216.34"],
                "NS": ["ns1.example.com.", "ns2.example.com."],
                "MX": ["10 mail.example.com.", "20 backup.mail.example.com."],
                "SOA": ["ns1.example.com. admin.example.com. 2023120301 7200 3600 1209600 86400"],
                "PTR": ["example.com."],
                "TXT": ["v=spf1 include:_spf.example.com ~all"],
                "CNAME": ["alias.example.com."],
                "MG": ["mailgroup@example.com"],
                "MR": ["mailrename@example.com"],
                "NULL": [""],
                "WKS": ["93.184.216.34"],
                "HINFO": ["Intel i7", "Ubuntu Linux"],
                "MINFO": ["admin@example.com", "errors@example.com"],
                "MAILB": ["mailbackup@example.com"],
            },

            "mywebsite.com": {
                "A": ["93.184.216.35", "93.184.216.36"],
                "NS": ["ns1.mywebsite.com.", "ns2.mywebsite.com."],
                "MX": ["10 mail.mywebsite.com.", "20 backup.mail.mywebsite.com."],
                "SOA": ["ns1.mywebsite.com. admin.mywebsite.com. 2023120302 7200 3600 1209600 86400"],
                "PTR": ["mywebsite.com.", "reverse.mywebsite.com."]
            },
            "opensource.org": {
                "A": ["93.184.216.36", "93.184.216.37"],
                "NS": ["ns1.opensource.org.", "ns2.opensource.org."],
                "MX": ["10 mail.opensource.org.", "20 backup.mail.opensource.org."],
                "SOA": ["ns1.opensource.org. admin.opensource.org. 2023120303 7200 3600 1209600 86400"],
                "PTR": ["93.184.216.36.in-addr.arpa.", "93.184.216.37.in-addr.arpa."],
                "TXT": ["\"Open source is freedom.\""],
                "CNAME": ["alias.opensource.org."],
                "HINFO": ["\"AMD Ryzen\" \"Arch Linux\""],
                "MINFO": ["admin@opensource.org errors@opensource.org"],
                "MB": ["mailbox1.opensource.org."],
                "MG": ["mailgroup@opensource.org"],
                "MR": ["mailrename@opensource.org"],
                "NULL": [""],
                "WKS": ["93.184.216.36 17 01020304"],  # UDP protocol
                "MAILB": ["backup-mail@opensource.org"]
            },
            "networking.net": {
                "A": ["93.184.216.37", "93.184.216.38"],
                "NS": ["ns1.networking.net.", "ns2.networking.net."],
                "MX": ["10 mail.networking.net.", "20 backup.mail.networking.net."],
                "SOA": ["ns1.networking.net. admin.networking.net. 2023120304 7200 3600 1209600 86400"],
                "PTR": ["networking.net."],
                "TXT": ["v=spf1 include:_spf.networking.net ~all"],
                "CNAME": ["alias.networking.net."],
                "MG": ["mailgroup@networking.net"],
                "MR": ["mailrename@networking.net"],
                "NULL": [""],
                "HINFO": ["Intel i7", "Ubuntu Linux"],
                "MINFO": ["admin@networking.net", "errors@networking.net"],
                "MAILB": ["mailbackup@networking.net"],
            },
            "university.edu": {
                "A": ["93.184.216.38", "93.184.216.39"],
                "NS": ["ns1.university.edu.", "ns2.university.edu."],
                "MX": ["10 mail.university.edu.", "20 backup.mail.university.edu."],
                "SOA": ["ns1.university.edu. admin.university.edu. 2023120305 7200 3600 1209600 86400"],
                "PTR": ["university.edu."],
                "TXT": ["v=spf1 include:_spf.university.edu ~all"],
                "CNAME": ["alias.university.edu."],
                "MG": ["mailgroup@university.edu"],
                "MR": ["mailrename@university.edu"],
                "NULL": [""],
                "WKS": ["93.184.216.38 6 01020304"],
                "HINFO": ["Intel i7", "Ubuntu Linux"],
                "MINFO": ["admin@university.edu", "errors@university.edu"],
                "MAILB": ["mailbackup@university.edu"],
            },
            "government.gov": {
                "A": ["93.184.216.39", "93.184.216.40"],
                "NS": ["ns1.government.gov.", "ns2.government.gov."],
                "MX": ["10 mail.government.gov.", "20 backup.mail.government.gov."],
                "SOA": ["ns1.government.gov. admin.government.gov. 2023120306 7200 3600 1209600 86400"],
                "PTR": ["government.gov.", "reverse.government.gov."]
            },
            "techstartup.io": {
                "A": ["93.184.216.40", "93.184.216.41"],
                "NS": ["ns1.techstartup.io.", "ns2.techstartup.io."],
                "MX": ["10 mail.techstartup.io.", "20 backup.mail.techstartup.io."],
                "SOA": ["ns1.techstartup.io. admin.techstartup.io. 2023120307 7200 3600 1209600 86400"],
                "PTR": ["93.184.216.40.in-addr.arpa.", "93.184.216.41.in-addr.arpa."],
                "TXT": ["\"Startups rule!\""],
                "CNAME": ["alias.techstartup.io."],
                "HINFO": ["\"Intel i9\" \"Debian Linux\""],
                "MINFO": ["admin@techstartup.io errors@techstartup.io"],
                "MB": ["mailbox1.techstartup.io."],
                "MG": ["mailgroup@techstartup.io"],
                "MR": ["mailrename@techstartup.io"],
                "NULL": [""],
                "WKS": ["93.184.216.40 6 01020304"],  # TCP protocol
                "MAILB": ["backup-mail@techstartup.io"]
            },
            "innovators.tech": {
                "A": ["93.184.216.41", "93.184.216.42"],
                "NS": ["ns1.innovators.tech.", "ns2.innovators.tech."],
                "MX": ["10 mail.innovators.tech."],
                "SOA": ["ns1.innovators.tech. admin.innovators.tech. 2023120308 7200 3600 1209600 86400"],
                "PTR": ["innovators.tech.", "reverse.innovators.tech."]
            },
        }


    def handle_name_query(self, query):
        """
        Handles the DNS query by checking the cache first and then looking up the record for the domain.
        """
        try:
            transaction_id, domain_name, qtype, _ = parse_dns_query(query)
            if not domain_name:
                return self.build_error_response(query, rcode=3)  # Invalid domain name

            # Convert qtype from numeric to string representation
            qtype_str = self.query_type_to_string(qtype)
            if not qtype_str:
                return self.build_error_response(query, rcode=4)  # Not Implemented

            # Check if domain exists and qtype is supported
            if domain_name in self.records and qtype_str in self.records[domain_name]:
                response = self.build_response(query)
                self.cache.store(response)
                return response
            else:
                return self.build_error_response(query, rcode=3)  # NXDOMAIN

        except Exception as e:
            logging.error(f"Error handling query: {e}")
            return self.build_error_response(query, rcode=2)  # Server failure



    def build_response(self, query):
        """
        Builds the DNS response with consistent handling of qtype as a string.
        """
        try:
            # Parse the DNS query
            transaction_id, domain_name, qtype, qclass = parse_dns_query(query)

            # Convert qtype to string
            record_type = self.query_type_to_string(qtype)
            if not record_type:
                logging.error(f"Unsupported query type: {qtype}")
                return self.build_error_response(query, rcode=4)  # Not Implemented

            # Validate domain and record type
            if domain_name not in self.records or record_type not in self.records[domain_name]:
                logging.info(f"Domain or record type not found: {domain_name}, {record_type}")
                return self.build_error_response(query, rcode=3)  # NXDOMAIN

            # Build DNS response header
            flags = 0x8180  # Standard query response (QR=1, AA=1, RCODE=0)
            questions = 1
            answers = len(self.records[domain_name][record_type])
            authority_rrs = 0
            additional_rrs = 0
            header = self.build_dns_header(transaction_id, flags, questions, answers, authority_rrs, additional_rrs)

            # Build DNS question section
            question = self.build_question_section(domain_name, qtype, qclass)

            # Build DNS answer section
            answer = self.build_answer_section(domain_name, record_type, qtype, qclass)

            # Combine all sections to form the response
            response = header + question + answer
            # logging.debug(f"header is {header}, question is {question}, answer is {answer}")
            return response

        except Exception as e:
            logging.error(f"Error building DNS response: {e}")
            return self.build_error_response(query, rcode=2)  # Server failure



    def build_answer_section(self, domain_name, record_type, qtype, qclass):
            
        """
        Constructs the DNS answer section for the response.
        """
        answer = b''
        domain_offsets = {domain_name: 12}  # Domain offsets for compression pointers
        current_length = 12

        # Convert query type to integer if needed
        querytype = self.query_type_to_int(record_type)
        if querytype is None:
            logging.error(f"Invalid record type: {record_type}")
            return answer  # Return an empty answer for unsupported types

        for record in self.records[domain_name][record_type]:
            compressed_name, current_length = self.encode_domain_name_with_compression(
                domain_name, domain_offsets, current_length
            )
            answer += compressed_name

            if record_type == "A":
                # IPv4 address
                answer += struct.pack("!HHI", querytype, qclass, 3600)
                answer += struct.pack("!H", 4)  # RDLENGTH
                answer += socket.inet_aton(record)

            elif record_type == "MX":
                # Mail exchange record
                priority, mail_server = record.split(' ', 1)
                mail_server_rdata, current_length = self.encode_domain_name_with_compression(
                    mail_server, domain_offsets, current_length
                )
                rdata = struct.pack("!H", int(priority)) + mail_server_rdata
                answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

            elif record_type in ["NS", "CNAME", "PTR"]:
                # Domain name records
                rdata, current_length = self.encode_domain_name_with_compression(
                    record, domain_offsets, current_length
                )
                answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

            elif record_type == "TXT":
                # Text record
                rdata = bytes([len(record)]) + record.encode('ascii')
                answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

            elif record_type == "SOA":
                # Start of Authority record
                primary_ns, admin_email, serial, refresh, retry, expire, min_ttl = record.split(' ')
                primary_ns_rdata, current_length = self.encode_domain_name_with_compression(
                    primary_ns, domain_offsets, current_length
                )
                admin_email_rdata, current_length = self.encode_domain_name_with_compression(
                    admin_email, domain_offsets, current_length
                )
                rdata = (primary_ns_rdata + admin_email_rdata +
                        struct.pack("!IIIII", int(serial), int(refresh), int(retry), int(expire), int(min_ttl)))
                answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

            elif record_type == "HINFO":
                # Host information
                cpu, os = record.split(' ', 1)
                rdata = bytes([len(cpu)]) + cpu.encode('ascii') + bytes([len(os)]) + os.encode('ascii')
                answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

            elif record_type in ["MB", "MG", "MR"]:
                # Mailbox-related records
                rdata, current_length = self.encode_domain_name_with_compression(
                    record, domain_offsets, current_length
                )
                answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

            elif record_type == "WKS":
                try:
                    # Well-known services
                    components = record.split(' ', 2)
                    if len(components) != 3:
                        raise ValueError(f"Invalid WKS record format for domain {domain_name}: {record}")
                    
                    ip, protocol, bitmap = components
                    rdata = socket.inet_aton(ip) + struct.pack("!B", int(protocol)) + bytes.fromhex(bitmap)
                    answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

                except ValueError as ve:
                    logging.error(f"Error processing WKS record for domain {domain_name}: {ve}")
                except Exception as e:
                    logging.error(f"Unexpected error in WKS record for domain {domain_name}: {e}")

            elif record_type in ["NULL", "AXFR", "MAILB", "MAILA"]:
                rdata = b''
                answer += struct.pack("!HHIH", querytype, qclass, 3600, len(rdata)) + rdata

            elif record_type == "*":
                # Wildcard queries (respond with all record types for the domain)
                for rtype, records in self.records[domain_name].items():
                    for r in records:
                        wildcard_answer = self.build_answer_section(domain_name, rtype, qtype, qclass)
                        answer += wildcard_answer

                answer += b''
        return answer


    
    def encode_domain_name_with_compression(self, domain_name, domain_offsets, current_length):
        """
        Encodes a domain name, using compression pointers where possible.

        Parameters:
        - domain_name (str): The domain name to encode.
        - domain_offsets (dict): A dictionary mapping domain names to their positions.
        - current_length (int): The current length of the message.

        Returns:
        - bytes: The encoded domain name.
        - int: The updated current length of the message.
        """
        try:
            if domain_name in domain_offsets:
                # Use a compression pointer if the domain was already encoded
                pointer = domain_offsets[domain_name]
                # logging.debug(f"Domain name '{domain_name}' already encoded at offset {pointer}. Using compression pointer.")
                compressed_pointer = struct.pack("!H", 0xC000 | pointer)
                return compressed_pointer, current_length
            else:
                # Encode the domain name fully and store its position
                encoded_name = b''.join(
                    bytes([len(label)]) + label.encode('ascii') for label in domain_name.split('.')
                )
                if not encoded_name.endswith(b'\x00'):  # Ensure only one null byte for termination
                    encoded_name += b'\x00'
                domain_offsets[domain_name] = current_length
                return encoded_name, current_length + len(encoded_name)
        except Exception as e:
            logging.error(f"Error encoding domain name '{domain_name}': {e}")
            raise

        #master file

    def save_master_files(self, output_dir="master_files"):
        """
        Saves DNS records to master zone files in the specified directory, formatted per RFC 1034, 1035, and 2181.

        Parameters:
            output_dir (str): The directory to save the master zone files.
        """
        os.makedirs(output_dir, exist_ok=True)

        for domain, records in self.records.items():
            file_name = f"{output_dir}/{domain.replace('.', '_')}.zone"
            try:
                with open(file_name, 'w') as file:
                    # Write $ORIGIN and $TTL
                    file.write(f"$ORIGIN {domain}.\n")
                    file.write(f"$TTL 3600\n\n")  # Default TTL for records
                    
                    for rtype, rdata_list in records.items():
                        for rdata in rdata_list:
                            try:
                                if rtype == "SOA":
                                    primary_ns, admin_email, serial, refresh, retry, expire, min_ttl = rdata.split(' ')
                                    file.write(f"{domain} IN SOA {primary_ns} {admin_email} (\n")
                                    file.write(f"    {serial} ; Serial\n")
                                    file.write(f"    {refresh} ; Refresh\n")
                                    file.write(f"    {retry} ; Retry\n")
                                    file.write(f"    {expire} ; Expire\n")
                                    file.write(f"    {min_ttl} ; Minimum TTL\n")
                                    file.write(")\n")

                                elif rtype == "MX":
                                    priority, mail_server = rdata.split(' ', 1)
                                    file.write(f"{domain} IN MX {priority} {mail_server}\n")

                                elif rtype in ["A", "NS", "PTR", "CNAME"]:
                                    file.write(f"{domain} IN {rtype} {rdata}\n")

                                elif rtype == "TXT":
                                    escaped_rdata = rdata.replace('"', '\\"')
                                    file.write(f"{domain} IN TXT \"{escaped_rdata}\"\n")

                                elif rtype == "HINFO":
                                    cpu, os_info = rdata.split(' ', 1)
                                    file.write(f"{domain} IN HINFO \"{cpu}\" \"{os_info}\"\n")

                                elif rtype == "MINFO":
                                    rmailbx, emailbx = rdata.split(' ', 1)
                                    file.write(f"{domain} IN MINFO {rmailbx} {emailbx}\n")

                                elif rtype in ["MB", "MG", "MR"]:
                                    file.write(f"{domain} IN {rtype} {rdata}\n")

                                elif rtype == "WKS":
                                    address, protocol, bitmap = rdata.split(' ', 2)
                                    file.write(f"{domain} IN WKS {address} {protocol} {bitmap}\n")

                                elif rtype == "NULL":
                                    file.write(f"{domain} IN NULL\n")

                                elif rtype == "AXFR":
                                    file.write(f"{domain} IN AXFR\n")

                                elif rtype == "MAILB":
                                    file.write(f"{domain} IN MAILB {rdata}\n")

                                elif rtype == "MAILA":
                                    file.write(f"{domain} IN MAILA {rdata}\n")

                                elif rtype == "*":
                                    file.write(f"{domain} IN * {rdata}\n")

                                else:
                                    logging.warning(f"Unsupported record type: {rtype} for domain {domain}. Skipping.")
                            except ValueError as ve:
                                logging.error(f"Error formatting record {rtype} for {domain}: {ve}")
                                continue

                    logging.info(f"Master file saved: {file_name}")

            except Exception as e:
                logging.error(f"Failed to save master file {file_name}: {e}")

                

    def periodic_save(self, authoritative_server, interval=3600):
        while True:
            time.sleep(interval)  # Save every hour
            authoritative_server.save_master_files()
            logging.info("Master files saved periodically.")




================================================
File: app/clear_cache.py
================================================
import subprocess

def clear_redis_cache(server_name):
    try:
        print(f"Clearing cache for {server_name}...")
        # Execute the Redis flushdb command inside the container
        result = subprocess.run(
            ["docker", "exec", "-i", server_name, "redis-cli", "flushdb"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            print(f"Cache cleared successfully for {server_name}.")
        else:
            print(f"Failed to clear cache for {server_name}: {result.stderr}")
    except Exception as e:
        print(f"Error clearing cache for {server_name}: {e}")

# List of Redis servers
servers = ["redis-server-1", "redis-server-2", "redis-server-3"]

# Clear cache for each server
for server in servers:
    clear_redis_cache(server)


================================================
File: app/main.py
================================================
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
    

================================================
File: app/name_cache.py
================================================
import redis
from BaseCache import BaseCache

# class NameCache(BaseCache):
#     def __init__(self, redis_host="localhost", redis_port=6380, db=0):
#         """
#         Initializes the Redis cache connection.
#         """
#         self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
#         print("Authoritative Cache connection initialized")

class NameCache(BaseCache):
    def __init__(self, redis_host="localhost", redis_port=6380, db=0):
        super().__init__(redis_host, redis_port, db)  # Call BaseCache constructor
        print("Authoritative Cache connection initialized")


================================================
File: app/resolver.py
================================================
import struct
import logging
from name_cache import NameCache
from resolver_cache import ResolverCache
from tld_cache import TLDCache
from udp_transport import UDPTransport
from authoritative import AuthoritativeServer
from root import RootServer
from tld import TLDServer 
from utils import (
    parse_dns_response,
    parse_dns_query
)


# Set up logging
logging.basicConfig(level=logging.DEBUG)

class Resolver: 
    def resolve_query(self, query, server, tld_cache, authoritative_cache, resolver_cache, root_server: RootServer, tld_server: TLDServer, authoritative_server: AuthoritativeServer, recursive, is_tcp=False):
        """
        Resolves a DNS query by checking the cache and querying the Root, TLD, and Authoritative servers in sequence.
        The recursive flag indicates whether to resolve the query recursively.
        """
        # Validate the query format
        try:
            transaction_id, domain_name, qtype, qclass = server.validate_query(query)
            logging.debug(f"Received query for domain: {domain_name}, qtype: {qtype}, qclass: {qclass}")
        except ValueError as e:
            logging.error(f"Query validation error: {e}")
            return server.build_error_response(query, rcode=4)  # NOTIMP (Not Implemented)

        transaction_id, domain_name, qtype, qclass = parse_dns_query(query)
        cache_key = (domain_name, qtype, qclass)
        # Check the cache for the response
        cached_response = resolver_cache.get(cache_key, transaction_id)
        if cached_response:
            logging.info(f"Resolver cache hit for domain: {domain_name}")
            human_readable = parse_dns_response(cached_response)
            logging.info(f"Response in human readable format is {human_readable}")
            return cached_response
            # return human_readable

        logging.info(f"Resolver cache miss for domain: {domain_name}. Querying root server.")

        if recursive:
            # Query Root Server and follow the chain for recursive resolution
            # logging.info(f"recursive query")
            root_response = root_server.handle_root_query(query)
            # logging.info(f"root response is {root_response}")
            if not root_response:
                logging.error(f"Root server could not resolve domain: {domain_name}")
                return self.build_error_response(query, rcode=3)  # NXDOMAIN

            # logging.debug(f"cache key is {cache_key}, transaction id is {transaction_id}")
            tld_cached_response = tld_cache.get(cache_key, transaction_id)
            # logging.debug(f"TLD cached response is: {tld_cached_response}")
            if tld_cached_response:
                logging.info(f"Top level domain cache hit for domain: {domain_name}")
                tld_response = tld_cached_response
            else:

                logging.info(f"Cache miss for top-level domain: {domain_name}")
                tld_server_ip = tld_server.extract_referred_ip(root_response)
                # logging.debug(f"Referred TLD server IP: {tld_server_ip}")
                tld_response = tld_server.handle_tld_query(root_response)

                logging.debug(f"TLD server IP is {tld_server_ip} and TLD response is {tld_response}")
                if not tld_response:
                    logging.error(f"TLD server could not resolve domain: {domain_name}")
                    return self.build_error_response(query, rcode=3)  # NXDOMAIN

                # Store the response in the TLD cache
                tld_cache.store(tld_response)
                # logging.info(f"Returning referral to TLD server at {tld_server_ip}")

            # Query Authoritative Server
            # Check the cache for the response
            cached_response = authoritative_cache.get(cache_key, transaction_id)
            if cached_response:
                logging.info(f"Authoritative cache hit for domain: {domain_name}")
                resolver_cache.store(cached_response)
                human_readable = parse_dns_response(cached_response)
                logging.info(f"Response in human readable format is {human_readable}")
                return cached_response
                # return human_readable

            # logging.info(f"your tld response is {tld_response}")
            authoritative_server_ip = authoritative_server.extract_referred_ip(tld_response)
            # logging.debug(f"Referred authoritative server IP: {authoritative_server_ip}")
            authoritative_response = authoritative_server.handle_name_query(tld_response)
            logging.info(f"Authoritative response is {authoritative_response}")
            if not authoritative_response:
                logging.error(f"Authoritative server could not resolve domain: {domain_name}")
                return self.build_error_response(query, rcode=3)  # NXDOMAIN

            # Cache the successful response
            logging.info(f"Authoritative anad resolver caching response for domain: {domain_name}")
            authoritative_cache.store(authoritative_response)
            resolver_cache.store(authoritative_response)
        else:
            logging.info(f"iterative query")

            # Iterative query: Simply send back the referral or best possible response
            root_response = root_server.handle_root_query(query)
            logging.info(f"root response is {root_response}")
            if not root_response:
                logging.error(f"Root server could not resolve domain: {domain_name}")
                return self.build_error_response(query, rcode=3)  # NXDOMAIN

            # Return the referral to TLD server
            tld_server_ip = tld_server.extract_referred_ip(root_response)
            tld_response = tld_server.handle_tld_query(query)
            return tld_response

        # Check if the response needs to be sent over TCP (due to TC flag)
        if len(authoritative_response) > 512:
            logging.info("Response size exceeds 512 bytes, setting TC flag.")
            if not is_tcp:  # If this is a UDP query
                # Set the TC flag in the DNS header to indicate truncation
                authoritative_response = self.set_tc_flag(authoritative_response)
                logging.info("Response truncated. Returning over UDP with TC flag set.")
                return authoritative_response
            else:
                # If the query is already over TCP, no need to set TC flag; just send the full response
                logging.info("Returning full response over TCP.")
                return authoritative_response

        # Return the response as a regular UDP response
        human_readable = parse_dns_response(authoritative_response)
        logging.info(f"Response in human readable format is {human_readable}")
        return authoritative_response
        # return human_readable

    def set_tc_flag(response):
        """
        Sets the TC flag in the DNS header to indicate that the response is truncated.
        This is used when sending the response over TCP.
        """
        # Unpack the DNS header
        header = response[:12]  # First 12 bytes are the DNS header
        transaction_id = struct.unpack("!H", header[:2])[0]
        flags = struct.unpack("!H", header[2:4])[0]
        # Set the TC flag (bit 1) to 1
        flags |= 0x0200  # 0x0200 corresponds to the TC bit (bit 1 of the flags byte)
        # Repack the DNS header with the updated flags
        header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
        # Return the response with the updated header
        return header + response[12:]


================================================
File: app/resolver_cache.py
================================================
import redis
from BaseCache import BaseCache

# class ResolverCache(BaseCache):
#     def __init__(self, redis_host="localhost", redis_port=6379, db=0):
#         """
#         Initializes the Redis cache connection.
#         """
#         self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
#         print("Resolver Cache connection initialized")

class ResolverCache(BaseCache):
    def __init__(self, redis_host="localhost", redis_port=6379, db=0):
        super().__init__(redis_host, redis_port, db)  # Call BaseCache constructor
        print("Resolver Cache connection initialized")


================================================
File: app/root.py
================================================
import tldextract
import logging
from Server import Server
import struct
from utils import (
    parse_dns_query,
    format_ns_name
)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("filelock").setLevel(logging.WARNING)

class RootServer(Server):
    def __init__(self):
        # Mapping of TLDs to TLD server addresses (expanded with more dummy data)
        self.tld_mapping = {
            "com": "192.168.1.10",
            "org": "192.168.1.11",
            "net": "192.168.1.12",
            "edu": "192.168.1.13",
            "gov": "192.168.1.14",
            "io": "192.168.1.15",
            "tech": "192.168.1.16",
            "co": "192.168.1.17",
            "us": "192.168.1.18",
            "ca": "192.168.1.19",
            "uk": "192.168.1.20",
            "de": "192.168.1.21",
            "fr": "192.168.1.22",
            "jp": "192.168.1.23",
            "in": "192.168.1.24",
            "au": "192.168.1.25",
            "cn": "192.168.1.26",
            "br": "192.168.1.27",
            "mx": "192.168.1.28",
            "ru": "192.168.1.29",
            "za": "192.168.1.30",
            "ch": "192.168.1.31",
            "it": "192.168.1.32",
            "es": "192.168.1.33",
            "se": "192.168.1.34",
            "pl": "192.168.1.35",
            "no": "192.168.1.36",
            "fi": "192.168.1.37",
            "nl": "192.168.1.38",
            "kr": "192.168.1.39",
            "sg": "192.168.1.40",
            "hk": "192.168.1.41",
            "ae": "192.168.1.42",
            "sa": "192.168.1.43",
            "cl": "192.168.1.44",
            "ar": "192.168.1.45",
            "tr": "192.168.1.47",
            "vn": "192.168.1.48",
            "my": "192.168.1.49",
            "kr": "192.168.1.50",
            "id": "192.168.1.51",
            "pk": "192.168.1.52",
            "ng": "192.168.1.53",
            "th": "192.168.1.54",
            "bd": "192.168.1.55",
            "ph": "192.168.1.56",
            "kw": "192.168.1.57",
            "kw": "192.168.1.58",
            "gr": "192.168.1.59",
            "cz": "192.168.1.60",
            "hk": "192.168.1.61",
            "ua": "192.168.1.62",
            "by": "192.168.1.63",
            "hr": "192.168.1.64",
            "si": "192.168.1.65",
            "at": "192.168.1.66",
            "be": "192.168.1.67",
            "lu": "192.168.1.68",
            "li": "192.168.1.69",
            "is": "192.168.1.70",
            "mt": "192.168.1.71",
            "rs": "192.168.1.72",
            "me": "192.168.1.73",
            "mk": "192.168.1.74",
            "gd": "192.168.1.75",
            "lt": "192.168.1.76",
            "ee": "192.168.1.77",
            "lv": "192.168.1.78",
            "ge": "192.168.1.79",
            "am": "192.168.1.80",
            "kg": "192.168.1.81",
            "md": "192.168.1.82",
            "uz": "192.168.1.83",
            "tj": "192.168.1.84",
            "tm": "192.168.1.85",
            "kp": "192.168.1.86",
        }


    def handle_root_query(self, query):
        """
        Handles DNS queries by referring them to the correct TLD server.
        """
        domain_name = self.extract_domain_name(query)
        tld = self.get_tld(domain_name)
        if tld in self.tld_mapping:
            tld_server_address = self.tld_mapping[tld]
            logging.info(f"Referring query for {domain_name} to TLD server at {tld_server_address}")
            return self.build_referral_response(query, tld, tld_server_address)
        
        logging.error(f"TLD {tld} not found in root server mapping.")
        return self.build_error_response(query, rcode=3)  # NXDOMAIN

    @staticmethod
    def extract_domain_name(query):
        """
        Extracts the domain name from the DNS query.
        """
        # Extract the domain name part from the query (skipping header).
        query = query[12:]  # Skip the DNS header (first 12 bytes)
        labels = []
        while query:
            length = query[0]
            if length == 0:
                break
            labels.append(query[1:1+length].decode())
            query = query[1+length:]
        return ".".join(labels)

    @staticmethod
    def get_tld(domain_name):
        """
        Extracts the top-level domain (TLD) from a domain name.
        """
        extracted = tldextract.extract(domain_name)
        return extracted.suffix  # Returns the full TLD (e.g., "com", "co.uk")
    
    def build_referral_response(self, query, tld, ns_address):
        """
        Constructs a referral response pointing to a name server.

        Parameters:
            query (bytes): The raw DNS query.
            ns_domain (str): The domain name of the name server (e.g., "a.gtld-servers.net").
            tld (str): The top-level domain being referred (e.g., "com").
            ns_address (str): The IP address of the name server (e.g., "192.168.1.1").

        Returns:
            bytes: The DNS referral response.
        """
        transaction_id, domain_name, qtype, qclass = parse_dns_query(query)

        # DNS Header
        flags = 0x8180  # Standard query response (QR=1, AA=0, RCODE=0)
        qd_count = 1
        an_count = 0
        ns_count = 1
        ar_count = 1

        # Build the DNS header
        header = self.build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)

        # Question Section
        question = self.build_question_section(domain_name, qtype, qclass)

        # Authority Section (NS Record)
        ns_record = self.build_rr(
            name=tld,  # Referring the TLD (e.g., "com")
            rtype=2,  # NS record
            rclass=1,  # IN class
            ttl=3600,  # TTL in seconds
            rdata=format_ns_name(domain_name)
        )

        # Additional Section (A Record for the Name Server)
        additional_record = self.build_rr(
            name=domain_name,
            rtype=1,
            rclass=1,
            ttl=3600,
            rdata= self.ip_to_bytes(ns_address)
        )

        return header + question + ns_record + additional_record





================================================
File: app/tcp_transport.py
================================================
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


================================================
File: app/tld.py
================================================
import logging
from utils import (
    parse_dns_query,
    format_ns_name,
)
from Server import Server   
from tld_cache import TLDCache

# Set up logging
logging.basicConfig(level=logging.DEBUG)


class TLDServer(Server):
    def __init__(self, cache: TLDCache):
        """
        Initializes the TLD server with a mapping of second-level domains to
        authoritative server addresses.
        """
        self.authoritative_mapping = {
            "example.com": "192.168.2.10",
            "mywebsite.com": "192.168.2.11",
            "opensource.org": "192.168.2.12",
            "networking.net": "192.168.2.13",
            "university.edu": "192.168.2.14",
            "government.gov": "192.168.2.15",
            "techstartup.io": "192.168.2.16",
            "innovators.tech": "192.168.2.17",
        }
        self.ttl = 3600
        self.cache = cache


    def handle_tld_query(self, query):
            """
            Handles DNS queries by referring them to the correct authoritative server.
            """
            try:
                _, domain_name, _, _ = parse_dns_query(query)
                domain_name = domain_name.lower()  # Ensure case-insensitivity
                print("Your query is for: " + domain_name)
            except ValueError as e:
                logging.error(f"Invalid query: {e}")
                print("Building error response")
                return self.build_error_response(query, rcode=1)  # Format error (RCODE 1)
            
            # cached_response = self.cache.get(domain_name)
            # if cached_response:
            #     logging.info(f"Cache hit for {domain_name}.")
            #     return cached_response

            # Find the authoritative server for the domain
            authoritative_server_address = self.find_authoritative_server(domain_name)
            if authoritative_server_address:
                # logging.info(
                #     f"Referring query for {domain_name} to authoritative server at {authoritative_server_address}")
                response = self.build_referral_response(query, domain_name, authoritative_server_address)
                # self.cache.store(domain_name, response)
                return response

            # If no authoritative server is found, return an error response
            print(f"No authoritative server found for {domain_name}")
            return self.build_error_response(query, rcode=3)  # Name Error (RCODE 3)


    def find_authoritative_server(self, domain_name):
        """
        Finds the authoritative server for the given domain name.
        Checks for exact domain name matches.
        """
        # Check for exact domain name match in the mapping
        if domain_name in self.authoritative_mapping:
            return self.authoritative_mapping[domain_name]

        # If no match is found, return None
        return None


    def build_referral_response(self, query, domain_name, next_server_ip):
        """
        Constructs a referral response pointing to the next server.
        """
        transaction_id, _, qtype, qclass = parse_dns_query(query)

        # DNS header
        flags = 0x8180  # Standard query response, authoritative answer
        qd_count = 1  # One question
        an_count = 0  # No answer records
        ns_count = 1  # One authority record
        ar_count = 1  # One additional record
        header = self.build_dns_header(transaction_id, flags, qd_count, an_count, ns_count, ar_count)

        # Question Section
        question = self.build_question_section(domain_name, qtype, qclass)

        # Authority Section (NS record)
        authority_rr = self.build_rr(
            name=domain_name,
            rtype=2,  # NS record
            rclass=1,  # IN class
            ttl=self.ttl,  # Time-to-live
            rdata=format_ns_name("ns1.authoritative-server.com"),
        )

        # Additional Section (A record for next server)
        additional_rr = self.build_rr(
            name="ns1.authoritative-server.com",
            rtype=1,  # A record
            rclass=1,  # IN class
            ttl=self.ttl,  # Time-to-live
            rdata= self.ip_to_bytes(next_server_ip),
        )

        return header + question + authority_rr + additional_rr



================================================
File: app/tld_cache.py
================================================
import redis
from BaseCache import BaseCache

# class TLDCache(BaseCache):
#     def __init__(self, redis_host="localhost", redis_port=6381, db=0):
#         """
#         Initializes the Redis cache connection.
#         """
#         self.client = redis.StrictRedis(host=redis_host, port=redis_port, db=db, decode_responses=False)
#         print("TLD Cache connection initialized")

class TLDCache(BaseCache):
    def __init__(self, redis_host="localhost", redis_port=6381, db=0):
        super().__init__(redis_host, redis_port, db)  # Call BaseCache constructor
        print("Authoritative Cache connection initialized")


================================================
File: app/udp_transport.py
================================================
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


================================================
File: app/utils.py
================================================
import struct
import socket
import random
import logging
import threading
import time


def send_dns_query(server, query, is_tcp):
    """
    Sends a DNS query to the given server using either UDP or TCP based on the is_tcp flag.
    """
    # Prepare the socket based on the desired transport protocol
    if is_tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server.ip, server.port))
        sock.sendall(query)
        response = sock.recv(4096)
        sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(query, (server.ip, server.port))
        response, _ = sock.recvfrom(4096)
        sock.close()

    # Call the appropriate handle query method based on the server type
    if isinstance(server, root_server):
        return server.handle_root_query(response)
    elif isinstance(server, tld_server):
        return server.handle_tld_query(response)
    elif isinstance(server, authoritative_server):
        return server.handle_name_query(response)
    return None



# def build_rr(name, rtype, rclass, ttl, rdata):
#     """
#     Builds a resource record.
    
#     Parameters:
#         name (str): The domain name for the record.
#         rtype (int): The type of the record (e.g., 1 for A, 2 for NS).
#         rclass (int): The class of the record (e.g., 1 for IN).
#         ttl (int): The time-to-live value for the record.
#         rdata (bytes): The record data.
    
#     Returns:
#         bytes: The resource record.
#     """
#     rr = b""
#     for part in name.split("."):
#         rr += struct.pack("!B", len(part)) + part.encode("utf-8")  # Encode to bytes
#     rr += b"\x00"  # End of domain name
#     rr += struct.pack("!HHI", rtype, rclass, ttl)  # TYPE, CLASS, TTL
#     rr += struct.pack("!H", len(rdata)) + rdata  # RDLENGTH and RDATA
#     return rr


def parse_dns_query(query):
    """
    Parses a DNS query to extract the transaction ID, domain name, query type (QTYPE), and query class (QCLASS).
    """
    # Ensure the query is long enough to contain a header
    if len(query) < 12:
        raise ValueError("Invalid DNS query: Too short")

    # Transaction ID is the first 2 bytes
    transaction_id = struct.unpack("!H", query[:2])[0]
    
    # Parse the domain name, which starts after the first 12 bytes (header)
    domain_parts = []
    idx = 12
    try:
        while query[idx] != 0:  # A label is terminated by a 0 byte
            length = query[idx]
            idx += 1
            if idx + length > len(query):
                raise ValueError("Invalid DNS query: Domain name length exceeds query size")
            domain_parts.append(query[idx:idx + length].decode())
            idx += length
    except IndexError:
        raise ValueError("Invalid DNS query: Domain name parsing failed")

    domain_name = ".".join(domain_parts)
    
    # Skip the next byte before reading QTYPE and QCLASS
    idx += 1
    
    # Now that the domain is fully parsed, the next 4 bytes should be QTYPE and QCLASS
    # Ensure there's enough data for QTYPE and QCLASS (2 bytes each)
    if len(query) < idx + 4:
        raise ValueError("Invalid DNS query: Missing QTYPE or QCLASS")

    # Unpack QTYPE and QCLASS (each are 2 bytes long, so we use "!HH")
    qtype = struct.unpack("!H", query[idx:idx + 2])[0]
    qclass = struct.unpack("!H", query[idx + 2:idx + 4])[0]
    
    # Debugging output to check what values are being parsed
    # logging.debug(f"Transaction ID: {transaction_id}, Domain: {domain_name}, QTYPE: {qtype}, QCLASS: {qclass}")

    # If QCLASS is not valid, raise an error
    if qclass != 1:  # Only support IN class (1)
        logging.error(f"Invalid query: Unsupported query class {qclass}")
        raise ValueError(f"Unsupported query class: {qclass}")

    return transaction_id, domain_name, qtype, qclass





def format_ns_name(name):
    """
    Formats an NS name for use in a DNS response (e.g., "ns.example.com").
    """
    formatted_name = b""
    for part in name.split("."):
        formatted_name += struct.pack("!B", len(part)) + part.encode()
    return formatted_name + b"\x00"







def extract_ip_from_answer(answer_section):
    """
    Extract the IP address from the answer section of a DNS response.

    Args:
        answer_section (str): The answer section from the DNS response (formatted as 'name IN A ip_address').

    Returns:
        str: The extracted IP address, or None if no valid A record is found.
    """
    try:
        # Split the answer section by spaces to extract the components
        parts = answer_section.split()

        # Check if the record type is A (IPv4 address)
        if len(parts) >= 4 and parts[2] == 'A':
            ip_address = parts[3]
            return ip_address
        else:
            print("Not an A record or invalid format.")
            return None
    except Exception as e:
        print(f"Error extracting IP address: {str(e)}")
        return None


def parse_dns_response(response):
    """
    Parse DNS response with enhanced error handling.
    """
    try:
        if len(response) < 12:
            raise ValueError("Response too short for DNS header")
        
        # Parse header
        header = struct.unpack("!HHHHHH", response[:12])
        transaction_id, flags, qdcount, ancount, nscount, arcount = header
        
        current_pos = 12
        questions = []
        answers = []
        
        # Parse question section
        for _ in range(qdcount):
            qname, qtype, qclass, new_pos = parse_question_section(response, current_pos)
            if qname:
                questions.append(f"{qname} TYPE{qtype} CLASS{qclass}")
            # print(questions)
            current_pos = new_pos
        
        # Parse answer section
        for _ in range(ancount):
            answer, new_pos = parse_answer_section(response, current_pos, qname)
            if answer:
                answers.append(answer)
            current_pos = new_pos
        
        return {
            'transaction_id': transaction_id,
            'flags': hex(flags),
            'questions': questions,
            'answers': answers
        }
        
    except Exception as e:
        logging.error(f"Error parsing DNS response: {str(e)}")
        return {
            'transaction_id': transaction_id if 'transaction_id' in locals() else None,
            'flags': hex(flags) if 'flags' in locals() else None,
            'questions': questions if 'questions' in locals() else [],
            'answers': answers if 'answers' in locals() else []
        }

def parse_answer_section(response, offset, domain_name):
    """
    Parse DNS answer section with detailed debugging.
    """
    try:
        if offset + 12 > len(response):  # Minimum answer record length
            return None, offset

        # Handle name compression
        if response[offset] & 0xC0 == 0xC0:
            offset += 2  # Skip compression pointer
        else:
            # Skip name fields until null terminator
            while offset < len(response) and response[offset] != 0:
                offset += response[offset] + 1
            offset += 1  # Skip null terminator

        # Read fixed fields
        if offset + 10 > len(response):  # TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
            return None, offset

        rtype, rclass, ttl = struct.unpack('!HHI', response[offset:offset + 8])
        offset += 8
        
        rdlength = struct.unpack('!H', response[offset:offset + 2])[0]
        offset += 2

        if offset + rdlength > len(response):
            return None, offset

        # For A records
        if rtype == 1 and rdlength == 4:
            ip_bytes = response[offset:offset + rdlength]
            ip_address = '.'.join(str(b) for b in ip_bytes)
            return f"{domain_name} IN A {ip_address}", offset + rdlength

        return None, offset + rdlength

    except Exception as e:
        logging.error(f"Error parsing answer section: {str(e)}")
        return None, offset


def parse_dns_name(response, offset):
    """
    Parse DNS name with debug logging.
    """
    try:
        name_parts = []
        original_offset = offset
        
        # Debug output
        # print(f"Starting to parse name at offset {offset}")
        # print(f"First few bytes: {response[offset:offset+10].hex()}")
        
        while offset < len(response):
            length = response[offset]
            # print(f"Label length byte at offset {offset}: {length}")
            
            # Check for compression (0xC0)
            if length & 0xC0 == 0xC0:
                # print(f"Found compression pointer at offset {offset}")
                pointer = ((length & 0x3F) << 8) | response[offset + 1]
                # print(f"Pointer value: {pointer}")
                # Move the offset to the pointer location
                offset = pointer
                continue
            
            # Check for end of name (length byte = 0)
            if length == 0:
                break
            
            # Debug check for invalid label length
            if length > 63:
                print(f"WARNING: Invalid label length {length} at offset {offset}")
                print(f"Surrounding bytes: {response[max(0, offset - 5):offset + 5].hex()}")
                raise ValueError(f"Label length {length} exceeds maximum of 63")
            
            # Increment offset to start of the label
            offset += 1
            if offset + length > len(response):
                raise ValueError("Label extends beyond message")
            
            # Extract the label and decode it
            label = response[offset:offset + length]
            try:
                name_parts.append(label.decode('ascii'))
                # print(f"Decoded label: {name_parts[-1]}")
            except UnicodeDecodeError:
                raise ValueError("Invalid character in domain name")
            
            # Update offset to move past the label
            offset += length
            
        # Join parts to form the fully qualified domain name
        name = '.'.join(name_parts)
        # print(f"Final parsed name: {name}")
        
        # Move the offset past the null byte that ends the name
        return name, offset + 1
        
    except Exception as e:
        logging.error(f"Error parsing DNS name: {str(e)}")
        return None, offset


def parse_question_section(response, offset):
    """
    Parse DNS question section with improved error handling.
    """
    try:
        # Parse the question name
        qname, offset = parse_dns_name(response, offset)
        if qname is None:
            raise ValueError("Failed to parse question name")
        
        # Ensure we have enough bytes for qtype and qclass
        if offset + 4 > len(response):
            raise ValueError("Question section truncated")
        
        # Get question type and class
        qtype, qclass = struct.unpack("!HH", response[offset:offset + 4])
        return qname, qtype, qclass, offset + 4
        
    except Exception as e:
        logging.error(f"Error parsing question section: {str(e)}")
        return None, None, None, offset





def construct_dns_response(response):
    """
    Processes a given DNS response and removes any parts that are not part of the 
    DNS response according to RFC standards.
    
    Parameters:
    - response: The raw DNS response bytes.
                
    Returns:
    - A byte string containing only the valid parts of the DNS response.
    """
    try:
        # Decode the header to determine the number of sections
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", response[:12])
        logging.info(f"tID is {transaction_id} flags are {flags} qdcount is {qdcount}, ancount is {ancount} nscount is {nscount} arcount is {arcount}")

        # Validate the response format
        if qdcount == 0 or ancount == 0:
            raise ValueError("Invalid DNS response: Missing question or answer section.")

        # Extract the question section length
        question_offset = 12
        while response[question_offset] != 0:  # Skip labels until null byte (end of domain name)
            question_offset += response[question_offset] + 1
            if question_offset >= len(response):  # Check for out-of-bounds
                raise IndexError("Question section exceeds response length.")
        question_offset += 5  # Skip the null byte, qtype, and qclass

        # Extract the answer section length
        answer_offset = question_offset
        actual_answers = 0  # Track actual number of answers

        for i in range(ancount):
            logging.info(f"Processing answer {i+1}, current answer_offset: {answer_offset}")
            
            # Ensure we don't exceed the response length
            if answer_offset >= len(response):
                raise IndexError(f"Answer section exceeds response length for answer {i+1}.")
            
            # Skip domain name (compressed or not)
            if response[answer_offset] & 0xC0 == 0xC0:  # Compressed name
                answer_offset += 2  # Skip the compression pointer
            else:
                while response[answer_offset] != 0:
                    answer_offset += response[answer_offset] + 1
                    if answer_offset >= len(response):  # Check for out-of-bounds
                        raise IndexError(f"Answer section domain name exceeds response length for answer {i+1}.")
                answer_offset += 1  # Skip null byte at the end of domain name

            # Skip Type, Class, TTL, RDLENGTH fields (10 bytes)
            if answer_offset + 10 > len(response):
                raise IndexError(f"Answer section truncated while reading Type/Class/TTL/RDLENGTH for answer {i+1}.")
            
            # Extract the RDATA length (RDLENGTH is at the offset)
            rdata_length = struct.unpack("!H", response[answer_offset + 8:answer_offset + 10])[0]
            logging.info(f"RDATA length is {rdata_length}")

            # Skip the RDLENGTH (2 bytes) and RDATA itself
            answer_offset += 10 + rdata_length  # Skip RDLENGTH and RDATA

            # Count this as a valid answer
            actual_answers += 1

        # Ensure the number of answers in the response matches the 'ancount' value
        if actual_answers != ancount:
            logging.warning(f"Warning: Expected {ancount} answers, but found {actual_answers}.")

        # Return only the valid part of the response (header + question + answer sections)
        valid_response = response[:answer_offset]
        logging.info(f"valid response is {valid_response}")
        return valid_response

    except Exception as e:
        logging.error(f"Error constructing DNS response: {e}", exc_info=True)
        return b""









================================================
File: master_files/example_com.zone
================================================
$ORIGIN example.com.
$TTL 3600

example.com IN A 93.184.216.34
example.com IN NS ns1.example.com.
example.com IN NS ns2.example.com.
example.com IN MX 10 mail.example.com.
example.com IN MX 20 backup.mail.example.com.
example.com IN SOA ns1.example.com. admin.example.com. (
    2023120301 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
example.com IN PTR example.com.
example.com IN TXT "v=spf1 include:_spf.example.com ~all"
example.com IN CNAME alias.example.com.
example.com IN MG mailgroup@example.com
example.com IN MR mailrename@example.com
example.com IN NULL
example.com IN HINFO "Intel" "i7"
example.com IN HINFO "Ubuntu" "Linux"
example.com IN MAILB mailbackup@example.com


================================================
File: master_files/government_gov.zone
================================================
$ORIGIN government.gov.
$TTL 3600

government.gov IN A 93.184.216.39
government.gov IN A 93.184.216.40
government.gov IN NS ns1.government.gov.
government.gov IN NS ns2.government.gov.
government.gov IN MX 10 mail.government.gov.
government.gov IN MX 20 backup.mail.government.gov.
government.gov IN SOA ns1.government.gov. admin.government.gov. (
    2023120306 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
government.gov IN PTR government.gov.
government.gov IN PTR reverse.government.gov.


================================================
File: master_files/innovators_tech.zone
================================================
$ORIGIN innovators.tech.
$TTL 3600

innovators.tech IN A 93.184.216.41
innovators.tech IN A 93.184.216.42
innovators.tech IN NS ns1.innovators.tech.
innovators.tech IN NS ns2.innovators.tech.
innovators.tech IN MX 10 mail.innovators.tech.
innovators.tech IN SOA ns1.innovators.tech. admin.innovators.tech. (
    2023120308 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
innovators.tech IN PTR innovators.tech.
innovators.tech IN PTR reverse.innovators.tech.


================================================
File: master_files/mywebsite_com.zone
================================================
$ORIGIN mywebsite.com.
$TTL 3600

mywebsite.com IN A 93.184.216.35
mywebsite.com IN A 93.184.216.36
mywebsite.com IN NS ns1.mywebsite.com.
mywebsite.com IN NS ns2.mywebsite.com.
mywebsite.com IN MX 10 mail.mywebsite.com.
mywebsite.com IN MX 20 backup.mail.mywebsite.com.
mywebsite.com IN SOA ns1.mywebsite.com. admin.mywebsite.com. (
    2023120302 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
mywebsite.com IN PTR mywebsite.com.
mywebsite.com IN PTR reverse.mywebsite.com.


================================================
File: master_files/networking_net.zone
================================================
$ORIGIN networking.net.
$TTL 3600

networking.net IN A 93.184.216.37
networking.net IN A 93.184.216.38
networking.net IN NS ns1.networking.net.
networking.net IN NS ns2.networking.net.
networking.net IN MX 10 mail.networking.net.
networking.net IN MX 20 backup.mail.networking.net.
networking.net IN SOA ns1.networking.net. admin.networking.net. (
    2023120304 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
networking.net IN PTR networking.net.
networking.net IN TXT "v=spf1 include:_spf.networking.net ~all"
networking.net IN CNAME alias.networking.net.
networking.net IN MG mailgroup@networking.net
networking.net IN MR mailrename@networking.net
networking.net IN NULL
networking.net IN HINFO "Intel" "i7"
networking.net IN HINFO "Ubuntu" "Linux"
networking.net IN MAILB mailbackup@networking.net


================================================
File: master_files/opensource_org.zone
================================================
$ORIGIN opensource.org.
$TTL 3600

opensource.org IN A 93.184.216.36
opensource.org IN A 93.184.216.37
opensource.org IN NS ns1.opensource.org.
opensource.org IN NS ns2.opensource.org.
opensource.org IN MX 10 mail.opensource.org.
opensource.org IN MX 20 backup.mail.opensource.org.
opensource.org IN SOA ns1.opensource.org. admin.opensource.org. (
    2023120303 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
opensource.org IN PTR 93.184.216.36.in-addr.arpa.
opensource.org IN PTR 93.184.216.37.in-addr.arpa.
opensource.org IN TXT "\"Open source is freedom.\""
opensource.org IN CNAME alias.opensource.org.
opensource.org IN HINFO ""AMD" "Ryzen" "Arch Linux""
opensource.org IN MINFO admin@opensource.org errors@opensource.org
opensource.org IN MB mailbox1.opensource.org.
opensource.org IN MG mailgroup@opensource.org
opensource.org IN MR mailrename@opensource.org
opensource.org IN NULL
opensource.org IN WKS 93.184.216.36 17 01020304
opensource.org IN MAILB backup-mail@opensource.org


================================================
File: master_files/techstartup_io.zone
================================================
$ORIGIN techstartup.io.
$TTL 3600

techstartup.io IN A 93.184.216.40
techstartup.io IN A 93.184.216.41
techstartup.io IN NS ns1.techstartup.io.
techstartup.io IN NS ns2.techstartup.io.
techstartup.io IN MX 10 mail.techstartup.io.
techstartup.io IN MX 20 backup.mail.techstartup.io.
techstartup.io IN SOA ns1.techstartup.io. admin.techstartup.io. (
    2023120307 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
techstartup.io IN PTR 93.184.216.40.in-addr.arpa.
techstartup.io IN PTR 93.184.216.41.in-addr.arpa.
techstartup.io IN TXT "\"Startups rule!\""
techstartup.io IN CNAME alias.techstartup.io.
techstartup.io IN HINFO ""Intel" "i9" "Debian Linux""
techstartup.io IN MINFO admin@techstartup.io errors@techstartup.io
techstartup.io IN MB mailbox1.techstartup.io.
techstartup.io IN MG mailgroup@techstartup.io
techstartup.io IN MR mailrename@techstartup.io
techstartup.io IN NULL
techstartup.io IN WKS 93.184.216.40 6 01020304
techstartup.io IN MAILB backup-mail@techstartup.io


================================================
File: master_files/university_edu.zone
================================================
$ORIGIN university.edu.
$TTL 3600

university.edu IN A 93.184.216.38
university.edu IN A 93.184.216.39
university.edu IN NS ns1.university.edu.
university.edu IN NS ns2.university.edu.
university.edu IN MX 10 mail.university.edu.
university.edu IN MX 20 backup.mail.university.edu.
university.edu IN SOA ns1.university.edu. admin.university.edu. (
    2023120305 ; Serial
    7200 ; Refresh
    3600 ; Retry
    1209600 ; Expire
    86400 ; Minimum TTL
)
university.edu IN PTR university.edu.
university.edu IN TXT "v=spf1 include:_spf.university.edu ~all"
university.edu IN CNAME alias.university.edu.
university.edu IN MG mailgroup@university.edu
university.edu IN MR mailrename@university.edu
university.edu IN NULL
university.edu IN WKS 93.184.216.38 6 01020304
university.edu IN HINFO "Intel" "i7"
university.edu IN HINFO "Ubuntu" "Linux"
university.edu IN MAILB mailbackup@university.edu


