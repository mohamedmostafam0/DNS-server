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
        
