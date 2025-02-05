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

