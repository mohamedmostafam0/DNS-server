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
