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


