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







