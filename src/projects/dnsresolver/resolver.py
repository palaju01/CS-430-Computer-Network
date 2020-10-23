#!/usr/bin/env python3
"""
DNS Resolver
"""

import argparse
import logging
from random import randint, choice
from socket import socket, SOCK_DGRAM, AF_INET
from typing import Tuple, List

PORT = 53

DNS_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "PTR": 12, "TXT": 16}

PUBLIC_DNS_SERVER = [
    "1.0.0.1",  # Cloudflare
    "1.1.1.1",  # Cloudflare
    "8.8.4.4",  # Google
    "8.8.8.8",  # Google
    "8.26.56.26",  # Comodo
    "8.20.247.20",  # Comodo
    "9.9.9.9",  # Quad9
    "64.6.64.6",  # Verisign
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
]


def val_to_2_bytes(value: int) -> Tuple[int]:
    """
    Split a value into 2 bytes
    Return the result as a tuple of 2 integers
    """
    return ((value >> 8) & 0xFF, value & 0xFF)


def val_to_n_bytes(value: int, n_bytes: int) -> Tuple[int]:
    """
    Split a value into n bytes
    Return the result as a tuple of n integers
    """
    bytesList = []
    while len(bytesList) < n_bytes:
        bytesList.insert(0, value & 0xFF)
        value = value >> 8
    return tuple(bytesList)


def bytes_to_val(byte_list: list) -> int:
    """Merge n bytes into a value"""
    value = 0
    for position, index in enumerate(range(len(byte_list),0,-1)):
        value += byte_list[index-1] << (8*position)
    return value


def get_2_bits(byte_list: list) -> int:
    """
    Extract first two bits of a two-byte sequence
    Return the result as a decimal value
    """
    num = bytes_to_val(byte_list)
    return num >> (len(bin(num)[2:])-2)


def get_domain_name_location(byte_list: list) -> int:
    """
    Extract size of the offset from a two-byte sequence
    Return the result as a decimal value
    """
    num = bytes_to_val(byte_list)
    return num & 0x3fff

def parse_cli_query(q_domain: str, q_type: str, q_server: str = None) -> Tuple[list, int, str]:
    """
    Parse command-line query
    Return a tuple of the domain (as a list of subdomains), numeric type, and the server
    If the server is not specified, pick a random one from `PUBLIC_DNS_SERVER`
    If type is not `A` or `AAAA`, raise `ValueError`
    """
    # split domain to list of subdomains
    subdomain = q_domain.split(".")

    # check if type is valid
    if not q_type:
        numericType = DNS_TYPES["A"]
    elif q_type == "A" or q_type == "AAAA":
        numericType = DNS_TYPES[q_type]
    else:
        raise ValueError("Unknown query type")
    
    # pick random server if it is not provided
    if q_server:
        server = q_server
    else:
        server = choice(PUBLIC_DNS_SERVER)
    return (subdomain,numericType,server)


def format_query(q_domain: list, q_type: int) -> bytearray:
    """
    Format DNS query
    Take the domain name (as a list) and the record type as parameters
    Return a properly formatted query
    Assumpions (defaults):
    - transaction id: random 0..65535
    - flags: recursive query set
    - questions: 1
    - class: Internet
    """
    query = bytearray()

    query.extend(val_to_2_bytes(randint(0,65535)))       # Add Transaction ID
    query.extend(val_to_2_bytes(0x100))                  # Add flags
    query.extend(val_to_2_bytes(1))                      # Add number of questions
    query.extend(val_to_2_bytes(0))                      # Add number of answers
    query.extend(val_to_2_bytes(0))                      # Add authority RRs
    query.extend(val_to_2_bytes(0))                      # Add additional RRs
    for subdomain in q_domain:
        query.extend(val_to_n_bytes(len(subdomain),1))   # Add length of subdomain
        for char in subdomain:
            query.extend(val_to_n_bytes(ord(char),1))    # Add each character in subdomain
    query.extend(val_to_n_bytes(0,1))                    # Terminate domain name
    query.extend(val_to_2_bytes(q_type))                 # Add type
    query.extend(val_to_2_bytes(0x0001))                 # Add class

    return query


def parse_response(resp_bytes: bytes) -> list:
    """
    Parse server response
    Take response bytes as a parameter
    Return a list of tuples in the format of (name, address, ttl)
    """
    # number of answers in response
    rr_ans = bytes_to_val(resp_bytes[6:8])

    # index of bytesarray where the answers start
    answer_start = 12
    while resp_bytes[answer_start] != 0:
        answer_start += 1
    answer_start += 5
    return parse_answers(resp_bytes, answer_start, rr_ans)


def parse_answers(resp_bytes: bytes, answer_start: int, rr_ans: int) -> List[tuple]:
    """
    Parse DNS server answers
    Take response bytes, offset, and the number of answers as parameters
    Return a list of tuples in the format of (name, address, ttl)
    """
    # List for tuples
    answers = []
    # Track the answer number
    currentAnswer = 1
    # Loop to retrieve each asnwer information
    while currentAnswer <= rr_ans:
        # Check whether the domain is given or it is a pointer
        pointer = resp_bytes[answer_start:answer_start+2]
        move = False
        if get_2_bits(pointer) == 3:         # if it is a pointer, then get the offset
            domainIndex = get_domain_name_location(pointer)
        else:                                # start from current position
            domainIndex = answer_start
            move = True
        
        subdomains = []
        while resp_bytes[domainIndex] != 0:
            subdomain = ""
            for _ in range(resp_bytes[domainIndex]):
                subdomain += chr(resp_bytes[domainIndex+1])
                domainIndex += 1
                if move:
                    answer_start += 1
            subdomains.append(subdomain)
            domainIndex += 1
        answer_start += 2
        if move:
            answer_start += 1
        domain = ".".join(subdomains)
        
        # Retrieve TTL
        ttl = int.from_bytes(resp_bytes[answer_start+4:answer_start+8],byteorder='big')

        # Retrieve address
        dataLength = int.from_bytes(resp_bytes[answer_start+8:answer_start+10],byteorder='big')
        if dataLength == 4:             # IPv4 request
            address = parse_address_a(4, resp_bytes[answer_start+10:answer_start+dataLength+11])
        else:             # IPv4 request
            address = parse_address_aaaa(16, resp_bytes[answer_start+10:answer_start+dataLength+11])


        answers.append((domain,address,ttl))

        # Position of first byte in the next answer
        answer_start += (10 + dataLength)
        currentAnswer += 1
    return answers


def parse_address_a(addr_len: int, addr_bytes: bytes) -> str:
    """
    Parse IPv4 address
    Convert bytes to human-readable dotted-decimal
    """
    return "{}.{}.{}.{}".format(addr_bytes[0],addr_bytes[1],addr_bytes[2],addr_bytes[3])


def parse_address_aaaa(addr_len: int, addr_bytes: bytes) -> str:
    """Extract IPv6 address"""
    address = ""
    index = 0
    while index <= 15:
        address += hex(int.from_bytes(addr_bytes[index:index+2], byteorder='big'))[2:]
        if index != 14:
            address += ":"
        index += 2
    return address


def resolve(query: tuple) -> None:
    """Resolve the query"""
    try:
        q_domain, q_type, q_server = parse_cli_query(*query)
    except ValueError as ve:
        print(ve.args[0])
        exit()
    logging.info(f"Resolving type {q_type} for {q_domain} using {q_server}")
    query_bytes = format_query(q_domain, q_type)
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(query_bytes, (q_server, PORT))
        response_data, _ = sock.recvfrom(2048)
    answers = parse_response(response_data)
    print(f"DNS server used: {q_server}")
    for a in answers:
        print()
        print(f"{'Domain:':10s}{a[0]}")
        print(f"{'Address:':10s}{a[1]}")
        print(f"{'TTL:':10s}{a[2]}")


def main():
    """Main function"""
    arg_parser = argparse.ArgumentParser(description="Parse arguments")
    # Required arguments
    #requiredArguments = arg_parser.add_argument_group('Required parse arguments')
    arg_parser.add_argument('domain', help='Domain name')
    # Optional arguments
    #optionalArguments = arg_parser.add_argument_group('Optional parse arguments')
    arg_parser.add_argument('-t', "--type", help='Type of request', required=False)
    arg_parser.add_argument('-s', "--server", help='Server used to resolve domain name', required=False)

    arg_parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable logging.DEBUG mode"
    )
    args = arg_parser.parse_args()

    logger = logging.getLogger("root")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)

    resolve((args.domain, args.type, args.server))


if __name__ == "__main__":
    main()
