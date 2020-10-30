#!/usr/bin/env python3
# encoding: UTF-8
"""Python Pinger"""

import binascii
import os
import select
import struct
import sys
import time
import socket
from statistics import mean, stdev

ECHO_REQUEST_TYPE = 8
ECHO_REPLY_TYPE = 0
ECHO_REQUEST_CODE = 0
ECHO_REPLY_CODE = 0
REGISTRARS = ["afrinic.net", "apnic.net", "arin.net", "lacnic.net", "ripe.net"]
# REGISTRARS = ["example.com"]


def print_raw_bytes(pkt: bytes) -> None:
    """Printing the packet bytes"""
    for i in range(len(pkt)):
        sys.stdout.write("{:02x} ".format(pkt[i]))
        if (i + 1) % 16 == 0:
            sys.stdout.write("\n")
        elif (i + 1) % 8 == 0:
            sys.stdout.write("  ")
    sys.stdout.write("\n")


def checksum(pkt: bytes) -> int:
    """Calculate checksum"""
    csum = 0
    count = 0
    count_to = (len(pkt) // 2) * 2

    while count < count_to:
        this_val = (pkt[count + 1]) * 256 + (pkt[count])
        csum = csum + this_val
        csum = csum & 0xFFFFFFFF
        count = count + 2

    if count_to < len(pkt):
        csum = csum + (pkt[len(pkt) - 1])
        csum = csum & 0xFFFFFFFF

    csum = (csum >> 16) + (csum & 0xFFFF)
    csum = csum + (csum >> 16)
    result = ~csum
    result = result & 0xFFFF
    result = result >> 8 | (result << 8 & 0xFF00)

    return result


def parse_reply(my_socket: socket.socket, req_id: int, timeout: int, addr_dst: str) -> tuple:
    """Receive an Echo reply"""
    time_left = timeout
    while True:
        started_select = time.time()
        what_ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if what_ready[0] == []:  # Timeout
            raise TimeoutError("Request timed out after 1 sec")

        time_rcvd = time.time()
        pkt_rcvd, addr = my_socket.recvfrom(1024)
        if addr[0] != addr_dst:
            raise ValueError("Wrong sender. Expected {}, received from {}".format(addr_dst,addr[0]))
        # Extract ICMP header from the IP packet and parse it
        #print_raw_bytes(pkt_rcvd)
        _,_,packet_size,_,_,ttl,_,_,destination_address,_ = struct.unpack('!BBHHHBBH4s4s',pkt_rcvd[:20])
        icmp_header = struct.unpack('!bbHHhd',pkt_rcvd[20:])
        #print("type,code,checksum,identificator,sequence number, time")
        #print(icmp_header)
        # Convert bytes to destination address
        destination_address = ".".join(map(str,struct.unpack("BBBB",destination_address)))
        if icmp_header[0] != 0: # Incorrect type
            raise ValueError("Incorrect type. Expected 0, received {}".format(icmp_header[0]))
        elif icmp_header[1] != 0: # Incorrect code
            raise ValueError("Incorrect code. Expected 0, received {}".format(icmp_header[1]))
        elif icmp_header[2] != checksum(pkt_rcvd[20:22]+pkt_rcvd[24:]): # Incorrect checksum
            raise ValueError("Incorrect checksum. Expected {}, received {}".format(checksum(pkt_rcvd[20:22]+pkt_rcvd[24:]),icmp_header[2]))
        elif req_id != icmp_header[3]: # Incorrect id
            raise ValueError("Incorrect id. Expected {}, received {}".format(req_id,icmp_header[3]))
        else:
            return (addr_dst,packet_size,(time_rcvd-icmp_header[5])*1000,ttl,icmp_header[4])
        #print(ip_header)
        #print(icmp_header)
        
        # DONE: End of ICMP parsing
        time_left = time_left - how_long_in_select
        if time_left <= 0:
            raise TimeoutError("Request timed out after 1 sec")


def format_request(req_id: int, seq_num: int) -> bytes:
    """Format an Echo request"""
    my_checksum = 0
    header = struct.pack(
        "!bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    data = struct.pack("!d", time.time())
    my_checksum = checksum(header + data)

    #if sys.platform == "darwin":
    #    my_checksum = socket.htons(my_checksum) & 0xFFFF
    #else:
    #    my_checksum = socket.htons(my_checksum)

    header = struct.pack(
        "!bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    packet = header + data
    return packet


def send_request(addr_dst: str, seq_num: int, timeout: int = 1) -> tuple:
    """Send an Echo Request"""
    result = None
    proto = socket.getprotobyname("icmp")
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    my_id = os.getpid() & 0xFFFF
    packet = format_request(my_id, seq_num)
    my_socket.sendto(packet, (addr_dst, 1))

    try:
        result = parse_reply(my_socket, my_id, timeout, addr_dst)
    except ValueError as ve:
        print(f"Packet error: {ve}")
    finally:
        my_socket.close()
    return result


def ping(host: str, pkts: int, timeout: int = 1) -> None:
    """Main loop"""
    # print title
    ip = socket.gethostbyname(host)
    print("\n--- Ping {} ({}) using Python ---\n".format(host,ip))
    transmitted = 0
    received = 0
    times = []
    for request_id in range(pkts):
        sequence_num = (request_id+1) * 0x01
        try:
            transmitted += 1
            data_list = send_request(ip, sequence_num, timeout)
            received += 1
            times.append(data_list[2])
            print("{} bytes from {}: icmp_seq={} TTL={} time={} ms".format(data_list[1],data_list[0],data_list[4],data_list[3],str(round(data_list[2],2))))
        except TimeoutError:
            print("No response: Request timed out after {} sec".format(timeout))
    
    print("\n--- {} ping statistics ---".format(host))
    print("{} packets transmitted, {} received, {}% packet loss".format(transmitted,received,int(100*((transmitted-received)/transmitted))))
    
    if received != 0:
        print("rtt min/avg/max/mdev = {}/{}/{}/{} ms".format(round(min(times),3),\
        round(mean(times),3), round(max(times),3), round(stdev(times),3)))
    return


if __name__ == "__main__":
    for rir in REGISTRARS:
        ping(rir, 5)
