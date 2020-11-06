#!/usr/bin/env python3
"""Python tracert implementation using ICMP"""
import argparse
import logging
import os
import socket
import struct
import time

ECHO_REQUEST_CODE = 0
ECHO_REQUEST_TYPE = 8
ATTEMPTS = 3


def checksum(pkt_bytes: bytes) -> int:
    """ 
    Calculate checksum
    :param pkt_bytes: packet bytes
    :returns checksum as an integer
    """
    s = 0
    if len(pkt_bytes) % 2:
        pkt_bytes += b"\00"
    for i in range(0, len(pkt_bytes), 2):
        w = (pkt_bytes[i] << 8) + pkt_bytes[i + 1]
        s = ((s + w) & 0xFFFF) + ((s + w) >> 16)
    return ~s & 0xFFFF


def format_request(req_id: int, seq_num: int) -> bytes:
    """
    Format an Echo request
    :param req_id: request id
    :param seq_num: sequence number
    :returns properly formatted Echo request
    """
    data = b"VOTE!"
    header = struct.pack(
        "!BBHHH",
        ECHO_REQUEST_TYPE,
        ECHO_REQUEST_CODE,
        0,
        req_id, 
        seq_num
    )
    header = struct.pack(
        "!BBHHH",
        ECHO_REQUEST_TYPE,
        ECHO_REQUEST_CODE,
        checksum(header + data),
        req_id,
        seq_num,
    )
    return header + data


def send_request(sock: socket, pkt_bytes: bytes, addr_dst: str, ttl: int) -> float:
    """
    Send an Echo Request
    :param sock: socket to use
    :param pkt_bytes: packet bytes to send
    :param addr_dst: destination address
    :param ttl: ttl of the packet
    :returns current time
    """
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack("I", ttl))
    sock.sendto(pkt_bytes, (addr_dst, 33434))
    return time.time()


def receive_reply(sock: socket) -> tuple:
    """
    Receive an ICMP reply
    :param sock: socket to use
    :returns a tuple of the received packet bytes, responder's address, and current time
    """
    pkt_bytes, addr = sock.recvfrom(1024)
    return pkt_bytes, addr, time.time()
    

def parse_reply(pkt_bytes: bytes) -> None:
    """
    Parse an ICMP reply
    :param pkt_bytes: data received from the wire
    """
    expected_types_and_codes = {0: [0], 3: [0, 1, 3], 8: [0], 11: [0]}
    data = pkt_bytes[28:]
    header = pkt_bytes[20:28]
    repl_type, repl_code, repl_checksum, repl_id, sequence = struct.unpack(
        "!BBHHH", header
    )
    if repl_type not in expected_types_and_codes:
        raise ValueError("Incorrect type {} received ".format(repl_type) + "instead of {}".format(', '.join([str(t) for t in expected_types_and_codes])))
    if repl_code not in expected_types_and_codes[repl_type]:
        raise ValueError("Incorrect code {} received with type {}".format(repl_code,repl_type)
    )
    if checksum(header + data) != 0:
        raise ValueError(
            "Incorrect checksum {} received ".format(hex(repl_checksum)[2:]) + "instead of {}".format(hex(checksum(header + data))[2:])
        )


def traceroute(hostname: str, max_hops: int = 30) -> None:
    """
    Trace the route to a domain
    :param hostname: host name
    :param max_hops: max hops
    """
    dest_addr = socket.gethostbyname(hostname)
    # Print title
    print("\nTracing route to {} [{}] ".format(hostname,dest_addr)+ "over a maximum of {} hops. \n".format(max_hops))

    # Set up request id
    req_id = os.getpid() & 0xFFFF
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")) as sock:
        ttl = 0
        destination_reached = False
        sock.settimeout(1)

        # Loop until the destination is reached
        while ttl < max_hops and not destination_reached:
            ttl += 1
            print(f"{ttl:>3d}   ", end="")
            seq_id = 0
            comment = ""
            for _ in range(ATTEMPTS):
                seq_id += 1
                # Format and send request
                pkt_out = format_request(req_id, seq_id)
                time_sent = send_request(sock, pkt_out, dest_addr, ttl)
                # Parse response
                try:
                    pkt_in, resp_addr, time_rcvd = receive_reply(sock)
                    parse_reply(pkt_in)
                    # Provide domain name if possible
                    try:
                        comment = f"{socket.gethostbyaddr(resp_addr[0])[0]} [{resp_addr[0]}]"
                    except:
                        comment = resp_addr[0]
                # If ValueError print ! and make comment
                except ValueError as val_err:
                    print(f"{'!':>3s}      ", end="")                    
                    comment = (comment if comment else f"Error while parsing the response: {str(val_err)}")
                    continue
                
                # If Timeout print * and make comment
                except (socket.timeout, TimeoutError) as to_err:
                    print(f"{'*':>3s}      ", end="")  
                    comment = (comment if comment else f"Request timed out: {str(to_err)}")
                    continue
                    
                # If there are no errors
                rtt = (time_rcvd - time_sent) * 1000
                
                # Show rtt if greater than 1 ms
                if rtt > 1:
                    print(f"{rtt:>3.0f} ms   ", end="")
                else:
                    print(f"{'<1':>3s} ms   ", end="")

                # If we reach the destination, let's stop
                if resp_addr[0] == dest_addr:
                    destination_reached = True
            print(comment)

    print("\nTrace complete.")

def main():
    """Main function"""
    arg_parser = argparse.ArgumentParser(description="Parse arguments")
    arg_parser.add_argument("server", type=str, help="Server to ping")
    arg_parser.add_argument( "-d", "--debug", action="store_true", help="Enable logging.DEBUG mode")
    args = arg_parser.parse_args()
    logger = logging.getLogger("root")
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    
    traceroute(args.server)

if __name__ == "__main__":
    main()
