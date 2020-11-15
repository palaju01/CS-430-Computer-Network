#!/usr/bin/env python3
"""Router implementation using UDP sockets"""


import argparse
import logging
import pathlib
import random
import select
import socket
import struct
import time
import toml
from typing import Tuple, Set, Dict


THIS_HOST = None
BASE_PORT = 4300


def read_config_file(filename: str) -> Tuple[Set, Dict]:
    """
    Read config file

    :param filename: name of the configuration file
    :return tuple of the (neighbors, routing table)
    """
    try:
        with open(filename, "r") as conf_file:
            # read the entire file
            config_str = conf_file.read()
            # Split file into separate routers
            routers = config_str.split("\n\n")
            # create the set and dictionary
            neighbors = set()
            routing_table = {}
            for router in routers:
                router_list = list(router.split("\n"))
                if router_list[0] == THIS_HOST: 
                    for neighbor in router_list[1:]:
                        # check if there is any neighbor
                        if neighbor != "":
                            next_hop, cost = neighbor.split(" ")
                            neighbors.add(next_hop)
                            routing_table[next_hop] = [int(cost),next_hop]
            return neighbors,routing_table
    except IOError:
        raise FileNotFoundError("Could not find the specified configuration file {}".format(filename))


def format_update(routing_table: dict) -> bytes:
    """
    Format update message

    :param routing_table: routing table of this router
    :returns the formatted message
    """
    message = bytearray()
    message.append(0x0)

    for dest in routing_table:
        for num in dest.split("."):
            message.append(int(num))
        message.append(routing_table[dest][0])
    return message


def send_update(node: str, routing_table: dict) -> None:
    """
    Send update
    
    :param node: recipient of the update message
    :param routing_table: this router's routing table
    """
    if node in routing_table:
        # bind host IP with ICMP port
        this_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        this_socket.bind((THIS_HOST,0))
        destination_port = BASE_PORT + int(node.split(".")[-1])
        
        # format update and send it
        msg = format_update(routing_table)
        this_socket.sendto(msg, (node, destination_port))
        print("Sent update to {}".format(node))


def parse_update(msg: bytes, neigh_addr: str, routing_table: dict) -> bool:
    """
    Update routing table
    
    :param msg: message from a neighbor
    :param neigh_addr: neighbor's address
    :param routing_table: this router's routing table
    :returns True is the table has been updated, False otherwise
    """
    updated = False
    index = 1   # index
    while index < len(msg) - 1:
        addr = str(msg[index]) + "." + str(msg[index+1]) + "." + str(msg[index+2]) + "." + str(msg[index+3])
        cost = msg[index+4]
        if addr in routing_table:
            if routing_table[addr][0] > routing_table[neigh_addr][0]+cost:
                routing_table[addr] = [routing_table[neigh_addr][0]+cost, neigh_addr]
                updated = True
        elif addr != THIS_HOST:
            routing_table[addr] = [cost+routing_table[neigh_addr][0],neigh_addr]
            updated = True
        index += 5
    return updated


def format_hello(msg_txt: str, src_node: str, dst_node: str) -> bytes:
    """
    Format hello message
    
    :param msg_txt: message text
    :param src_node: message originator
    :param dst_node: message recipient
    """
    msg = bytearray()
    msg.append(0x1)

    # add source IP address
    for num in src_node.split("."):
        msg.append(int(num))
    # add destination IP address
    for num in dst_node.split("."):
        msg.append(int(num))
    # add encoded message
    msg = msg + bytearray(msg_txt.encode())

    return msg

def send_hello(msg_txt: str, src_node: str, dst_node: str, routing_table: dict) -> None:
    """
    Send a message

    :param mst_txt: message to send
    :param src_node: message originator
    :param dst_node: message recipient
    :param routing_table: this router's routing table
    """
    if dst_node in routing_table:
        # bind host IP with ICMP port
        this_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        this_socket.bind((THIS_HOST,0))
        destination_port = BASE_PORT + int(routing_table[dst_node][1].split(".")[-1])
        
        # format hello message and send it
        msg = format_hello(msg_txt, src_node, dst_node)
        this_socket.sendto(msg, (routing_table[dst_node][1], destination_port))
        print("Sent hello message to {}".format(dst_node))


def parse_hello(msg: bytes, routing_table: dict) -> str:
    """
    Parse the HELLO message

    :param msg: message
    :param routing_table: this router's routing table
    :returns the action taken as a string
    """
    sender = str(msg[1]) + "." + str(msg[2]) + "." + str(msg[3]) + "." + str(msg[4])
    destination = str(msg[5]) + "." + str(msg[6]) + "." + str(msg[7]) + "." + str(msg[8])
    data = msg[9:].decode()

    if destination == THIS_HOST:
            print("Received {} from {}".format(data,sender))
            return "Received {} from {}".format(data,sender)
    else:
        send_hello(data,sender,destination, routing_table)
        return "Forwarded {} to {}".format(data,routing_table[destination][1])


def print_status(routing_table: dict) -> None:
    """
    Print status

    :param routing_table: this router's routing table
    """
    print("   {:^14} {:^10} {:^14}".format("Host","Cost","Via"))
    for router in routing_table:
        print("   {:^14} {:^10} {:^14}".format(router,routing_table[router][0],routing_table[router][1]))


def format_status_request(dst_node: str) -> bytes:
    """
    Format update message

    :param dst_node: message recipient
    :returns the formatted message
    """
    address = list(dst_node.split("."))
    message = struct.pack("!BBBBB", 2, int(address[0]), int(address[1]), int(address[2]), int(address[3]))
    return message


def send_status_request(dst_node: str, routing_table: dict) -> None:
    """
    Send status request

    :param routing_table: routing table of this router
    """
    if dst_node in routing_table:
        # bind host IP with a port
        this_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        this_socket.bind((THIS_HOST,0))
        destination_port = BASE_PORT + int(routing_table[dst_node][1].split(".")[-1])
        
        # format status request message and send it
        msg = format_status_request(THIS_HOST)
        this_socket.sendto(msg, (routing_table[dst_node][1], destination_port))
        print("Sent status request to {}".format(dst_node))


def parse_status_request(msg: bytes, routing_table: dict) -> str:
    """
    Parse the HELLO message

    :param msg: message
    :param routing_table: this router's routing table
    :returns the action taken as a string
    """
    source = str(msg[1]) + "." + str(msg[2]) + "." + str(msg[3]) + "." + str(msg[4])
    print("Received status request from {}".format(source))
    send_status_response(source,routing_table)
    return "Received status request from {}".format(source)


def format_status_response(dst_node: str, routing_table: dict) -> bytes:
    """
    Format status response message

    :param routing_table: routing table of this router
    :returns the formatted message
    """
    message = bytearray()
    message.append(0x3)

    # add destination address
    for dst in list(dst_node.split(".")):
        message.append(int(dst))
    
    # add routing table data
    for dest in routing_table:
        message.append(routing_table[dest][0])
        for num in dest.split("."):
            message.append(int(num))
    return message


def send_status_response(dst_node: str, routing_table: dict) -> None:
    """
    Send status response message

    :param routing_table: routing table of this router
    """
    if dst_node in routing_table:
        #print(dst_node, routing_table)
        # bind host IP with a port
        this_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        this_socket.bind((THIS_HOST,0))
        destination_port = BASE_PORT + int(routing_table[dst_node][1].split(".")[-1])
        
        # format status request message and send it
        msg = format_status_response(dst_node,routing_table)
        this_socket.sendto(msg, (routing_table[dst_node][1], destination_port))
        print("Sent status response to {}".format(dst_node))


def parse_status_response(msg: bytes, routing_table: dict) -> str:
    """
    Parse the HELLO message

    :param msg: message
    :param routing_table: this router's routing table
    :returns the action taken as a string
    """
    destination = str(msg[1]) + "." + str(msg[2]) + "." + str(msg[3]) + "." + str(msg[4])
    if destination == THIS_HOST:
            print("Received status response")
            return "Received status response"
    else:
        send_status_response(destination,routing_table)
        return "Forwarded status response to {}".format(routing_table[destination][1])


def route(neighbors: set, routing_table: dict, timeout: int = 5):
    """
    Router's main loop

    :param neighbors: this router's neighbors
    :param routing_table: this router's routing table
    :param timeout: default 5
    """
    ubuntu_release = [
        "Groovy Gorilla",
        "Focal Fossa",
        "Eoam Ermine",
        "Disco Dingo",
        "Cosmic Cuttlefish",
        "Bionic Beaver",
        "Artful Aardvark",
        "Zesty Zapus",
        "Yakkety Yak",
        "Xenial Xerus",
    ]
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((THIS_HOST, BASE_PORT + int(THIS_HOST.split(".")[-1])))

    # print router status 
    print_status(routing_table)

    while True:
        # The following section determines when to "randomly" send messages to other routers.

        rand = random.randrange(0,20)
        # random hello message
        if rand == 5:
            #print("random hello message")
            msg = random.choice(ubuntu_release)
            dst = random.choice(list(routing_table.keys()))
            send_hello(msg,THIS_HOST,dst,routing_table)
        # random update message
        elif rand == 10:
            #print("random update message")
            dst = random.choice(list(routing_table.keys()))
            send_update(dst,routing_table)
        # random status request message - optional
        elif rand == 15:
            #print("random status request")
            dst = random.choice(list(routing_table.keys()))
            send_status_request(dst,routing_table)


        # The following section process incoming messages from other routers.

        new_messages = select.select([listener], [], [], timeout)

        for sckt in new_messages[0]:
            msg, addr = sckt.recvfrom(1024)
            if msg[0] == 0:
                # Update message
                updated = parse_update(msg, addr[0], routing_table)
                if updated:
                    print_status(routing_table)
                    for neighbor in neighbors:
                        send_update(neighbor,routing_table)
            elif msg[0] == 1:
                # Hello message
                parse_hello(msg, routing_table)
            elif msg[0] == 2:
                # Status request
                parse_status_request(msg, routing_table)
            elif msg[0] == 3:
                # Status response
                parse_status_response(msg, routing_table)

            # If the type is not 0 to 3, the packet will be dropped.

def main():
    """Main function"""
    arg_parser = argparse.ArgumentParser(description="Parse arguments")
    arg_parser.add_argument("router_address", help="IP for new router")
    arg_parser.add_argument("-c", "--configuration", default="data/projects/routing/network_simple.txt", help="Path to configuration file")
    arg_parser.add_argument("-d", "--debug", action="store_true", help="Enable logging.DEBUG mode")
    args = arg_parser.parse_args()

    logger = logging.getLogger("root")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)

    # set up the router IP address
    global THIS_HOST
    THIS_HOST = args.router_address

    # read configuration file
    neighbors,routing_table = read_config_file(args.configuration)

    # start the router
    route(neighbors,routing_table)

if __name__ == "__main__":
    main()
