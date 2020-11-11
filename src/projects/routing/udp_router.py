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

    #print("Update Message:", msg)
    return message


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
                routing_table[addr][0] = routing_table[neigh_addr][0]+cost
                updated = True
        index += 5
    return updated


def send_update(node: str) -> None:
    """
    Send update
    
    :param node: recipient of the update message
    """
    raise NotImplementedError


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
        format_hello(data,sender,destination)
        return "Forwarded {} to {}".format(data,routing_table[destination][1])


def send_hello(msg_txt: str, src_node: str, dst_node: str, routing_table: dict) -> None:
    """
    Send a message

    :param mst_txt: message to send
    :param src_node: message originator
    :param dst_node: message recipient
    :param routing_table: this router's routing table
    """
    message = format_hello(msg_txt,src_node,dst_node)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message, (routing_table[dst_node][1], BASE_PORT))


def print_status(routing_table: dict) -> None:
    """
    Print status

    :param routing_table: this router's routing table
    """
    raise NotImplementedError


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
    raise NotImplementedError


def main():
    """Main function"""
    print("started")

if __name__ == "__main__":
    main()
