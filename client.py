#!/usr/bin/env python3

import socket
from proto_gen import sniffed_info_pb2

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8080        # The port used by the server

def recv_message(conn, msg_type):
    """ Receive a message, prefixed with its size, from a TCP/IP socket """
    # Receive the size of the message data
    data = b''
    size = conn.recv(4) # convention that first 4 bytes contain size of message to follow
    # Trigger to stop waiting for server message is when incoming message size is 0
    if int.from_bytes(size, "big") == 0:
        return None
    # Receive the message data
    data = conn.recv(int.from_bytes(size, "big"))
    # Decode the message
    msg = msg_type()
    msg.ParseFromString(data)
    # Create a FlowInfo object and populate it with received data
    return msg

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    response = recv_message(s, sniffed_info_pb2.FlowInfo)
    while response is not None:
        # Assuming that the incoming response type is a protobuf FlowInfo object
        print(f'Received {response.s_addr}:{response.s_port} {response.d_addr}:{response.d_port} {response.num_bytes_30}-{response.rst}')
        response = recv_message(s, sniffed_info_pb2.FlowInfo)