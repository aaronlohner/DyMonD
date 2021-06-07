#!/usr/bin/env python3

import socket
from proto_gen import sniffed_info_pb2
from google.protobuf.internal.decoder import _DecodeVarint


HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8080        # The port used by the server

def decode_varint(data):
    """ Decode a protobuf varint to an int """
    return _DecodeVarint(data, 0)[0]

def recv_message(conn, msg_type):
    """ Receive a message, prefixed with its size, from a TCP/IP socket """
    # Receive the size of the message data
    data = b''
    # while True:
    #     try:
    #         data += conn.recv(1)
    #         size = decode_varint(data)
    #         break
    #     except IndexError:
    #         pass
    # Receive the message data
    data = conn.recv(1024)#size)
    # Decode the message
    msg = msg_type()
    msg.ParseFromString(data)
    # Create a SearchRequest object and populate it with received data
    return msg

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    #s.sendall(b'Hello from Python client')
    #data = s.recv(1024)
    response = recv_message(s, sniffed_info_pb2.FlowInfo)
    while len(response.SerializeToString()) > 0:
        # Assuming that the incoming response type is a protobuf SearchRequest
        print(f'Received {response.s_addr}:{response.s_port} {response.d_addr}:{response.d_port} {response.num_bytes_30}-{response.rst}')
        response = recv_message(s, sniffed_info_pb2.FlowInfo)