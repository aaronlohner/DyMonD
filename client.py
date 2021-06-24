import sys
import socket
from proto_gen import sniffed_info_pb2
from proto_gen.sniffed_info_pb2 import FlowArray, Flow
from script import node, edge

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8080         # The port used by the server

def send_message(conn:socket, mesg:str) -> None:
    """Send a message though the TCP socket."""
    mesg = bytes(mesg.encode('utf-8'))
    length = sys.getsizeof(mesg)
    # First send the message length
    conn.send(length.to_bytes(4, byteorder="big"))
    conn.send(mesg)
    print("Sent message")

def recv_message(conn:socket, msg_type) -> FlowArray:
    """Receive a message, prefixed with its size, from a TCP socket."""
    data = b''
    # Convention is that first 4 bytes contain size of message to follow
    size = conn.recv(4)
    # Stop waiting for server to send messages when receive an incoming message of size 0
    if int.from_bytes(size, "big") == 0:
        print("Exiting")
        return None
    data = conn.recv(int.from_bytes(size, "big"))
    # Create object of specified type to store received data
    msg = msg_type()
    msg.ParseFromString(data)
    return msg

def generate_graph(flow_array:FlowArray, nodes, edges, newNode1, newNode2, id1, id2):
    node1 = flow_array.flows[0].s_addr
    node2 = flow_array.flows[0].d_addr
    print(f'{node1}, {node2}')


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    mode = None
    while mode != 'l' and mode != 'o':
        mode = input("Type 'l' for live mode, 'o' for offline mode: ")
    send_message(s, mode)

    if mode == 'l':
        txt = input("Enter the Network Interface name or leave blank to use e69b93ccc8384_l: ")
        if len(txt) == 0:
            txt = "e69b93ccc8384_l"
    else:
        txt = input("Enter the file name (must be a .pcap file in the captures folder) or leave blank to use teastoreall.pcap: ")
        if len(txt) == 0:
            txt = "teastoreall.pcap"
    send_message(s, txt)
    
    response = recv_message(s, sniffed_info_pb2.FlowArray)
    # generate_graph(response, None, None, None, None, None, None)
    while response is not None:
        # Assuming that the incoming response type is a protobuf FlowArray object
        for i, flow in enumerate(response.flows):
            print(f'Received #{i+1}: {flow.s_addr}:{flow.s_port} {flow.d_addr}:{flow.d_port} {flow.num_bytes}-{flow.rst}')
        response = recv_message(s, sniffed_info_pb2.FlowArray)
