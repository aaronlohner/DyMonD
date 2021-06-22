import socket
import struct
from proto_gen import sniffed_info_pb2
from proto_gen.sniffed_info_pb2 import FlowArray, Flow
from script import node, edge

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8080        # The port used by the server

def send_message(conn, mesg):#:socket):
    # sends IP address (for now, just send the network interface)
    # maybe also depth of call graph (int)
    conn.send(bytes(mesg.encode('utf-8')))
    print("Sent message")

def recv_message(conn, msg_type):# -> FlowArray:
    """ Receive a message, prefixed with its size, from a TCP/IP socket """
    # Receive the size of the message data
    data = b''
    # Convention is that first 4 bytes contain size of message to follow
    # recv() seems to wait until buffer is nonempty
    size = conn.recv(4)
    # Trigger to stop waiting for server message is when incoming message size is 0
    #if int.from_bytes(size, "big") == 0:
    #   return None
    # Receive the message data
    try:
        data = conn.recv(struct.unpack('>i', size)[0])
    except Exception as e:
        print('Exiting')
        return
    # Decode the message
    msg = msg_type()
    msg.ParseFromString(data)
    # Create a Flow object and populate it with received data
    return msg

def generate_graph(flow_array, nodes, edges, newNode1, newNode2, id1, id2):#:FlowArray, nodes, edges, newNode1, newNode2, id1, id2):
    node1 = flow_array.flows[0].s_addr
    node2 = flow_array.flows[0].d_addr
    #print(f'{node1}, {node2}')
    print('%s, %s' % (node1, node2))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
live = None
while live != 'L' or live != 'O':
    live = raw_input("Type 'L' for live mode, 'O' for offline mode: ")
if live == 'L':
    txt = raw_input("Enter the Network Interface name: ")
else:
    txt = raw_input("Enter the file name (must be a .pcap file directly in the DyMonD folder) or leave blank to use teastoreall.pcap: ")
    if txt is None:
        txt = "teastoreall.pcap"
send_message(s, txt)
response = recv_message(s, sniffed_info_pb2.FlowArray)
# generate_graph(response, None, None, None, None, None, None)
while response is not None:
    # Assuming that the incoming response type is a protobuf FlowArray object
    for i, flow in enumerate(response.flows):
        #print(f'Received #{i+1}: {flow.s_addr}:{flow.s_port} {flow.d_addr}:{flow.d_port} {flow.num_bytes}-{flow.rst}')
        print('Received #%d: %s:%s %s:%s %d-%f' % (i+1, flow.s_addr, flow.s_port, flow.d_addr, flow.d_port, flow.num_bytes, flow.rst))
    response = recv_message(s, sniffed_info_pb2.FlowArray)
s.close()
