import sys
import socket
from time import sleep
from proto_gen.sniffed_info_pb2 import FlowArray, Flow

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 9080         # The port used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def send_message(mesg:str) -> None:
    """Send a message though the TCP socket."""
    mesg = bytes(mesg.encode('utf-8'))
    length = sys.getsizeof(mesg)
    # First send the message length
    s.send(length.to_bytes(4, byteorder="big"))
    s.send(mesg)
    print("Sent message")

def recv_message() -> FlowArray: # IF INCOMING MESSAGE IS PROTOBUF: recv_message(mesg_type) -> FlowArray:
    """Receive a message, prefixed with its size, from a TCP socket."""
    data = b''
    # Convention is that first 4 bytes contain size of message to follow
    size = s.recv(4)
    # Stop waiting for server to send messages when receive an incoming message of '0'
    if int.from_bytes(size, "big") == 0:
        return None
    data = s.recv(int.from_bytes(size, "big"))
    data = data.decode("utf-8").split("\n")
    # # Create object of specified type to store received data
    # msg = msg_type()
    # sleep(0.01) -- MAY NEED TO INCLUDE IF EXPERIENCING PARSING/DECODE ERRORS
    # msg.ParseFromString(data)
    msg = FlowArray()
    for line in data:
        if len(line) > 0:
            flow = Flow()
            line = line.split()
            flow.s_addr, flow.s_port, flow.d_addr, flow.d_port = line[0:4]
            flow.num_bytes = int(line[4])
            if line[5] == "1":
                flow.is_server = True
            else:
                flow.is_server = False
            flow.service_type = line[6]
            flow.rst = float(line[7])
            msg.flows.append(flow)
    return msg

def recv_message_test() -> str:
    sleep(0.001)
    data = b''
    # Convention is that first 4 bytes contain size of message to follow
    size = s.recv(4)
    # Stop waiting for server to send messages when receive an incoming message of '0'
    if int.from_bytes(size, "big") == 0:
        return None
    data = s.recv(int.from_bytes(size, "big")).decode("utf-8")
    return data

def setup_client(mode:str, log:str, host):
    if host is None:
        s.connect((HOST, PORT))
    else:
        print("Attempting to connect to sniffer on host address " + host)
        s.connect((host, PORT))
    send_message(mode)
    sleep(0.2)
    send_message(log)

def sniff(arg:str):
    sleep(0.2)
    send_message(arg)
    

def stop_client():
    send_message("stop") # ad hoc stopping signal
    s.close()
    print("Disconnected from server")

