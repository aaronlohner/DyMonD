import sys
import socket
from time import sleep
from proto_gen.sniffed_info_pb2 import FlowArray

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8080         # The port used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def send_message(mesg:str) -> None:
    """Send a message though the TCP socket."""
    #length = sys.getsizeof(mesg)
    mesg = bytes(mesg.encode('utf-8'))
    length = sys.getsizeof(mesg)
    print(f"Length: {length}")
    # First send the message length
    s.send(length.to_bytes(4, byteorder="big"))
    s.send(mesg)
    print("Sent message")

def recv_message(msg_type) -> FlowArray:
    """Receive a message, prefixed with its size, from a TCP socket."""
    data = b''
    # Convention is that first 4 bytes contain size of message to follow
    size = s.recv(4)
    # Stop waiting for server to send messages when receive an incoming message of size 0
    if int.from_bytes(size, "big") == 0:
        return None
    data = s.recv(int.from_bytes(size, "big"))
    # Create object of specified type to store received data
    msg = msg_type()
    msg.ParseFromString(data)
    return msg

''''''
def setup_client(mode:str, arg:str, log:str):
    s.connect((HOST, PORT))
    send_message(mode)
    sleep(0.2)
    send_message(arg)
    sleep(0.2)
    send_message(log)
''''''
'''
def setup_client(mode:chr):
    s.connect((HOST, PORT))
    send_message(mode)

def sniff(arg:str, log:str):
    send_message(arg)
    sleep(0.2)
    send_message(log)
'''
def stop_client():
    s.close()
    print("Disconnected from server")

