import sys
import socket
from proto_gen import sniffed_info_pb2
from proto_gen.sniffed_info_pb2 import FlowArray, Flow

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 8080         # The port used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def send_message(mesg:str) -> None:
    """Send a message though the TCP socket."""
    mesg = bytes(mesg.encode('utf-8'))
    length = sys.getsizeof(mesg)
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
from time import sleep

def setup_client(mode:chr, arg:str, tcp:str):
    s.connect((HOST, PORT))
    send_message(mode + tcp)
    sleep(0.1)
    send_message(arg)

    
def stop_client():
    s.close()
    print("Disconnected from server")

