import sys
import socket
from time import sleep
from proto_gen.sniffed_info_pb2 import FlowArray, Flow

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 9080         # The port used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connected = False

def send_message(mesg:str) -> None:
    """Send a message though the TCP socket."""
    mesg = bytes(mesg.encode('utf-8'))
    length = sys.getsizeof(mesg)
    # First send the message length
    s.send(length.to_bytes(4, byteorder="big"))
    s.send(mesg)

def recv_message() -> FlowArray: # if using protobuf, this fcn should have a param called mesg_type
    """Receive a message, prefixed with its size, from a TCP socket."""
    data = b''
    # Convention is that first 4 bytes contain size of message to follow
    size = s.recv(4)
    # Stop waiting for server to send messages when receive an incoming message of '0'
    if int.from_bytes(size, "big") == 0:
        return None
    data = s.recv(int.from_bytes(size, "big"))
    data = data.decode("utf-8").split("\n")
    # If using protobuf: Create object of specified type to store received data
    # msg = msg_type()
    # sleep(0.01) #-- MAY NEED TO MODIFY IF EXPERIENCING DECODE ERRORS
    # msg.ParseFromString(data)
    msg = FlowArray()
    for line in data:
        flow = Flow()
        line = line.split()
        print(line)
        if len(line) == 0:
            continue
        flow.s_addr, flow.s_port, flow.d_addr, flow.d_port = line[0:4]
        flow.num_bytes = int(float(line[4]))
        if line[5] == "1":
            flow.is_server = True
        else:
            flow.is_server = False
        flow.service_type = line[6]
        flow.rst = float(line[7])
        msg.flows.append(flow)
    return msg

def setup_client(host):
    global connected
    if not connected:
        print("Setting up connection with agent...")
        if host is None or host == HOST:
            s.connect((HOST, PORT))
        else:
            print("Attempting to connect to agent on host address " + host)
            s.connect((host, PORT))
        connected = True

def sniff(mode:str, log:str, arg:str, time:int=8):
    """
    Sends data to agent to initiate application monitoring on one component or to read from a capture file.

    Args:
        mode (str): The framework usage mode (i for application monitoring or f for reading from file), not to be confused with TCP vs logging mode.
        log (str): The mode in which to send flows (* for TCP mode, else a filename for logging mode).
        arg (str): IP address of component to be monitored or name of pcap file to be read.
        time (int, optional): Number of seconds that component at IP address specified or capture file specified in arg will be monitored.

    Return:
        NoneType: None
    """
    sleep(0.2)
    if mode == 'f': # arg holds capture file name
        print("Requesting agent to sniff capture file {}".format(arg))
    else: # arg holds network interface of ip
        print("Requesting agent to sniff on IP address {}".format(arg))
    send_message(mode)
    sleep(0.2)
    send_message(log)
    sleep(0.2)
    send_message(arg)
    sleep(0.2)
    send_message(str(time))
    

def stop_client():
    print("Closing connection with agent")
    send_message("stop") # stopping signal
    s.close()
    print("Disconnected from agent")

