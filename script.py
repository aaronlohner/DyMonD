import os
import sys
import re
import time
import random
from io import TextIOWrapper
from typing import Dict, Tuple, List
from client import setup_client, stop_client, recv_message, sniff
from proto_gen import sniffed_info_pb2
from proto_gen.sniffed_info_pb2 import FlowArray, Flow

# THIS SCRIPT WAS ORIGINALLY LOCATED WITHIN THE FOLDER webvowl1.1.7SE

#the script is to generate a json file that can be used in webvowl1.1.7SE
#input file is csv containing edges in the format of (Node1, Node2, connection information)
#change input on line #58 and output on line #59

nodes = {}
edges = {}

class node: #attributes of a node
    def __init__(self, ptype, pname, paddress, pPort, pcolor):
        self.type = ptype
        self.name = pname
        self.address = paddress
        self.port = pPort
        self.color = pcolor
    def __str__(self):
        return self.type + ", " + self.name + ", " + self.address + "\n"
    def __eq__(self, other):
        if self.type == other.type and self.address == other.address:
            return True
        else:
            return False

class edge: #attributes of an edge
    def __init__(self, ptype, pTH, pRST, pC, pdomain, prange):
        self.type = ptype
        self.TH = pTH
        self.RST = pRST
        self.C = pC
        self.domain = pdomain
        self.range = prange
    def __str__(self):
        return self.type + ", " + self.TH + ", " + str(self.RST) + ", " + self.domain + ", " + self.range + "\n"
    def __eq__(self, other):
        if self.type == other.type and self.range == other.range and self.domain == other.domain:
            return True
        else:
            return False
        
def randomColor(): #generate random light colors
    return "#"+''.join([(str)(hex(random.randint(80,255))).split("x")[1], (str)(hex(random.randint(80,255))).split("x")[1], (str)(hex(random.randint(80,255))).split("x")[1]])



def getName(label):#get the IPaddress of a node from name
    counter1 = 0
    counter2 = 0
    for counter1 in range(len(label)):
        if not label[counter1].isdigit():
            break
    for counter2 in range(len(label)):
        if label[counter2] == '/':
            break
    if counter2 == len(label)-1: counter2 = len(label)
    return label[0:counter1], label[counter1:len(label)].upper() # (port, service type)


def generate_graph_from_file(log:str):
    data = open(log, "r")#input

    newNode1 = None
    newNode2 = None
    id1 = None
    id2 = None

    for line in data:#read edge information
    #     if len(line.strip().split(" ")) == 3:
    #         node1, node2, weight = line.strip().split(" ")#node1: the first node; node2: the second node; weight: information
    #         node12=node1.split(":")[1]#seperate port and ip address
    #         node22=node2.split(":")[1]
    #         if node12.isdigit() and not node22.isdigit():#node 1 is client and node2 is server
    # #            newNode1 = node("owl:Class", node1, node1.split(":")[0], randomColor())
    #             newNode1 = node("owl:Class", "Client", node1.split(":")[0], node12, randomColor())
    #             newNode2 = node("owl:equivalentClass", getName(node22)[1], node2.split(":")[0], getName(node22)[0],randomColor())
    #         elif not node12.isdigit() and node22.isdigit():#node 1 is server and node2 is client
    #             newNode1 = node("owl:equivalentClass", getName(node12)[1], (node1.split(":")[0]), getName(node12)[0],randomColor())
    #             newNode2 = node("owl:Class", "Client", node2.split(":")[0], node22, randomColor())
    #         elif node12.isdigit() and node22.isdigit():#both nodes are not server
    #             newNode1 = node("owl:Class", "Unknown", node1.split(":")[0], node12,randomColor())
    #             newNode2 = node("owl:Class", "Unknown", node2.split(":")[0], node22,randomColor())
        if len(line.strip().split(" ")) == 4:
            node1, node2, service_type, weight = line.strip().split(" ")#node1: the first node; node2: the second node; weight: information
            node12=node1.split(":")[1]#seperate port and ip address
            node22=node2.split(":")[1]
            if service_type[-1] == 'C':#node 1 is client and node2 is server
    #            newNode1 = node("owl:Class", node1, node1.split(":")[0], randomColor())
                newNode1 = node("owl:Class", "Client", node1.split(":")[0], node12, randomColor())
                newNode2 = node("owl:equivalentClass", service_type[0:-2], node2.split(":")[0], node22,randomColor())
            elif service_type[-1] == 'S':#node 1 is server and node2 is client
                newNode1 = node("owl:equivalentClass", service_type[0:-2], (node1.split(":")[0]), node12,randomColor())
                newNode2 = node("owl:Class", "Client", node2.split(":")[0], node22, randomColor())
            else:#both nodes are not server
                newNode1 = node("owl:Class", "Unknown", node1.split(":")[0], node12,randomColor())
                newNode2 = node("owl:Class", "Unknown", node2.split(":")[0], node22,randomColor())
            if newNode1 not in nodes.values():#if node 1 is not included in graph
                id1 = len(nodes)
                nodes[len(nodes)] = newNode1#expand node list
                
                for key in nodes:#assign same color to nodes with same IPaddress; connect nodes with same IPaddress with an edged named "same address"
                    if nodes[key].address == newNode1.address and nodes[key].type == "owl:Class" and newNode1.type == "owl:equivalentClass":
                        newNode1.color = nodes[key].color
                        edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(key), str(id1))
                    elif nodes[key].address == newNode1.address and nodes[key].type == "owl:equivalentClass" and newNode1.type == "owl:Class":
                        newNode1.color = nodes[key].color
                        edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(id1), str(key))
            else:
                for key in nodes:
                    if nodes[key] == newNode1:
                        id1 = key
                        if nodes[key].name == "Unknown" and newNode1.name == "Client":
                            nodes[key].name = "Client"
                        break
                        
            if newNode2 not in nodes.values():#if node 2 is not included in graph
                id2 = len(nodes)
                nodes[len(nodes)] = newNode2#expand node list
                
                for key in nodes:#assign same color to nodes with same IPaddress
                    if nodes[key].address == newNode2.address and nodes[key].type == "owl:Class" and newNode2.type == "owl:equivalentClass":
                        newNode2.color = nodes[key].color
                        edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(key), str(id2))
                    elif nodes[key].address == newNode2.address and nodes[key].type == "owl:equivalentClass" and newNode2.type == "owl:Class":
                        newNode2.color = nodes[key].color
                        edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(id2), str(key))
            else:
                for key in nodes:
                    if nodes[key] == newNode2:
                        id2 = key
                        if nodes[key].name == "Unknown" and newNode2.name == "Client":
                            nodes[key].name = "Client"
                        break
                        
            if "-" in weight:#if edge information contains more than throughput, add more information to the edge
                th, rst = weight.split("-", 1)
                newEdge = edge("owl:ObjectProperty", th, rst,1, str(id1), str(id2))
            else:#only throughput
                th = weight
                newEdge = edge("owl:ObjectProperty", th,0,1, str(id1), str(id2))
            if newEdge not in edges.values():#add new edge
                edges[len(edges)] = newEdge
            else:
                for key in edges:#if edge in graph, add throughput to existed edge and increment connection
                    if edges[key] == newEdge:
                        edges[key].TH = str(int(edges[key].TH) + int(th))
                        edges[key].C = str(int(edges[key].C) + 1)
                        if rst:
                            # print(str(edges[key]) + str(rst))
                            oRST = float(edges[key].RST)
                            oC = int(edges[key].C)
                            edges[key].RST = str((oRST*(oC-1) + float(rst))/oC)
            rst = 0
            newNode1 = None
            newNode2 = None
            id1 = None
            id2 = None
    data.close()

def generate_graph(flow_array:FlowArray):
    newNode1 = None
    newNode2 = None
    id1 = None
    id2 = None

    for flow in flow_array.flows:
        # if flow.s_port.isdigit() and not flow.d_port.isdigit():#node 1 is client and node2 is server
        #     newNode1 = node("owl:Class", "Client", flow.s_addr, flow.s_port, randomColor())
        #     newNode2 = node("owl:equivalentClass", getName(flow.d_port)[1], flow.d_addr, getName(flow.d_port)[0],randomColor())
        # elif not flow.s_port.isdigit() and flow.d_port.isdigit():#node 1 is server and node2 is client
        #     newNode1 = node("owl:equivalentClass", getName(flow.s_port)[1], (flow.s_addr), getName(flow.s_port)[0],randomColor())
        #     newNode2 = node("owl:Class", "Client", flow.d_addr, flow.d_port, randomColor())
        # elif flow.s_port.isdigit() and flow.d_port.isdigit():#both nodes are not server
        #     newNode1 = node("owl:Class", "Unknown", flow.s_addr, flow.s_port,randomColor())
        #     newNode2 = node("owl:Class", "Unknown", flow.d_addr, flow.d_port,randomColor())

        # (ptype, pname (c/s), paddress, pPort, pcolor)
        # (port, service type)
        if not flow.is_server:#node 1 is client and node2 is server
            newNode1 = node("owl:Class", "Client", flow.s_addr, flow.s_port, randomColor())
            newNode2 = node("owl:equivalentClass", flow.service_type, flow.d_addr, flow.d_port, randomColor())
        else:#node 1 is server and node2 is client
            newNode1 = node("owl:equivalentClass", flow.service_type, flow.s_addr, flow.s_port, randomColor())
            newNode2 = node("owl:Class", "Client", flow.d_addr, flow.d_port, randomColor())
        if newNode1 not in nodes.values():#if node 1 is not included in graph
            id1 = len(nodes)
            nodes[len(nodes)] = newNode1#expand node list

            for key in nodes:#assign same color to nodes with same IPaddress; connect nodes with same IPaddress with an edged named "same address"
                if nodes[key].address == newNode1.address and nodes[key].type == "owl:Class" and newNode1.type == "owl:equivalentClass":
                    newNode1.color = nodes[key].color
                    edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(key), str(id1))
                elif nodes[key].address == newNode1.address and nodes[key].type == "owl:equivalentClass" and newNode1.type == "owl:Class":
                    newNode1.color = nodes[key].color
                    edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(id1), str(key))
        else:
            for key in nodes:
                if nodes[key] == newNode1:
                    id1 = key
                    if nodes[key].name == "Unknown" and newNode1.name == "Client":
                        nodes[key].name = "Client"
                    break
        
        if newNode2 not in nodes.values():#if node 2 is not included in graph
            id2 = len(nodes)
            nodes[len(nodes)] = newNode2#expand node list
            
            for key in nodes:#assign same color to nodes with same IPaddress
                if nodes[key].address == newNode2.address and nodes[key].type == "owl:Class" and newNode2.type == "owl:equivalentClass":
                    newNode2.color = nodes[key].color
                    edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(key), str(id2))
                elif nodes[key].address == newNode2.address and nodes[key].type == "owl:equivalentClass" and newNode2.type == "owl:Class":
                    newNode2.color = nodes[key].color
                    edges[len(edges)] = edge("owl:DatatypeProperty", "same address",0,0, str(id2), str(key))
        else:
            for key in nodes:
                if nodes[key] == newNode2:
                    id2 = key
                    if nodes[key].name == "Unknown" and newNode2.name == "Client":
                        nodes[key].name = "Client"
                    break

        newEdge = edge("owl:ObjectProperty", str(flow.num_bytes), str(flow.rst), 1, str(id1), str(id2))
        if newEdge not in edges.values():#add new edge
            edges[len(edges)] = newEdge
        else:
            for key in edges:#if edge in graph, add throughput to existed edge and increment connection
                if edges[key] == newEdge:
                    edges[key].TH = str(int(edges[key].TH) + int(flow.num_bytes))
                    edges[key].C = str(int(edges[key].C) + 1)
                    if flow.rst:
                        # print(str(edges[key]) + str(flow.rst))
                        oRST = float(edges[key].RST)
                        oC = int(edges[key].C)
                        edges[key].RST = str((oRST*(oC-1) + float(flow.rst))/oC)
        newNode1 = None
        newNode2 = None
        id1 = None
        id2 = None

def write_json_output(fname:str):
    print("Writing json output")
    output = open("json/" + fname + ".json", "w")#output
    output.write("{")
    output.write("\"class\":[")#write nodes
    for key in nodes:
        if key == 0:
            output.write("{\"id\": \"" + str(key) + "\",\n\"type\": \"" + nodes[key].type + "\"\n}")
        else:
            output.write(",\n{\"id\": \"" + str(key) + "\",\n\"type\": \"" + nodes[key].type + "\"\n}")
    output.write("],")
    output.write("\"classAttribute\":[")#write node attributes
    for key in nodes:
        if key == 0:
            output.write("{\"id\": \"" + str(key) + "\",\n\"label\": \"" + nodes[key].name + "\",\n\"comment\": {\n\"undefined\":\"" + nodes[key].address +"\\nPort: " + nodes[key].port + "\"\n},\n\"attributes\":[\n\"" + nodes[key].color + "\"\n]\n}")
        else:
            output.write(",\n{\"id\": \"" + str(key) + "\",\n\"label\": \"" + nodes[key].name + "\",\n\"comment\": {\n\"undefined\":\"" + nodes[key].address +"\\nPort: " + nodes[key].port +"\"\n},\n\"attributes\":[\n\"" + nodes[key].color + "\"\n]\n}")
    output.write("],")
    output.write("\"property\":[")#write edge 
    for key in edges:
        if key == 0:
            output.write("{\"id\": \"" + str(key) + "\",\n\"type\": \"" + edges[key].type + "\"\n}")
        else:
            output.write(",\n{\"id\": \"" + str(key) + "\",\n\"type\": \"" + edges[key].type + "\"\n}")
    output.write("],")
    output.write("\"propertyAttribute\":[")#write edge attributes
    for key in edges:
        if key == 0:
            if edges[key].TH == "same address":
                output.write("\n{\"id\": \"" + str(key) + "\",\n\"label\": \"" + edges[key].TH + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")
            elif float(edges[key].RST):
                output.write("{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH + ", RST: " + edges[key].RST + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")            
            else:
                output.write("{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH+ ", C: " + (str)(edges[key].C) + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")
        else:
            if edges[key].TH == "same address":
                output.write(",\n{\"id\": \"" + str(key) + "\",\n\"label\": \"" + edges[key].TH + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")
            elif float(edges[key].RST):
                output.write(",\n{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH + ", RST: " + edges[key].RST + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")  
            else:
                output.write(",\n{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH + ", C: " + (str)(edges[key].C) + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")
    output.write("]\n}")
    output.close()  

def load_interfaces_dictionary() -> Dict[str, str]:
    interfaces = {}
    with open("Interfaces.txt", "r") as f:
        for line in f:
            k, v = line.split()
            interfaces[k] = v
    return interfaces

def equal_flows(new_flow:Flow, flow:Flow) -> bool:
    if new_flow.s_addr == flow.s_addr and new_flow.s_port == flow.s_port and \
        new_flow.d_addr == flow.d_addr and new_flow.d_port == flow.d_port and \
            new_flow.is_server == flow.is_server and new_flow.service_type == flow.service_type:
            return True
    return False

def next_hop_extractor(new_flows_container, ip:str, visited:List[str]) -> Tuple[List[str], List[str]]:
    ips = []
    if type(new_flows_container) is not str:
        for flow in new_flows_container.flows:
            if flow.s_addr == ip:
                new_ip = flow.d_addr
                if new_ip not in visited:
                    ips.append(new_ip)
                    visited.append(new_ip)
    else:
        with open(new_flows_container, "r") as f:
            for line in f:
                if line.split(':')[0] == ip: # if flow has current ip as saddr
                    new_ip = line.split(' ')[1].split(':')[0]
                    if new_ip not in visited:
                        ips.append(new_ip)
                        visited.append(new_ip)
    return (ips, visited)

if __name__ == '__main__':
    arg_line = " ".join(sys.argv[1:])
    if re.match("-[if](\s+[\w.\-]*)?(\s+-w(\s+[\w.\-]*)?)?$", arg_line) is None:
        raise SystemExit(f"Usage: {sys.argv[0]} (-i | -f) <argument> <-w> <logfile>")

    arg = None
    if sys.argv[1] == "-i" and (len(sys.argv) == 2 or sys.argv[2] == "-w"):
        print("Using e69b93ccc8384_l")
        arg = "e69b93ccc8384_l" # default network interface from compute-04 node
    elif sys.argv[1] == "-f" and (len(sys.argv) == 2 or sys.argv[2] == "-w"):
        print("Using teastoreall.pcap")
        arg = "teastoreall.pcap" # default pcap file
    else:
        arg = sys.argv[2]

    log = "*"
    if "-w" in sys.argv:
        if sys.argv[-1] != "-w":
            log = sys.argv[-1]
        else:
            log = "log.txt"

    t = time.perf_counter()

    '''ORIGINAL VERSION
    setup_client(str(sys.argv[1][1]), str(arg), log)

    if log == "*": # special char to denote that there is no log to read from
        response = recv_message(sniffed_info_pb2.FlowArray)
        print("Received response from sniffer")
        generate_graph(response)
    else: # read from log
        # Proceed to read from logfile only when sniffer closes connection and sends a blank message,
        # indicating it is done writing to logfile
        recv_message(None) 
        print("Reading from file")
        generate_graph_from_file(log)
    '''

    '''NEW VERSION'''
    # Temporary implementation: dictionary mapping interfaces to ips,
    # use 'interfaces' dictionary to add ip of input interface to q and visited,
    # reverse-lookup interface from new found ips to pass in to sniff()
    interfaces = load_interfaces_dictionary()
    if log == "*":
        setup_client(sys.argv[1][1], log)
    else:
        setup_client(sys.argv[1][1], "temp-log.txt")
        log = "logs/" + log
        temp_log = "logs/temp-log.txt"
    if sys.argv[1] == "-f": # reading from pcap file
        sniff(arg)
        if log == "*": # special char to denote that there is no log to read from
            response = recv_message(sniffed_info_pb2.FlowArray)
            print("Received response from sniffer")
            generate_graph(response)
        else: # reading from log
            # Proceed to read from logfile only when sniffer closes connection and sends a
            # blank message, indicating it is done writing to logfile
            recv_message(None)
            print("Reading from file")
            generate_graph_from_file(log)
    else: # sniffing network interface
        q, visited = [interfaces[arg]], [interfaces[arg]]
        if log == "*": # if using tcp
            l = FlowArray()
            while len(q) > 0:
                print(f"ips in q: {q}")
                ip = q.pop(0)
                sniff(list(interfaces.keys())[list(interfaces.values()).index(ip)])#sniff(ip)
                f = recv_message(sniffed_info_pb2.FlowArray)
                print(f"num flows: {len(l.flows)}")
                if len(l.flows) == 0:
                    l.flows.extend(f.flows)
                else:
                    for new_flow in f.flows:
                        for flow in l.flows:
                            exists = False
                            if equal_flows(new_flow, flow):
                                exists = True
                                break
                        if not exists:
                            l.flows.append(new_flow)
                ips, visited = next_hop_extractor(f, ip, visited)
                q.extend(ips)
            stop_client()
            generate_graph(l)
        else: # if using log
            open(log, "w").close()
            lines_to_write = []
            while len(q) > 0:
                #print(f"ips in q: {q}")
                ip = q.pop(0)
                sniff(list(interfaces.keys())[list(interfaces.values()).index(ip)])#sniff(ip)
                recv_message(None)
                with open(log, "r") as l, open(temp_log, "r") as f:
                    # Add new flows to the main list
                    if os.stat(log).st_size == 0:
                            lines_to_write.extend(f)
                    else:
                        for new_line in f:
                            for line in l:
                                exists = False
                                if ' '.join(new_line.split(' ')[0:3]) in line:
                                    exists = True
                                    break
                            if not exists:
                                lines_to_write.append(new_line)
                            # else: overwrite existing line with sum of throughput, avg rst?
                            # doesn't that get done later anyway? maybe just append all new lines
                            # to master list, regardless of repeated lines?
                            l.seek(0)
                with open(log, "a") as f:
                    f.writelines(lines_to_write)
                ips, visited = next_hop_extractor(temp_log, ip, visited)
                q.extend(ips)
                lines_to_write.clear()
            stop_client()
            generate_graph_from_file(log)
        ''''''

    write_json_output("out")
    print(f"Elapsed time: {round(time.perf_counter() - t, 5)} seconds")
    # stop_client()