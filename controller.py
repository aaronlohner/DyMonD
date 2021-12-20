import os
import argparse
import time
import random
import json
import os.path as osp
from typing import Tuple, List
from client import setup_client, stop_client, recv_message, recv_message_test, sniff
from proto_gen.sniffed_info_pb2 import FlowArray, Flow

from flask import Flask, request

app = Flask(__name__)
app.config["DEBUG"] = True

@app.route("/run", methods=['GET'])
def run():
    mode, log, host, arg, time, out = request.args.values()
    time = int(time)
    json_obj = run_startup(mode, log, host, arg, time, out)
    return json_obj

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
        
def reset_global_vars():
    global nodes; global edges
    nodes.clear(); edges.clear()

def randomColor(): #generate random light colors
    return "#"+''.join([(str)(hex(random.randint(80,255))).split("x")[1], (str)(hex(random.randint(80,255))).split("x")[1], (str)(hex(random.randint(80,255))).split("x")[1]])

def generate_graph_from_file(log:str):
    data = open(log, "r")#input

    newNode1 = None
    newNode2 = None
    id1 = None
    id2 = None

    for line in data:#read edge information
        if len(line.strip().split(" ")) == 4:
            node1, node2, service_type, weight = line.strip().split(" ")#node1: the first node; node2: the second node; weight: information
            node12=node1.split(":")[1]#seperate port and ip address
            node22=node2.split(":")[1]
            if service_type[-1] == 'C':#node 1 is client and node2 is server
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
                nodes[len(nodes)] = newNode1#expand node dictionary
                
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
                nodes[len(nodes)] = newNode2#expand node dictionary
                
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
                newEdge = edge("owl:ObjectProperty", th, str(round(float(rst), 3)),1, str(id1), str(id2))
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
                            oRST = float(edges[key].RST)
                            oC = int(edges[key].C)
                            edges[key].RST = str(round((oRST*(oC-1) + float(rst))/oC, 3))
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
        if flow.service_type == "Unknown": # neither node is client or server
            newNode1 = node("owl:Class", flow.service_type, flow.s_addr, flow.s_port, randomColor())
            newNode2 = node("owl:Class", flow.service_type, flow.d_addr, flow.d_port, randomColor())
        elif not flow.is_server:#node 1 is client and node2 is server
            newNode1 = node("owl:Class", "Client", flow.s_addr, flow.s_port, randomColor())
            newNode2 = node("owl:equivalentClass", flow.service_type, flow.d_addr, flow.d_port, randomColor())
        else:#node 1 is server and node2 is client
            newNode1 = node("owl:equivalentClass", flow.service_type, flow.s_addr, flow.s_port, randomColor())
            newNode2 = node("owl:Class", "Client", flow.d_addr, flow.d_port, randomColor())
        
        if newNode1 not in nodes.values():#if node 1 is not included in graph
            id1 = len(nodes)
            nodes[len(nodes)] = newNode1#expand node dictionary

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
            nodes[len(nodes)] = newNode2#expand node dictionary
            
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

        newEdge = edge("owl:ObjectProperty", str(flow.num_bytes), str(round(flow.rst, 3)), 1, str(id1), str(id2))
        if newEdge not in edges.values():#add new edge
            edges[len(edges)] = newEdge
        else:
            for key in edges:#if edge in graph, add throughput to existed edge and increment connection
                if edges[key] == newEdge:
                    edges[key].TH = str(int(edges[key].TH) + int(flow.num_bytes))
                    edges[key].C = str(int(edges[key].C) + 1)
                    if flow.rst:
                        oRST = float(edges[key].RST)
                        oC = int(edges[key].C)
                        edges[key].RST = str(round((oRST*(oC-1) + float(flow.rst))/oC, 3))
        newNode1 = None
        newNode2 = None
        id1 = None
        id2 = None

def write_json_output(fname:str):
    print("Producing call graph data")
    json_dict = {}
    json_dict["class"] = [{"id":str(key), "type":nodes[key].type} for key in nodes]
    json_dict["classAttribute"] = [{"id":str(key), "label":nodes[key].name, "comment":{"undefined":nodes[key].address + ", Port: " + nodes[key].port}, "attributes":[nodes[key].color]} for key in nodes]
    json_dict["property"] = [{"id":str(key), "type":edges[key].type} for key in edges]
    json_dict["propertyAttribute"] = [{"id":str(key), "label":edges[key].TH if edges[key].TH == "same address" else "TH: " + render_readable(int(edges[key].TH)) + ", ", "domain":edges[key].domain, "range":edges[key].range} for key in edges]
    for propAtt in json_dict["propertyAttribute"]:
        if propAtt["label"] != "same address":
            key = int(propAtt["id"])
            if float(edges[key].RST):
                propAtt["label"] += "RST: " + edges[key].RST
            else:
                propAtt["label"] += "C: " + str(edges[key].C)

    reset_global_vars()
    with open(osp.join("json", fname), "w") as f:
        json.dump(json_dict, f, indent=4)

    return json_dict

def render_readable(num:int) -> str:
    if num < 10000:
        return str(num)
    elif num < 100000:
        return str(round(num/1000, 1)) + "K"
    elif num < 1000000:
        return str(int(num/1000)) + "K"
    elif num < 10000000:
        return str(round(num/1000000, 1)) + "M"
    elif num < 1000000000:
        return str(int(num/1000000)) + "M"
    else:
        return str(round(num/1000000000, 0)) + "B"

def equal_flows(new_flow:Flow, flow:Flow) -> bool:
    if new_flow.s_addr == flow.s_addr and new_flow.s_port == flow.s_port and \
        new_flow.d_addr == flow.d_addr and new_flow.d_port == flow.d_port and \
            new_flow.is_server == flow.is_server and new_flow.service_type == flow.service_type:
            return True
    return False

def next_hop_extractor(new_flows_container, ip:str, visited:List[str], blacklisted_ips:List[str]=[]) -> Tuple[List[str], List[str]]:
    ips = []
    if type(new_flows_container) is not str:
        for flow in new_flows_container.flows:
            if flow.s_addr == ip:
                new_ip = flow.d_addr
                if new_ip not in visited and new_ip not in blacklisted_ips:
                    ips.append(new_ip)
                    visited.append(new_ip)
    else:
        with open(new_flows_container, "r") as f:
            for line in f:
                if line.split(':')[0] == ip: # if flow has current ip as saddr
                    new_ip = line.split(' ')[1].split(':')[0]
                    if new_ip not in visited and new_ip not in blacklisted_ips:
                        ips.append(new_ip)
                        visited.append(new_ip)
    return (ips, visited)

def run_startup(mode:str, log:str, host:str, arg:str, sniff_time:int, out:str): 
    
    log_orig = log
    temp_log = None
    if mode == "i" and log != "*": # if sniffing interface and using log
        # Sniffer will write to a temp log
        temp_log = os.path.join("logs", "temp-log.txt")
        log = os.path.join("logs", log)
    elif log != "*": # if sniffing file and using log (sniffing interface using log would trigger above statement)
        log = os.path.join("logs", log)

    setup_client(host)
    print("Connected")
    return run_main(mode, log_orig, log, temp_log, arg, sniff_time, out)

def run_main(mode:str, log_orig:str, log:str, temp_log:str, arg:str, sniff_time:int, out:str, cmd_mode=False):
    total_time=0.0
    t = time.perf_counter()
    f = FlowArray()
    if mode == "f": # reading from pcap file
        sniff(mode, log_orig, arg)

        # if args.test:
        #     to_write = ""
        #     response = recv_message_test()
        #     while response is not None:
        #         to_write += response
        #         response = recv_message_test()
        #     with open("logs/model_string.txt", "w") as ft:
        #         ft.writelines(to_write)

        if log == "*":
            print("Waiting for flows from agent...")
            response = recv_message()
            while response is not None:
                f.flows.extend(response.flows)
                response = recv_message()
            print("Received flows from agent")
            tg_start = time.perf_counter()
            generate_graph(f)
        else: # reading from log
            print("Waiting for flows to be recorded by agent...")
            # Proceed to read from logfile only when sniffer closes connection and sends a
            # blank message, indicating it is done writing to logfile
            recv_message()
            print("Reading flows from file")
            tg_start = time.perf_counter()
            generate_graph_from_file(log)
    else: # sniffing network interface
        q, visited, ips = [arg], [arg], []
        exists = False
        #open("logs/model_string.txt", "w").close()

        if log == "*": # if using tcp
            l = FlowArray()            
            while len(q) > 0:
                print("IP address(es) in queue: {}".format(q))
                ip = q.pop(0)
                sniff(mode, log_orig, ip, sniff_time)

                # if args.test:
                #     to_write = ""
                #     response = recv_message_test()
                #     while response is not None:
                #         to_write += response
                #         response = recv_message_test()
                #     with open("logs/model_string.txt", "a") as ft:
                #         ft.writelines(to_write)
                #         ft.write("\n\n\nNext component\n")

                print("Waiting for flows from agent...")
                response = recv_message()#sniffed_info_pb2.FlowArray) # uses protobuf
                while response is not None:
                    f.flows.extend(response.flows)
                    response = recv_message()#sniffed_info_pb2.FlowArray) # uses protobuf
                print("Received flows from agent")
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
                t1_start = time.perf_counter()
                ips, visited = next_hop_extractor(f, ip, visited) # can also specify ips to omit (on blacklist)
                end_time=time.perf_counter()-t1_start
                total_time=total_time+end_time
                q.extend(ips)
                del f.flows[:]
            if cmd_mode:
                stop_client()
            tg_start = time.perf_counter()
            generate_graph(l)
        else: # if using log
            open(log, "w").close()
            lines_to_write = []
            while len(q) > 0:
                print("IP address(es) in queue: {}".format(q))
                ip = q.pop(0)
                sniff(mode, log_orig, ip, sniff_time)
                print("Waiting for flows to be recorded by agent...")
                recv_message()
                with open(log, "r") as l, open(temp_log, "r") as f:
                    print("Reading flows from file")
                    f.seek(0)
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
                            l.seek(0)
                with open(log, "a") as l:
                    l.writelines(lines_to_write)
                t1_start = time.perf_counter()
                ips, visited = next_hop_extractor(temp_log, ip, visited) # can also specify ips to omit (on blacklist)
                end_time=time.perf_counter()-t1_start
                total_time=total_time+end_time
                q.extend(ips)
                lines_to_write.clear()
            if cmd_mode:
                stop_client()
            os.remove(temp_log)
            tg_start = time.perf_counter()
            generate_graph_from_file(log)

    endg_time=time.perf_counter()-tg_start
    total_time=total_time+endg_time
    #print("Controller time: {} seconds".format(round(total_time, 5)))

    print("Elapsed time since controller started: {} seconds".format(round(time.perf_counter() - t, 5)))
    return write_json_output(out)

def run_startup_parser():
    parser = argparse.ArgumentParser()
    group1 = parser.add_mutually_exclusive_group(required=True)
    group2 = parser.add_mutually_exclusive_group()
    group1.add_argument("-f", "--file", help="read capture file containing flows to be sniffed")
    group1.add_argument("-i", "--IP", help="perform live sniffing starting with provided IP")
    group2.add_argument("-H", "--host", help="address for sniffer host")
    group2.add_argument("-l", "--log", nargs="?", const="log.txt", default="*", help="send results from sniffer using log file (uses log.txt if no arg). Defaults to sending flows via TCP and omitting a log")
    parser.add_argument("-t", "--time", type=int, choices=range(5,1000), metavar="[5-1000]", default=8, help="sniffing time for each component")
    parser.add_argument("-o", "--output", default="out.json", help="name of json output file. Defaults to out.json")
    #parser.add_argument("--test", action="store_true", help="receive string for input to learning model")
    args = parser.parse_args()

    mode, arg, temp_log = None, None, None
    if args.IP is not None:
        mode = "i"
        arg = args.IP
    elif args.file is not None:
        mode = "f"
        arg = args.file
    log = args.log
    
    if mode == "i" and log != "*": # if sniffing interface and using log
        # Sniffer will write to a temp log
        temp_log = os.path.join("logs", "temp-log.txt")
        log = os.path.join("logs", log)
    elif log != "*": # if sniffing file and using log (sniffing interface using log would trigger above statement)
        log = os.path.join("logs", log)
    setup_client(args.host)
    print("Connected")
    
    run_main(mode, args.log, log, temp_log, arg, args.time, args.output, cmd_mode=True)

if __name__ == '__main__':
    run_startup_parser()