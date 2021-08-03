import random

#the script is to generate a json file that can be used in webvowl1.1.7SE
#input file is csv containing edges in the format of (Node1, Node2, connection information)
#change input on line #58 and output on line #59

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
    return label[0:counter1], label[counter1:len(label)].upper()

#####################################


data = open("networkTSK2.txt", "r")#input
output = open("networkTSK2.json", "w")#output

nodes = {}
edges = {}
newNode1 = None
newNode2 = None
id1 = None
id2 = None

for line in data:#read edge information
    if len(line.strip().split(" ")) == 3:
        node1, node2, weight = line.strip().split(" ")#node1: the first node; node2: the second node; weight: information
        node12=node1.split(":")[1]#seperate port and ip address
        node22=node2.split(":")[1]
        if node12.isdigit() and not node22.isdigit():#node 1 is client and node2 is server
#            newNode1 = node("owl:Class", node1, node1.split(":")[0], randomColor())
            newNode1 = node("owl:Class", "Client", node1.split(":")[0], node12, randomColor())
            newNode2 = node("owl:equivalentClass", getName(node22)[1], node2.split(":")[0], getName(node22)[0],randomColor())
        elif not node12.isdigit() and node22.isdigit():#node 1 is server and node2 is client
            newNode1 = node("owl:equivalentClass", getName(node12)[1], (node1.split(":")[0]), getName(node12)[0],randomColor())
            newNode2 = node("owl:Class", "Client", node2.split(":")[0], node22, randomColor())
        elif node12.isdigit() and node22.isdigit():#both nodes are not server
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
            th, rst = weight.split("-")
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
                        print(str(edges[key]) + str(rst))
                        edges[key].RST = rst
        rst = 0
        newNode1 = None
        newNode2 = None
        id1 = None
        id2 = None
    
    
#########################################

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

        elif edges[key].RST:
            output.write("{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH + ", RST: " + edges[key].RST + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")
            
        else:
            output.write("{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH+ ", C: " + (str)(edges[key].C) + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")
    else:
        if edges[key].TH == "same address":
            output.write(",\n{\"id\": \"" + str(key) + "\",\n\"label\": \"" + edges[key].TH + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")

        elif edges[key].RST:
            output.write(",\n{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH + ", RST: " + edges[key].RST + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")  
        else:
            output.write(",\n{\"id\": \"" + str(key) + "\",\n\"label\": \"TH: " + edges[key].TH + ", C: " + (str)(edges[key].C) + "\",\n\"domain\": \"" + edges[key].domain + "\",\n\"range\": \"" + edges[key].range + "\"\n}")
output.write("]\n}")
data.close()
output.close()  
