#include <boost/algorithm/string.hpp>
#include <map>
#include <pthread.h>
#include <mutex>
#include <queue>
#include <Utils.hpp>
#include <ctime>
#include <time.h>
#include <vector>
#include "/home/melsaa1/anaconda3/envs/name/include/python3.7m/Python.h"
#include <agent.hpp> // needed for flow struct defn
#include <server.hpp> // needed for server method calls
using namespace std;
using namespace boost::filesystem;
struct service
{
  char ID[32];
  char label[32];
  float score;
  std::vector<std::string> URLS;
  std::string MSlabel;
  
};
float threshold = 0.98;
std::mutex mtx;
vector<struct flow*> flowarray;
queue<raw_pkt*> Que;
int enq=0;
int deq=0;
std::ofstream file;
char interface[32];
char* ipaddress = NULL;
char* tracefile = NULL; 
bool LiveMode=false;
double duration=30.0;
int FindService( vector < struct service *> &services, char ID [32])
{
 int pos=-1;
 for (int j=0; j< services.size();j++)
{ 
if(strcmp(services[j]->ID,ID)==0)
{
 
 pos=j;
 break;
}
}
return  pos;
}

vector<vector<string>> strTo2DStr(const string& str, const int& r, const int& c)
{
    vector<vector<string>> mat;
    int rows(r), cols(c);
    vector<string> words;
    istringstream ss(str);
    copy(istream_iterator<string>(ss),istream_iterator<string>(),back_inserter(words));

    int counter(0);
    for ( int i(0); i < rows; ++i ){
        vector<string> temp;
        for ( int j(0); j < cols; ++j){
            if ( counter < words.size() )
                temp.push_back(words[counter++]);
            else
                temp.push_back("");
        }
        mat.push_back(temp);
    }

    return mat;
}

void GetURLs(service* S, std::vector<char*> Packets)

{

    int methodCode;
    char *uri;
    size_t pos = 0;
    std::string token;
for (int i=0; i<Packets.size(); i++)
{

         methodCode = parseMethod(Packets[i], strlen(Packets[i]));

        if (methodsName[methodCode] != "NONE"){


   uri = parseUri(Packets[i], strlen(Packets[i]));
        if (uri !=NULL)
        {
        char * token = strtok(uri, "?");
        if (token!=NULL)
        {S->URLS.push_back((std::string)token); 
}
} 
}
}
}

std::string GetMSLabel(std::vector<std::string> URIS){
std::map<std::string, int> wordcount;
std::string word, data;
size_t pos = 0, pos1=0;
bool Threshold=false;
std::string MSlabel;
InitStopWords();
for (int i=0; i<URIS.size(); i++)
{
//count++;
boost::to_lower(URIS[i]);

std::string token, token1;
while ((pos = URIS[i].find( "/")) != std::string::npos) {
    token = URIS[i].substr(0, pos);
 if (token.find(".") != std::string::npos)  
{
std::vector<std::string> tokens;
while ((pos1 = token.find(".")) != std::string::npos) {
 token1 = token.substr(0, pos1);
    tokens.push_back(token1);
    token.erase(0, pos1 + 1);
}//while ((pos = data.find("."))
if (tokens.size()>0)
{
   if (SearchList(StopWords,tokens[tokens.size()-1]))
    {if (!tokens[tokens.size()-2].empty())word= tokens[tokens.size()-2];}
  else 
    word= tokens[tokens.size()-1];
 }  
}//if (token.find(".")
word=token;
if (!word.empty() && Alpha(word) && !(SearchList(StopWords,word)))
  {
    
if (wordcount.count(word)>0)
          wordcount[word] += 1;
else
  wordcount.insert ( std::pair<std::string,int>(word,1) );
  }
    URIS[i].erase(0, pos + 1);
}//while ((pos = data.find(delimiter))
}
for ( auto item : wordcount )
{
  if (((float)item.second/URIS.size()) >= 0.5)
      {MSlabel=MSlabel+"/"+item.first; Threshold=true;}
}
if(!Threshold)

{

    multimap<int, std::string> MM;
    for (auto& it : wordcount) {
        MM.insert({ it.second, it.first });
    }
map<int, std::string>::iterator itr;


  itr = MM.end();

  for (int i=0; i<3;i++)
{
  --itr;
  MSlabel=MSlabel+"/"+itr->second;
}
}

return MSlabel;
}

void *process_packet_queue(void*) {


    u_int8_t tcp_hl = 0;
    u_int16_t tcp_dl = 0;
    u_int8_t ip_hl=0;
    u_int16_t sport, dport;
    char buf[55];
    char* saddr = (char*)malloc(sizeof("aaa.bbb.ccc.ddd"));
    char* daddr = (char*)malloc(sizeof("aaa.bbb.ccc.ddd"));
    raw_pkt *rpkt = NULL;
    double run_duration;
    clock_t begin = clock();
if(LiveMode)
  run_duration=duration+0.1;//30.1;
else
  run_duration=duration;//100.0;
while (true) {

    clock_t end = clock();
        double elapsed_time = double(end - begin) / CLOCKS_PER_SEC;
        if (elapsed_time >= run_duration) {
            break;
        }

    if (deq < enq) {
        
        mtx.lock();
        rpkt = (raw_pkt *) Que.front();
        Que.pop();
        deq++;
        mtx.unlock();
 if (NULL != rpkt) {
            char *cp = rpkt->raw;

            ethhdr *eth_hdr = NULL;
            iphdr *ip_hdr = NULL;
            tcphdr *tcp_hdr = NULL;
            udphdr *udp_hdr = NULL;
            struct Ack_time *cap_time;

            int foundIndex = 0, tp, tp_l;
            bool Pfound = false;
            bool found = false;
            int b = 0;
            eth_hdr = packet_parse_ethhdr(cp);

            if (eth_hdr->ether_type != 0x0800) // not an IP packet
            {
                free_ethhdr(eth_hdr);
            }
            else {
                cp = cp + sizeof(ethhdr);
                ip_hdr = packet_parse_iphdr(cp);
                strncpy(saddr, ip_ntos(ip_hdr->saddr), sizeof("aaa.bbb.ccc.ddd"));
                strncpy(daddr, ip_ntos(ip_hdr->daddr), sizeof("aaa.bbb.ccc.ddd"));
                ip_hl = (ip_hdr->ihl) << 2; /* bytes */
                tp_l = ip_hdr->tot_len - ip_hl;
                tp = ip_hdr->protocol;
                cp = cp + ip_hl;
                if (tp == 17) // UDP packet
                {
                    udp_hdr = packet_parse_udphdr(cp);
                    sport = udp_hdr->uh_sport;
                    dport = udp_hdr->uh_dport;
                    tcp_dl = tp_l - 8;
                    cp = cp + 8;
                } else  // TCP packet
                {

                    tcp_hdr = packet_parse_tcphdr(cp);
                    sport = tcp_hdr->th_sport;
                    dport = tcp_hdr->th_dport;
                    tcp_hl = tcp_hdr->th_off << 2; /* bytes */
                    tcp_dl = tp_l - tcp_hl;
                    cp = cp + tcp_hl;
                }
                snprintf(buf, sizeof(buf), "%s-%s--%" PRIu16 "-%" PRIu16 "-%d", saddr, daddr, sport, dport, tp);
                for (int i = 0; i < flowarray.size(); i++) {
                    if (flowarray[i]->flowID == NULL) continue;
                    if (strstr(buf, flowarray[i]->flowID) != NULL) {
                        found = true;
                        flowarray[i]->NumBytes += tcp_dl;
                        if (strstr(flowarray[i]->proto, "Unknown") != NULL) {
                            Pfound = true;
                        }

                        foundIndex = i;
                        break;
                    }
                }

                if (!found) {
                    // allocate memory for one `struct flow'
                    struct flow *f = (struct flow *) calloc(sizeof(struct flow), 1);
                    // copy the data into the new element (structure)
                    f->flowID = strdup(buf);
                    f->saddr = strdup(saddr);
                    f->daddr = strdup(daddr);
                    f->sport = new char[sizeof(sport) + 1];
                    f->dport = new char[sizeof(dport) + 1];
                    sprintf(f->sport, "%u", sport);
                    sprintf(f->dport, "%u", dport);
                    f->NumBytes = tcp_dl;
                    f->protof = false;
                    strncpy(f->proto, "Unknown", 32);
                    flowarray.push_back(f);
                    Pfound = false;
                    foundIndex = flowarray.size() - 1;

                }
                if (tcp_hdr != NULL) {
                    if (tcp_hdr->th_flags == TH_ACK ||tcp_hdr->th_flags == 0x18) {
                        cap_time = (struct Ack_time *) calloc(sizeof(struct Ack_time), 1);
                        cap_time->sec = rpkt->pkthdr.ts.tv_sec;
                        cap_time->usec = rpkt->pkthdr.ts.tv_usec;
                        flowarray[foundIndex]->Ack_times.push_back(cap_time);
                    }
                }
               

if (flowarray[foundIndex]->Packets.size() < 100 && tcp_dl > 0)
{
char *linesp, *lineep, *dataend, *eol;
int lnl=0;
linesp = (char*)  cp;
dataend= cp +tcp_dl;
        lineep = find_line_end(linesp, dataend, (const char**)&eol);
        if(lineep!=NULL){
        lnl = lineep - linesp + 1;
        char *array = new char[lnl];
        strncpy(array,cp,lnl);
flowarray[foundIndex]->Packets.push_back(array);

}
else
{
char *array = new char[36];

if ( tcp_dl >= 36&& flowarray[foundIndex]->Packets.size() < 100)
 {        
                        strncpy(array, cp, 36);
                        flowarray[foundIndex]->Packets.push_back(array);
 } 
else if ( tcp_dl > 0&& tcp_dl<36 && flowarray[foundIndex]->Packets.size() < 100 )
            {
             int d=36-tcp_dl;int index=tcp_dl;
             strncpy(array,cp,index);
             for (int j=0; j<d; j++)
              {array[index]='0'; index++;}

flowarray[foundIndex]->Packets.push_back(array);
}
}
}



                if (tcp_hdr != NULL)
                    free_tcphdr(tcp_hdr);
                if (udp_hdr != NULL)
                    free_udphdr(udp_hdr);
                free_ethhdr(eth_hdr);
                free_iphdr(ip_hdr);


            } 

            raw_packet_free(rpkt);

        } else
           continue;

    } 
}
    
    free(saddr);
    free(daddr);
return 0;
}

void * 
capture_main(void*) {

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    struct pcap_pkthdr pkthdr;
    char *raw = NULL;
    pcap_t *cap = NULL;
    raw_pkt *pkt = NULL;
    clock_t begin, end;
    double elapsed_time;
    double sniff_duration = duration;//30.0;
    if (!LiveMode)
    {    printf("Processing the network trace file...\n");cap = pcap_open_offline(tracefile, errbuf);}
    else
   { 
       char *interface_pcap = interface;
       printf("Starting to sniff...\n"); cap = pcap_open_live(interface_pcap, 65535, 1, 1000, errbuf);
       }  
        
         if (cap == NULL) {
        printf("errbuf: ");
        printf("%s\n", errbuf);
        exit(1);
    }
    begin = clock();
    raw = (char *) pcap_next(cap, &(pkthdr));
    while (NULL != raw) {
        pkt = MALLOC(raw_pkt, 1);
        pkt->pkthdr = pkthdr;
        char *r = MALLOC(char, pkthdr.len);
        memcpy(r, raw, pkthdr.len);
        pkt->raw = r;

        mtx.lock();
        Que.push(pkt);
        enq++;
        mtx.unlock();

       if (LiveMode)
{ 
        end = clock();
        elapsed_time = double(end - begin) / CLOCKS_PER_SEC;
        if (elapsed_time >= sniff_duration) {
            break;
        }
}

        raw = (char *) pcap_next(cap, &(pkthdr));
    }

    if (cap != NULL)
        pcap_close(cap);
return 0;
}

/***********************************
 
 ***********************************
 
 **** MAIN STARTS HERE ****
 
 ***********************************
***********************************/
int main(int argc, char *argv[]){
    std::ofstream myfile, FP, file;
    std::ifstream infile("services.txt");
    int b = 0;  int opt;
    void *thread_result;
    pthread_t job_pkt_q;
    pthread_t capture;
    char ID[28];
    string log_str = "logs/logging.txt"; // for debugging
    char *input_ip;
    bool cmd_mode = false;

wchar_t** _argv = (wchar_t**)PyMem_Malloc(sizeof(wchar_t*)*argc);
    for (int i=0; i<argc; i++) {
    wchar_t* argp = Py_DecodeLocale(argv[i], NULL); // already a variable called arg elsewhere
    _argv[i] = argp;
    }
    clock_t start1 = clock();
    Py_Initialize();
    PyObject * pModule = NULL;
    PyObject * pFunc = NULL;
    PyObject *pDict = NULL;
    PyObject *pReturn = NULL;
   Py_SetProgramName(_argv[0]); 
  PySys_SetArgv(argc, _argv); // must call this to get sys.argv and relative imports
    pModule = PyImport_ImportModule("Model");
        if(pModule==NULL){
                printf("Model is not found\n");
                PyErr_Print();}
                pDict = PyModule_GetDict(pModule); 
    pFunc = PyDict_GetItemString(pDict, "prediction");
    if(!pFunc ||!(PyCallable_Check(pFunc))){
        if (PyErr_Occurred())
                            PyErr_Print();
                        fprintf(stderr, "Cannot find prediction function \"%s\"\n", argv[2]);
        Py_XDECREF(pFunc);
                Py_DECREF(pModule);
        return 0;
    }
    PyObject *PyList  = PyList_New(0);
    PyObject *ArgList = PyTuple_New(1);

    clock_t end1 = clock();
    double elapsed1 = double(end1 - start1)/CLOCKS_PER_SEC;


InitMethodName();
// Standalone args and sniffing time
bool standalone = true;
while((opt = getopt(argc, argv, "t:i:f:p:c")) != -1){
                switch(opt){
            case 't':
                if(atof(optarg) <= 5 || atof(optarg) >= 1000) {
                    printf("Time out of range");
                    exit(EXIT_FAILURE);
                } else duration = atof(optarg);
                break;
            case 'i':
                    input_ip = optarg; break;
            case 'p':
                    ipaddress = optarg; break;
            case 'f':
                    tracefile = optarg; break;
            case 'c':
                    cmd_mode = true; break;
                }
        }

char mode_buf[64], log[64], arg[64], time[64];
bool sniff_more = true;
string capture_dir; // = "captures/"'
map<string, string> ip_map;
if(argc == 1 || strstr(argv[1], "-t") != NULL || cmd_mode){
    standalone = false;
    setup_server(); // prepare server for incoming client tcp connection
    // receive_message(mode_buf, true); // receive indication if using interface or reading from file
    // receive_message(log, true); // receive indication if sending via tcp or writing to logfile
    // receive_message(arg, false);  // receive network interface name or name of pcap file
    // printf("Monitoring request received\n");
    // opt = mode_buf[0];
    // capture_dir.append(arg);
    // switch(opt){
    //             case 'i':
    //                 interface = arg; break;
    //             case 'p':
    //                         ipaddress = arg; break;
    //             case 'f':
    //                     tracefile = (char*)capture_dir.c_str(); break;
    //         }

    ifstream inFile("interfaces/Interfaces.csv", ios::in);
    string lineStr;
    while (getline(inFile, lineStr))
    {
        // Interface is VALUE, IP is KEY
        int index = lineStr.find(" ");
        string interface_val = lineStr.substr(0, index);
        string ip_address_key = lineStr.substr(index+1, lineStr.size()-1);
        ip_map[ip_address_key] = interface_val;
    }


    // This is for logging the flows sent over tcp for debugging purposes
    FP.open(log_str, std::ios_base::out);
    FP.close();
} else { // Standalone mode
    log[0] = '\0';
}
    
    while(sniff_more){
        if(standalone){
            sniff_more = false;
            if (interface[0] != '\0') {
                LiveMode=true;
                printf("input_ip: %s\n", input_ip);
                strncpy(interface, ip_map[input_ip].c_str(), 32);
                printf("interface: %s\n", interface);
            }
        } else {
            receive_message(mode_buf, false); // receive indication if using interface or reading from file
            if(!strcmp(mode_buf, "stop")) {
                break;
            }
            receive_message(log, true); // receive indication if sending via tcp or writing to logfile
            receive_message(arg, true);  // receive network interface name or name of pcap file
            receive_message(time, true);
            duration = atof(time);
            if(mode_buf[0] == 'i'){
                printf("Monitoring request received\n");
                LiveMode=true;
                strncpy(interface, ip_map[arg].c_str(), 32);
                flowarray.clear();
            } else {
                LiveMode=false;
                capture_dir.clear();
                capture_dir.append("captures/").append(arg);
                tracefile = (char*)capture_dir.c_str();
                sniff_more = false;
            }
        }
        

        /* Start packet receiving thread */
        pthread_create(&job_pkt_q, NULL,&process_packet_queue, NULL);
        /* Start main capture in live or offline mode */
        pthread_create(&capture, NULL, &capture_main, NULL);

        // Wait for all threads to finish
        pthread_join(job_pkt_q, &thread_result);
    pthread_join(capture, &thread_result);
    clock_t start2 = clock();
    char *array = new char[36];
    int rownum = 0;
    for (int i = 0; i < flowarray.size(); i++) {
           if (flowarray[i]->Packets.size() == 100 ) {
               rownum++;
           }
    }
    int *arr_2d=new int[rownum*3600];
    int(*p)[3600]=(int(*)[3600])arr_2d; 

    int itr_row = 0;
    int itr_col = 0;

    for (int i = 0; i < flowarray.size(); i++) {

        if (flowarray[i]->Packets.size() == 100 ) {
             for (int j = 0; j < 100; j++) {     
                       strncpy(array, flowarray[i]->Packets[j], 36);
                for (int l = 0; l < 36; l++) {   
                        int b = (unsigned char)array[l]; 
                        p[itr_row][itr_col+l]= b;
                    }
                    itr_col = itr_col + 36;

                }
                itr_row++;
                itr_col=0;
            }

    }

    clock_t end2 = clock();
    double elapsed2 = double(end2 - start2)/CLOCKS_PER_SEC; // Time needed to formulate the inpur to the deep learning model
    std::string str;
   for (int x =0;x<rownum;x++) {
       for(int y = 0;y<3600;y++){
        str += std::to_string(p[x][y]);
        str += " ";
    }
   }
    printf("Sending flows data to the model, starting service identification.\n");
    clock_t start3 = clock();
    PyTuple_SetItem(ArgList, 0, Py_BuildValue("s", str.c_str()));
    pReturn=PyObject_CallObject(pFunc, ArgList);
    clock_t end3 = clock();
    double elapsed3 = double(end3 - start3)/CLOCKS_PER_SEC;// Service Identification time
    char* result;
    PyArg_Parse(pReturn,"s",&result);
    int cols=2;
    vector< vector<string> > mat = strTo2DStr(result,rownum,cols);
    const char *label[18] = {"Cass-C", "Cass-S", "CassMN", "DB2-C", "DB2-S", "HTTP-S", "HTTP-C", "MYSQL-S", "MYSQL-C", "Memcached-C", "Memcached-S", "MonetDB-C", "MonetDB-S", "PGSQL-C", "PGSQL-S", "Redis-C", "Redis-S", "Spark-W"};
int counter_mat = 0;
myfile.open("predictions.txt", std::ios_base::app);
for (int i = 0; i < flowarray.size(); i++) {
       
        if (flowarray[i]->Packets.size() == 100 ) {
            int index = stoi(mat[counter_mat][0]);
            const char* lab=label[index];
            double score_double = std::stod(mat[counter_mat][1]);
            flowarray[i]->score=score_double;
            myfile << flowarray[i]->saddr << ":" << flowarray[i]->sport << " " << flowarray[i]->daddr << ":"
                    << flowarray[i]->dport <<" " << lab << " "<<  flowarray[i]->score << "\n";
            counter_mat++;
        }

}
myfile.close();
/******************validate label**********************/
vector < struct service *>services;

int counter_f = 0;
for(int i = 0; i < flowarray.size(); i++)
  {
     
      if(flowarray[i]->Packets.size() == 100 )
      {
        int ind = std::stoi(mat[counter_f][0]);
        string lab =label[ind];
        string lab_del = lab.substr(0, lab.size()-2);
        char * mat_lab = const_cast<char*>(lab_del.c_str());
        float mat_score = std::stod(mat[counter_f][1]);
        if(mat_score>=threshold){
            char *ip;
            char *port;
            int specialType=0;
            if(lab.back()=='S')
            {
              ip = flowarray[i]->saddr;
              port = flowarray[i]->sport;
              flowarray[i]->isServer=1;
        }
            else if(lab.back()=='C')
            {
              ip = flowarray[i]->daddr;
              port = flowarray[i]->dport;
              flowarray[i]->isServer=0;
            }
            else if(lab.back()=='N'||lab.back()=='W')
            {
              ip = flowarray[i]->daddr;
              port = flowarray[i]->dport;
              flowarray[i]->isServer=0;
              specialType=1;
            }
            char ID [32];
            strncpy (ID, ip,32);
            strncat (ID, port,32);
        
            int found = 0;
            int pos = 0;
            //check if server IP/port number is in services;
            for (int j = 0; j < services.size (); j++)
            {
              if (strcmp(services[j]->ID,ID)==0)
                {
                  found = 1;
                  pos = j;
                  break;
                }
            }
          if (found == 0 && mat_score >= threshold)
            {
              struct service *ser =(struct service *) calloc (sizeof (struct service), 1);
              strncpy(ser->ID,ID,32);
              if(specialType==0){
              strncpy(ser->label,mat_lab,32);}
              else{
                  strncpy(ser->label,const_cast<char*>(lab.c_str()),32);}
              ser->score = mat_score;
              services.push_back (ser);
            }
          else if(found==1){
          if (mat_score > services[pos]->score) { 
            if(specialType==0){strncpy(services[pos]->label,mat_lab,32);}
            else{strncpy(services[pos]->label,const_cast<char*>(lab.c_str()),32);}
          services[pos]->score = mat_score;
            }
        }
        }
        else{flowarray[i]->isServer=2;}
      
    counter_f++;
        }
    
    
}
/*for all flows
1 packets.size!=100 --> label unknown
2 packets.size =100 -->
                    1) found services.ID=flows.ID, update label if not equal
                    2) not found service.ID = flows.ID, label as unknown.
*/

/**************/


int count = 0;
for (int i = 0; i < flowarray.size(); i++)
    {
      if (flowarray[i]->Packets.size() != 100 )  {          
          strncpy(flowarray[i]->proto,"Unknown",32);   
      }

      else if (flowarray[i]->Packets.size() == 100 )
        {
        
        int ind = std::stoi(mat[count][0]);
        string flab =label[ind];
        string flab_del = flab.substr(0, flab.size()-2);
        char * mat_lab = const_cast<char*>(flab_del.c_str());
            char *ip;
            char *port;
            char *ip_1;
            char *port_1;
            ip = flowarray[i]->saddr;
            port = flowarray[i]->sport;
            ip_1 = flowarray[i]->daddr;
            port_1 = flowarray[i]->dport;
            char ID[32];
            strncpy (ID, ip,32);
            strncat (ID, port,32);
            char ID_1[32];
            strncpy (ID_1, ip_1,32);
            strncat (ID_1, port_1,32);
            int pos=-1;
            int found=0;
          for (int j = 0; j < services.size(); j++)
            {
              if (strcmp(services[j]->ID,ID)==0)
                {
                  pos = j;
                  found = 1;
                  break;
                }
            }
          int pos_1=-1;
          int found_1=0;
          for (int j = 0; j < services.size(); j++)
            {
              if (strcmp(services[j]->ID,ID_1)==0)
                {
                  pos_1 = j;
                  found_1 = 1;
                  break;
                }
            }
            if(found==1&&found_1==0){
                flowarray[i]->isServer = 1;
                if(strcmp(flowarray[i]->proto,services[pos]->label)!=0){
                    strncpy(flowarray[i]->proto,services[pos]->label,32);
                    flowarray[i]->score=services[pos]->score;
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    }
                
            }
            else if(found==0&&found_1==1){
                flowarray[i]->isServer = 0;
                if(strcmp(flowarray[i]->proto,services[pos_1]->label)!=0){
                    strncpy(flowarray[i]->proto,services[pos_1]->label,32);
                     flowarray[i]->score=services[pos_1]->score;
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}

                    }

            }
            else if(found==1&&found_1==1){
                if(services[pos]->score > services[pos_1]->score){
                    flowarray[i]->isServer = 1;
                    if(strcmp(flowarray[i]->proto,services[pos]->label)!=0){
                    strncpy(flowarray[i]->proto,services[pos]->label,32);
                    flowarray[i]->score=services[pos]->score;
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    }
                }
                else if(services[pos]->score <= services[pos_1]->score){
                     flowarray[i]->isServer = 0;
                    if(strcmp(flowarray[i]->proto,services[pos_1]->label)!=0){
                    strncpy(flowarray[i]->proto,services[pos_1]->label,32);
                    flowarray[i]->score=services[pos_1]->score;
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    }
                }

            }
            else{
                flowarray[i]->specialType=3;
            }

       count ++;
        }


        
    }
// validate the Bidirection flows 

char RFlowID[55];
int test_counter=0;
for(int i = 0; i < flowarray.size (); i++){
    if(flowarray[i]->Packets.size()==100){

   if(!flowarray[i]->protof)
{
snprintf(RFlowID, sizeof(RFlowID), "%s-%s--%s-%s",flowarray[i]->daddr, flowarray[i]->saddr,flowarray[i]->dport,flowarray[i]->sport);
int position =-1;
for(int j = i+1; j < flowarray.size(); j++){
if (strstr(flowarray[j]->flowID,RFlowID)!=NULL)
{
position=j;
break;

}
}
if (position>0)
{
 if (strcmp(flowarray[i]->proto,flowarray[position]->proto)!=0)
{
  if (flowarray[i]->score > flowarray[position]->score)
     {
        strncpy(flowarray[position]->proto,flowarray[i]->proto,32);
       if (flowarray[i]->isServer==0)
           flowarray[position]->isServer=1;
       else if (flowarray[i]->isServer==1)
           flowarray[position]->isServer=0;
     }
  else if (flowarray[i]->score < flowarray[position]->score)
     {
        strncpy(flowarray[i]->proto,flowarray[position]->proto,32);
       if (flowarray[position]->isServer==0)
           flowarray[i]->isServer=1;
       else if (flowarray[position]->isServer==1)
           flowarray[i]->isServer=0;
     }

}
else
{
  if (flowarray[i]->score > flowarray[position]->score)
     {
       if (flowarray[i]->isServer==0)
           flowarray[position]->isServer=1;
       else if (flowarray[i]->isServer==1)
           flowarray[position]->isServer=0;
     }
  else if (flowarray[i]->score < flowarray[position]->score)
     {
       if (flowarray[position]->isServer==0)
           flowarray[i]->isServer=1;
       else if (flowarray[position]->isServer==1)
           flowarray[i]->isServer=0;
     }

}
flowarray[position]->protof=true;
}
flowarray[i]->protof=true; 
}
//validate the Bidirection flows 
   if(flowarray[i]->isServer==1&&flowarray[i]->specialType!=3){
            char new_proto[32];
            const char *type = "-S";
            strncpy (new_proto, flowarray[i]->proto,32);
            strncat (new_proto, type,32);
        strncpy(flowarray[i]->proto,new_proto,32);
    }
    else if (flowarray[i]->isServer==0&&flowarray[i]->specialType!=3){
        char new_proto[32];
        const char *type = "-C";
            strncpy (new_proto, flowarray[i]->proto,32);
            strncat (new_proto, type,32);
     if(strcmp(flowarray[i]->proto,"HTTP")==0)
{
 int pos;
 char ID[32];
 strncpy (ID, flowarray[i]->daddr,32);
 strncat (ID, flowarray[i]->dport,32);
 pos=FindService(services,ID);
if(pos>=0)
{
 GetURLs(services[pos],flowarray[i]->Packets);
}
}

        strncpy(flowarray[i]->proto,new_proto,32);
        
    }
    else if(flowarray[i]->specialType==3){
            strncpy(flowarray[i]->proto, "Unknown", 32);
                }
    test_counter++;
    }
}
 for (int j=0; j< services.size();j++)
{
   if(strcmp(services[j]->label,"HTTP")==0 && services[j]->URLS.size()>0)
{
std::string label=GetMSLabel(services[j]->URLS);
 if (!label.empty())
   services[j]->MSlabel.assign(label);
}

}
/*********************validate label***********************/ 
         // performance metrics calculation   
     printf("Collecting performance figures\n");
     int counter = 0;
     double diff, RST;
    if(log[0] != '*'){ // anything but '*' indicates that log should be used
        string log_str = "logs/";
        if(strlen(log) == 0){
            log_str.append("log.txt");
        } else {
            log_str.append(log);
        }
        FP.open(log_str, std::ios_base::out); 
        printf("Writing to log\n");
     for(int i = 0; i < flowarray.size(); i++) {
         if (flowarray[i]->Packets.size() == 100) {
               if(strstr(flowarray[i]->proto,"HTTP") != NULL) {
           char SID[32];
           if (flowarray[i]->isServer==0)
              {
                strncpy (SID, flowarray[i]->daddr,32);
                strncat (SID, flowarray[i]->dport,32);
              }
            else if (flowarray[i]->isServer==1)
              {
                strncpy (SID, flowarray[i]->saddr,32);
                strncat (SID, flowarray[i]->sport,32);
              }
            int index=FindService(services,SID);
           if (index>=0)
             {
              std::string newproto= (std::string)flowarray[i]->proto;
              newproto.insert(4,services[index]->MSlabel);   
              strncpy(flowarray[i]->proto,newproto.c_str(),32);
  
            }
        }

            if (flowarray[i]->Ack_times.size() > 1 && flowarray[i]->isServer==1) {
                 diff = 0.0;
                 for (int j = 0; j < flowarray[i]->Ack_times.size(); j++) {
                     if (j != flowarray[i]->Ack_times.size() - 1)
                         diff += (flowarray[i]->Ack_times[j + 1]->sec +
                                  flowarray[i]->Ack_times[j + 1]->usec * 0.000001) -
                                 (flowarray[i]->Ack_times[j]->sec + flowarray[i]->Ack_times[j]->usec * 0.000001);
                 }
                 RST = (int)(abs(diff / (flowarray[i]->Ack_times.size() - 1)) * 1000.0)/1000.0;
                 FP << flowarray[i]->saddr << ":" << flowarray[i]->sport << " " << flowarray[i]->daddr << ":"
                    << flowarray[i]->dport <<" " << flowarray[i]->proto << " " << flowarray[i]->NumBytes / 30 << "-" << RST << "\n";
             } else {
                 FP << flowarray[i]->saddr << ":" << flowarray[i]->sport << " " << flowarray[i]->daddr << ":"
                    << flowarray[i]->dport  <<" " << flowarray[i]->proto << " " << flowarray[i]->NumBytes / 30 << "\n";
             }
         }
     }
     FP.close();
    if(argc == 1 || strstr(argv[1], "-t") != NULL || cmd_mode) send_message(); // blank message indicates finished writing to log
    } else { // use tcp

        // For debugging flows
        FP.open(log_str, ios::app);

        for(int i = 0; i < flowarray.size(); i++) {
           if (flowarray[i]->Packets.size() == 100 ) {
              if(strstr(flowarray[i]->proto,"HTTP") != NULL) {
           char SID[32];
           if (flowarray[i]->isServer==0)
              {
                strncpy (SID, flowarray[i]->daddr,32);
                strncat (SID, flowarray[i]->dport,32);
              }
            else if (flowarray[i]->isServer==1)
              {
                strncpy (SID, flowarray[i]->saddr,32);
                strncat (SID, flowarray[i]->sport,32);
              }
            int index=FindService(services,SID);
           if (index>=0)
             {
              std::string newproto= (std::string)flowarray[i]->proto;
              newproto.insert(4,services[index]->MSlabel);   
              strncpy(flowarray[i]->proto,newproto.c_str(),32);
  
            }
        }

               if(flowarray[i]->Ack_times.size()>1 && flowarray[i]->isServer==1){
                    diff=0.0;
                    for(int j = 0; j < flowarray[i]->Ack_times.size(); j++) {
                        if (j!=flowarray[i]->Ack_times.size()-1)
                            diff += (flowarray[i]->Ack_times[j + 1]->sec +
                                  flowarray[i]->Ack_times[j + 1]->usec * 0.000001) -
                                 (flowarray[i]->Ack_times[j]->sec + flowarray[i]->Ack_times[j]->usec * 0.000001);
                    }
                    RST = abs(diff/( flowarray[i]->Ack_times.size() -1)); 
                    add_to_flow_array(flowarray[i], RST);

                    // For debugging flows
                    FP << flowarray[i]->saddr << ":" << flowarray[i]->sport << " " << flowarray[i]->daddr << ":"
                    << flowarray[i]->dport <<" " << flowarray[i]->proto << " " << flowarray[i]->NumBytes / 30 << "-" << RST << "\n";
                }
                else {
                    add_to_flow_array(flowarray[i], 0.0);

                    // For debugging flows
                    FP << flowarray[i]->saddr << ":" << flowarray[i]->sport << " " << flowarray[i]->daddr << ":"
                    << flowarray[i]->dport  <<" " << flowarray[i]->proto << " " << flowarray[i]->NumBytes / 30 << "\n";
                }
                counter++;
           }
        }

        FP.close();
        if (!standalone) {
            send_message(flowarray);
            printf("Flows sent to controller\n");
            send_message();
        }
        counter = 0;
    }
     for(int i = 0; i < flowarray.size(); i++)
     {
        for (int j=0; j<flowarray[i]->Ack_times.size(); j++)
             free(flowarray[i]->Ack_times[j]);
         free(flowarray[i]);
     }
    //  if(mode_buf[0] == 'i'){
    //     flowarray.clear();
    //     receive_message(arg, false);
    //     if(!strcmp(mode_buf, "stop")) { // if(!strcmp(arg, "stop")) {
    //         sniff_more = false;
    //     } else {
    //         printf("Monitoring request received\n");
    //     }
    //  } else {
    //      sniff_more = false;
    //  }
    }

        printf("Sniffing completed\n");
        clock_t start4 = clock();
        Py_DECREF(ArgList);
        Py_DECREF(PyList);
        Py_DECREF(pReturn);
        Py_DECREF(pFunc);
        Py_DECREF(pModule);
        Py_XDECREF(pDict);
        Py_Finalize();
        clock_t end4 = clock();        
        double elapsed4 = double(end4 - start4)/CLOCKS_PER_SEC;// environment finalization time
    return 0;
}
