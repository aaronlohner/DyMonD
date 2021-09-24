#include <pthread.h>
#include <mutex>
#include <queue>
#include <Utils.hpp>
#include <ctime>
#include <time.h>
#include <vector>
#include "/home/melsaa1/anaconda3/envs/name/include/python3.7m/Python.h"
#include <sniffer.hpp> // needed for flow struct defn
#include <server.hpp> // needed for server method calls
using namespace std;
using namespace boost::filesystem;
struct service
{
  char ID[32];
  char label[32];
  float score;
  
};
float threshold = 0.98;

//add post-validation code 
std::mutex mtx;
vector<struct flow*> flowarray;
queue<raw_pkt*> Que;
int enq=0;
int deq=0;
std::ofstream file;
char* interface = NULL;
char* ipaddress = NULL;
char* tracefile = NULL; 
bool LiveMode=false;
double duration=30.0;
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

void GetURLs( std::vector<char*> Packets)

{

file.open("URLS",  std::ios_base::app);
    
    int methodCode;
    char *uri;

for (int i=0; i<Packets.size(); i++)
{

         methodCode = parseMethod(Packets[i], strlen(Packets[i]));

        if (methodsName[methodCode] != "NONE"){
       

   uri = parseUri(Packets[i], strlen(Packets[i]));
        if (uri !=NULL)
        {
         char * token = strtok(uri, "?");
        if (token!=NULL)
        {file << token << "\n";
        //printf("%s \n",token); 
}
} 
}
}
file.close();

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
//        printf("pop\n");
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
                printf("eth \n");
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
                    strncpy(f->proto, "Unknown", 32);//f->proto = strdup("Unknown");
                    flowarray.push_back(f);
                    Pfound = false;
                    foundIndex = flowarray.size() - 1;

                }
                if (tcp_hdr != NULL) {
                    if (tcp_hdr->th_flags == TH_ACK) {
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
                
// here is the service identification module. This is the one should be replaced by calling the python script with flows.csv as an input

                if ((!Pfound)) {
                    if (dport == 80 || dport == 8080 || dport == 8000 || dport == 8079) {
                        //flowarray[foundIndex]->dport = strdup(strcat(flowarray[foundIndex]->dport, "http"));
                        flowarray[foundIndex]->protof = true;
                        Pfound = true;
                        snprintf(flowarray[foundIndex]->proto, sizeof(flowarray[foundIndex]->proto), "%s","HTTP-C");
                    }
                    else if (sport == 80 || sport == 8080 || sport == 8000 || sport == 8079) {
//                        flowarray[foundIndex]->sport = strdup(strcat(flowarray[foundIndex]->sport, "http"));
                        flowarray[foundIndex]->protof = true;
                        Pfound = true;
                        snprintf(flowarray[foundIndex]->proto, sizeof(flowarray[foundIndex]->proto), "%s","HTTP-S");

                    }
                    else if (dport == 3306) {
  //                      flowarray[foundIndex]->dport = strdup(strcat(flowarray[foundIndex]->dport, "mysql"));
                        snprintf(flowarray[foundIndex]->proto, sizeof(flowarray[foundIndex]->proto), "%s","MySQL-C");

                        flowarray[foundIndex]->protof = true;
                        Pfound = true;
                    }
                    else if (sport == 3306) {
    //                    flowarray[foundIndex]->sport = strdup(strcat(flowarray[foundIndex]->sport, "mysql"));
                        snprintf(flowarray[foundIndex]->proto, sizeof(flowarray[foundIndex]->proto), "%s","MySQL-S");

                        flowarray[foundIndex]->protof = true;
                        Pfound = true;
                    }
                    else if (dport == 11211) {
      //                  flowarray[foundIndex]->dport = strdup(strcat(flowarray[foundIndex]->dport, "memcached"));
                        snprintf(flowarray[foundIndex]->proto, sizeof(flowarray[foundIndex]->proto), "%s","Memcache-C");
                        flowarray[foundIndex]->protof = true;
                        Pfound = true;
                    }
                    else if (sport == 11211) {
        //                flowarray[foundIndex]->sport = strdup(strcat(flowarray[foundIndex]->sport, "memcached"));
                        snprintf(flowarray[foundIndex]->proto, sizeof(flowarray[foundIndex]->proto), "%s","Memcache-S");
                        flowarray[foundIndex]->protof = true;
                        Pfound = true;
                    }


                }


                if (tcp_hdr != NULL)
                    free_tcphdr(tcp_hdr);
                if (udp_hdr != NULL)
                    free_udphdr(udp_hdr);
                free_ethhdr(eth_hdr);
                free_iphdr(ip_hdr);


            } // else eth_type

            raw_packet_free(rpkt);

        } else
           continue;

    } //while
}
    
    printf("raw is null \n");
    free(saddr);
    free(daddr);
}

void *
capture_main(void *) {

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
    cap = pcap_open_offline(tracefile, errbuf);
    else
    cap = pcap_open_live(interface, 65535, 1, 1000, errbuf);  
        
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

wchar_t** _argv = (wchar_t**)PyMem_Malloc(sizeof(wchar_t*)*argc);
    for (int i=0; i<argc; i++) {
    wchar_t* arg = Py_DecodeLocale(argv[i], NULL);
    _argv[i] = arg;
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
                printf("no module is found\n");
                PyErr_Print();}
                else{printf("module is found\n");}
        pDict = PyModule_GetDict(pModule); 
    pFunc = PyDict_GetItemString(pDict, "prediction");
    if(!pFunc ||!(PyCallable_Check(pFunc))){
        if (PyErr_Occurred())
                            PyErr_Print();
                        fprintf(stderr, "Cannot find function \"%s\"\n", argv[2]);
        Py_XDECREF(pFunc);
                Py_DECREF(pModule);
        return 0;
    }
    PyObject *PyList  = PyList_New(0);
    PyObject *ArgList = PyTuple_New(1);

    clock_t end1 = clock();
    double elapsed1 = double(end1 - start1)/CLOCKS_PER_SEC;
    printf("Time measured for initialization and finding the target python program and function: %.3f seconds.\n", elapsed1);

InitMethodName();    
while((opt = getopt(argc, argv, "t:i:f:p")) != -1){
                switch(opt){
            case 't':
                if(atof(optarg) <= 0 || atof(optarg) > 1000) {
                    printf("Time out of range");
                    exit(EXIT_FAILURE);
                } else duration = atof(optarg);
                break;
                        case 'i':
                                interface = optarg; break;
                        case 'p':
                                ipaddress = optarg; break;
                        case 'f':
                                tracefile = optarg; break;
                }
        }

char mode_buf[64], log[64], arg[64];
bool sniff_more = true;
string capture_dir = "captures/";
if(argc == 1 || strstr(argv[1], "-t") != NULL){
    setup_server(); // prepare server for incoming client tcp connection
    receive_message(mode_buf); // receive indication if using interface or reading from file
    receive_message(log); // receive indication if sending via tcp or writing to logfile
    receive_message(arg);  // receive network interface name or name of pcap file
    opt = mode_buf[0];
    capture_dir.append(arg);
    switch(opt){
                case 'i':
                    interface = arg; break;
                case 'p':
                            ipaddress = arg; break;
                case 'f':
                        tracefile = (char*)capture_dir.c_str(); break;
            }
} else {
    log[0] = '\0';
}
 if (interface != NULL)
    LiveMode=true;
    
    printf("Starting to sniff...\n");
    while(sniff_more){
        /* Start packet receiving thread */
        pthread_create(&job_pkt_q, NULL,&process_packet_queue, NULL);
        /* Start main capture in live or offline mode */
        pthread_create(&capture, NULL, &capture_main, NULL);

        // Wait for all threads to finish
        pthread_join(job_pkt_q, &thread_result);
    pthread_join(capture, &thread_result);

    printf("enq: %d Deq: %d\n", enq,deq);
//std::string line;
//   int index=0;
/*while (std::getline(infile, line))
{
    std::istringstream iss(line);
    //std::string token1;
    char *token1;
    double token2;
    bool found=false;
    if (!(iss >> token1 >> token2)) { break; } // error
//      if (token2<1.0)
//{
         snprintf(ID, sizeof(ID), "%s%s", flowarray[index]->saddr,flowarray[index]->sport);  
        for (int i = 0; i < Nodes.size(); i++) {
                    if (Nodes[i]->NodeID == NULL) continue;
                    if (strstr(ID, Nodes[i]->NodeID) != NULL) {
                           if (token2 > Nodes[i]->score ) {
                          Nodes[i]->service= strdup(token1);
                          Nodes[i]->score= token2;
                          flowarray[index]->proto=strdup(token1);
                     
                    }
else 
   flowarray[index]->proto=strdup(Nodes[i]->service);
found=true;
break;
                }              
}
 if(!found)
flowarray[index]->proto=strdup(token1);
index++;
}*/
 /*   myfile.open("flows/flows.csv", std::ios_base::out);
    printf("flowarray size is %lu\n",flowarray.size());
     char *array = new char[36];
    for (int i = 0; i < flowarray.size(); i++) {
       
        if (flowarray[i]->Packets.size() == 100 ) {
              if ( flowarray[i]->protof)
                {  GetURLs(flowarray[i]->Packets); }
             for (int j = 0; j < 100; j++) {     
                 if( strlen(flowarray[i]->Packets[j]) >= 36)
                       strncpy(array, flowarray[i]->Packets[j], 36);
                else if ( strlen(flowarray[i]->Packets[j]) > 0 &&  strlen(flowarray[i]->Packets[j]) < 36) {
                    int d = 36 - strlen(flowarray[i]->Packets[j]);
                    int index = strlen(flowarray[i]->Packets[j]);
                    strncpy(array, flowarray[i]->Packets[j], index);
                    for (int j = 0; j < d; j++) {
                        array[index] = '0';
                        index++;
                    }
}
                for (int l = 0; l <36; l++) {    
                    b = ( unsigned char )array[l];
                    if((j*l)!=3465)
                    myfile << b << ",";
                    else     // last byte is followed by new line instead of ","
                    myfile << b << "\n"; 
                }
            }
           
        }
    }
    myfile.close();*/
    clock_t start2 = clock();
    char *array = new char[36];
    int rownum = 0;
    for (int i = 0; i < flowarray.size(); i++) {
           if (flowarray[i]->Packets.size() == 100 ) {
               rownum++;
           }
    }
    //printf("2darray rownum is %d",rownum);
    int *arr_2d=new int[rownum*3600];
    int(*p)[3600]=(int(*)[3600])arr_2d; 

    int itr_row = 0;
    int itr_col = 0;

    for (int i = 0; i < flowarray.size(); i++) {

        if (flowarray[i]->Packets.size() == 100 ) {
              if ( flowarray[i]->protof)
                {  GetURLs(flowarray[i]->Packets); }
             for (int j = 0; j < 100; j++) {     
                 //if( strlen(flowarray[i]->Packets[j]) >= 36)
                       strncpy(array, flowarray[i]->Packets[j], 36);
                /*else if ( strlen(flowarray[i]->Packets[j]) > 0 &&  strlen(flowarray[i]->Packets[j]) < 36) {
                    int d = 36 - strlen(flowarray[i]->Packets[j]);
                    int index = strlen(flowarray[i]->Packets[j]);
                    strncpy(array, flowarray[i]->Packets[j], index);
                    for (int j = 0; j < d; j++) {
                        array[index] = '0';
                        index++;
                    }
}*/
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
    double elapsed2 = double(end2 - start2)/CLOCKS_PER_SEC;
    printf("Time measured for set up 2d array: %.3f seconds.\n", elapsed2);
    printf("2d array creation finished. rownum is %d, column num is 3600\n",itr_row);
       std::string str;
   for (int x =0;x<rownum;x++) {
       for(int y = 0;y<3600;y++){
        str += std::to_string(p[x][y]);
        str += " ";
    }
   }
   cout<< str<< endl;
    clock_t start3 = clock();
    PyTuple_SetItem(ArgList, 0, Py_BuildValue("s", str.c_str()));
    pReturn=PyObject_CallObject(pFunc, ArgList);
    clock_t end3 = clock();
    double elapsed3 = double(end3 - start3)/CLOCKS_PER_SEC;
    printf("Time measured from sending to receiving: %.3f seconds.\n", elapsed3);


    char* result;
    PyArg_Parse(pReturn,"s",&result);
    printf("result from python is");
    printf("%s\n",result);

    //int rows=rownum
    int cols=2;
    vector< vector<string> > mat = strTo2DStr(result,rownum,cols);

    char *label[18] = {"Cass-C", "Cass-S", "CassMN", "DB2-C", "DB2-S", "HTTP-S", "HTTP-C", "MYSQL-S", "MYSQL-C", "Memcached-C", "Memcached-S", "MonetDB-C", "MonetDB-S", "PGSQL-C", "PGSQL-S", "Redis-C", "Redis-S", "Spark-W"};
int counter_mat = 0;

for (int i = 0; i < flowarray.size(); i++) {
       
        if (flowarray[i]->Packets.size() == 100 ) {
            int index = stoi(mat[counter_mat][0]);
            char* lab=label[index];
            //flowarray[i]->proto=label[index];
           // mat[counter][0]=lab;
           // printf("%s\n",mat[counter][0]);
            //flowarray[i]->proto=const_cast<char *>(mat[counter][0].c_str());
           // printf("%s ",flowarray[i]->proto);
           // printf("%s\n",mat[counter][0]);
            double score_double = std::stod(mat[counter_mat][1]);
            //flowarray[i]->score=score_double;
            //printf("%f\n",flowarray[i]->score);
            cout<<i<<" "<<flowarray[i]->sport<<" "<<flowarray[i]->saddr<<" "<<flowarray[i]->dport <<" "<< flowarray[i]->daddr<<" "<<lab <<" "<< score_double <<endl;

            counter_mat++;
        }

}

vector < struct service *>services;
/******************validate label**********************/
printf("first for loop....\n");

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
              printf("create service\n");
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
//    free(ID);
        }
    
    
}
//test services
for(int j = 0;j<services.size();j++){
    cout<< j <<":ID "<<services[j]->ID <<" lab:"<<services[j]->label<<endl;
}

/*for all flows
1 packets.size!=100 --> label unknown
2 packets.size =100 -->
                    1) found services.ID=flows.ID, update label if not equal
                    2) not found service.ID = flows.ID, label as unknown.
*/

/**************/


int count = 0;
printf("iterate through flows...\n");
for (int i = 0; i < flowarray.size(); i++)
    {
      if (flowarray[i]->Packets.size() != 100 )  {          
          strncpy(flowarray[i]->proto,"Unknown",32);   
      }

      else if (flowarray[i]->Packets.size() == 100 )
        {
        
        int ind = std::stoi(mat[count][0]);
        //   cout<< ind << endl;
        string flab =label[ind];
        string flab_del = flab.substr(0, flab.size()-2);
        char * mat_lab = const_cast<char*>(flab_del.c_str());
            char *ip;
            char *port;
            char *ip_1;
            char *port_1;

          if(flowarray[i]->isServer ==1)  
          {   
              ip = flowarray[i]->saddr;
              port = flowarray[i]->sport;
          //printf("server ip: %s server port: %s",ip,port);
            }
          else if(flowarray[i]->isServer == 0)
            {
              ip = flowarray[i]->daddr;
              port = flowarray[i]->dport;
            }
            else if(flowarray[i]->isServer == 2){
                ip = flowarray[i]->saddr;
              port = flowarray[i]->sport;
              ip_1 = flowarray[i]->daddr;
              port_1 = flowarray[i]->dport;
            }
          if(flowarray[i]->isServer ==1||flowarray[i]->isServer ==0){
          char ID[32];
       //   ID = (char *) malloc(strlen(ip) + strlen(port) + 1);
          strncpy (ID, ip,32);
          strncat (ID, port,32);
      //printf("%d",i);
          printf("%s\n",ID);
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
        //replace with counter;
          if(found==1&&(strcmp(flowarray[i]->proto,services[pos]->label)!=0)){
                    strncpy(flowarray[i]->proto,services[pos]->label,32);
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    //cout<<"i is: "<<i<<" proto is "<< flowarray[i]->proto<< endl;
            }
            if(found==0){
            flowarray[i]->specialType=3;
            }
        }
        else if(flowarray[i]->isServer ==2){
          char ID[32];
       //   ID = (char *) malloc(strlen(ip) + strlen(port) + 1);
          strncpy (ID, ip,32);
          strncat (ID, port,32);
          char ID_1[32];
       //   ID = (char *) malloc(strlen(ip) + strlen(port) + 1);
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
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    //cout<<"i is: "<<i<<" proto is "<< flowarray[i]->proto<< endl;
                    }
                
            }
            else if(found==0&&found_1==1){
                flowarray[i]->isServer = 0;
                if(strcmp(flowarray[i]->proto,services[pos_1]->label)!=0){
                    strncpy(flowarray[i]->proto,services[pos_1]->label,32);
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    //cout<<"i is: "<<i<<" proto is "<< flowarray[i]->proto<< endl;
                    }

            }
            else if(found==1&&found_1==1){
                if(services[pos]->score > services[pos_1]->score){
                    flowarray[i]->isServer = 1;
                    if(strcmp(flowarray[i]->proto,services[pos]->label)!=0){
                    strncpy(flowarray[i]->proto,services[pos]->label,32);
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    //cout<<"i is: "<<i<<" proto is "<< flowarray[i]->proto<< endl;
                    }
                }
                else if(services[pos]->score <= services[pos_1]->score){
                     flowarray[i]->isServer = 0;
                    if(strcmp(flowarray[i]->proto,services[pos_1]->label)!=0){
                    strncpy(flowarray[i]->proto,services[pos_1]->label,32);
                    if(strcmp(flowarray[i]->proto,"CassMN")==0||strcmp(flowarray[i]->proto,"Spark-W")==0){
                        flowarray[i]->specialType=2;
                    }
                    else{flowarray[i]->specialType=1;}
                    //cout<<"i is: "<<i<<" proto is "<< flowarray[i]->proto<< endl;
                    }
                }

            }
            else{
                flowarray[i]->specialType=3;
            }



        }



       count ++;
        }


        
    }
//test result


int test_counter=0;
for(int i = 0; i < flowarray.size (); i++){
    if(flowarray[i]->Packets.size()==100){
            printf("flow array %d \n",test_counter);
            cout << "proto before concatenation: "<< flowarray[i]->proto<< endl;
    if(flowarray[i]->specialType==2){
        cout << "proto after concatenation: "<< flowarray[i]->proto<< endl;
    }
    else if(flowarray[i]->isServer==1&&flowarray[i]->specialType!=3){
            char new_proto[32];
            const char *type = "-S";
            strncpy (new_proto, flowarray[i]->proto,32);
            strncat (new_proto, type,32);
        strncpy(flowarray[i]->proto,new_proto,32);
    cout<<"proto after concatenation: " << flowarray[i]->proto<< endl;}
    else if (flowarray[i]->isServer==0&&flowarray[i]->specialType!=3){
        char new_proto[32];
        const char *type = "-C";
            strncpy (new_proto, flowarray[i]->proto,32);
            strncat (new_proto, type,32);
        strncpy(flowarray[i]->proto,new_proto,32);
        cout<<"proto after concatenation: " << flowarray[i]->proto<< endl;
    }
    else if(flowarray[i]->specialType==3){
            strncpy(flowarray[i]->proto, "Unknown", 32);
        cout << "proto after concatenation: " << flowarray[i]->proto<< endl;
        }
    test_counter++;
    printf("\n");
    }
}

/*********************validate label***********************/   
    int counter = 0;
     double diff, RST;
    if(log[0] != '*'){ // anything but '*' indicates that log should be used
        string log_str = "logs/";
        if(strlen(log) == 0){
            log_str.append("log.txt");
        } else {
            log_str.append(log);
        }
         // performance metrics clacualation and dumping into file
        FP.open(log_str, std::ios_base::out); // using standard ports
        printf("Writing to log\n");
     for(int i = 0; i < flowarray.size(); i++) {
         if (flowarray[i]->Packets.size() == 100) {
            if (flowarray[i]->Ack_times.size() > 1) {
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
     if(argc == 1 || strstr(argv[1], "-t") != NULL) send_message(); // blank message indicates finished writing to log
    } else { // use tcp
        for(int i = 0; i < flowarray.size(); i++) {
           if (flowarray[i]->Packets.size() == 100 ) {
                if(flowarray[i]->Ack_times.size()>1){
                    diff=0.0;
                    for(int j = 0; j < flowarray[i]->Ack_times.size(); j++) {
                        if (j!=flowarray[i]->Ack_times.size()-1)
                            diff += (flowarray[i]->Ack_times[j + 1]->sec +
                                  flowarray[i]->Ack_times[j + 1]->usec * 0.000001) -
                                 (flowarray[i]->Ack_times[j]->sec + flowarray[i]->Ack_times[j]->usec * 0.000001);
                    }
                    RST = abs(diff/( flowarray[i]->Ack_times.size() -1)); 
                    add_to_flow_array(flowarray[i], RST);
                }
                else {
                    add_to_flow_array(flowarray[i], 0.0);
                }
                counter++;
           }
        }
        send_message(flowarray);
        if(counter > 0) {
            printf("Flows sent to controller\n");
            send_message();
            counter = 0;
        }
    }
     for(int i = 0; i < flowarray.size(); i++)
     {
        for (int j=0; j<flowarray[i]->Ack_times.size(); j++)
             free(flowarray[i]->Ack_times[j]);
         free(flowarray[i]);
     }
     if(mode_buf[0] == 'i'){
        flowarray.clear();
        receive_message(arg);
        if(!strcmp(arg, "stop")) sniff_more = false;
     } else {
         sniff_more = false;
     }
    }
        clock_t start4 = clock();
        Py_DECREF(ArgList);
        Py_DECREF(PyList);
        Py_DECREF(pReturn);
        Py_DECREF(pFunc);
        Py_DECREF(pModule);
        Py_XDECREF(pDict);
        Py_Finalize();
        clock_t end4 = clock();
        
        double elapsed4 = double(end4 - start4)/CLOCKS_PER_SEC;
        printf("Time measured for finalization: %.3f seconds.\n", elapsed4);
    
  
  
/* for(int i = 0; i < Nodes.size(); i++)
     {
         // printf("%s %s %f\n",Nodes[i]->NodeID, Nodes[i]->service, Nodes[i]->score); 
         free(Nodes[i]);
     }*/



    return 0;
}