// #include <assert.h> /* assert */
// #include <iostream>
#include <pthread.h>
#include <mutex>          // std::mutex
// #include <bits/stdc++.h>
// #include <boost/filesystem.hpp>
// #include <string.h>
// #include <pcap/pcap.h>
// #include <netinet/in.h>
// #include <time.h>
#include <queue>
#include <Utils.hpp> // modified
#include <ctime>
#include <sniffer.hpp> // needed for flow struct defn
#include <server.hpp> // needed for server method calls
using namespace std;
using namespace boost::filesystem;


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
    double run_duration ;
    clock_t begin = clock();
if(LiveMode)
  run_duration=10.1; //30.1
else
  run_duration=2.0;
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
    double sniff_duration = 10.0; //30.0
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
    int b = 0; 	int opt;
    void *thread_result;
    pthread_t job_pkt_q;
    pthread_t capture;
    char ID[28];



InitMethodName();    
while((opt = getopt(argc, argv, "i:f:p")) != -1){
		switch(opt){
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
if(argc == 1){
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
    myfile.open("flows/flows.csv", std::ios_base::out);
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
    myfile.close();
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
                 RST = abs(diff / (flowarray[i]->Ack_times.size() - 1));
                 FP << flowarray[i]->saddr << ":" << flowarray[i]->sport << " " << flowarray[i]->daddr << ":"
                    << flowarray[i]->dport <<" " << flowarray[i]->proto << " " << flowarray[i]->NumBytes / 30 << "-" << RST << "\n";
             } else {
                 FP << flowarray[i]->saddr << ":" << flowarray[i]->sport << " " << flowarray[i]->daddr << ":"
                    << flowarray[i]->dport  <<" " << flowarray[i]->proto << " " << flowarray[i]->NumBytes / 30 << "\n";
             }
             printf("%d, ", ++counter);
         }
     }
     FP.close();
     if(argc == 1) send_message();
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
                    add_to_flow_array(flowarray[i]);
                }
                printf("%d, ", ++counter);
            }
        }
        send_message(flowarray);
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

/* for(int i = 0; i < Nodes.size(); i++)
     {
         // printf("%s %s %f\n",Nodes[i]->NodeID, Nodes[i]->service, Nodes[i]->score); 
         free(Nodes[i]);
     }*/



    return 0;
}
