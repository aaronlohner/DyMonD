#include <sniffer.hpp>
#include <server.hpp>
//#include <include/server.hpp>

void *check_malloc(unsigned long size)
{

	void *ptr = NULL;
	if ((ptr = malloc(size)) == NULL) {
		printf("Out of memory!\n");
		exit(1);
	}
	return ptr;
}

char *ip_ntos(u_int32_t n){
	static char buf[sizeof("aaa.bbb.ccc.ddd")];
	memset(buf, '\0', 15);

	sprintf(buf, "%d.%d.%d.%d",
			(n & 0xff000000) >> 24,
			(n & 0x00ff0000) >> 16,
			(n & 0x0000ff00) >> 8,
			(n & 0x000000ff) >> 0);

	return buf;
}

ethhdr *
packet_parse_ethhdr(const char *p)
{
	ethhdr *hdr, *tmp;

	tmp = (ethhdr *)p;
	hdr = MALLOC(ethhdr, 1);

	memset(hdr, 0, sizeof(ethhdr));
	memcpy(hdr->ether_dhost, tmp->ether_dhost, 6 * sizeof(u_int8_t));
	memcpy(hdr->ether_shost, tmp->ether_shost, 6 * sizeof(u_int8_t));
	hdr->ether_type = ntohs(tmp->ether_type);
	return hdr;
}

/*
 * Parse the IP header with little endian format
 */
iphdr *
packet_parse_iphdr(const char *p)
{
	iphdr *hdr, *tmp;
	tmp = (iphdr *)p;

	hdr = MALLOC(iphdr, 1);
	memset(hdr, '\0', sizeof(iphdr));

	hdr->ihl = tmp->ihl;
	hdr->version = tmp->version;
	hdr->tos = tmp->tos;
	hdr->tot_len = ntohs(tmp->tot_len);
	hdr->id = ntohs(tmp->id);
	hdr->frag_off = ntohs(tmp->frag_off);
	hdr->ttl = tmp->ttl;
	hdr->protocol = tmp->protocol;
	hdr->check = ntohs(tmp->check);
	hdr->saddr = ntohl(tmp->saddr);
	hdr->daddr = ntohl(tmp->daddr);

	return hdr;
}


/*
 * Parse the TCP header with little endian format
 */
tcphdr *
packet_parse_tcphdr(const char *p)
{
        tcphdr *hdr, *tmp;
        tmp = (tcphdr *)p;

        hdr = MALLOC(tcphdr, 1);
        memset(hdr, '\0', sizeof(tcphdr));

        hdr->th_sport = ntohs(tmp->th_sport);
        hdr->th_dport = ntohs(tmp->th_dport);
        hdr->th_seq = ntohl(tmp->th_seq);
        hdr->th_ack = ntohl(tmp->th_ack);
        hdr->th_x2 = tmp->th_x2;
        hdr->th_off = tmp->th_off;
        hdr->th_flags = tmp->th_flags;
        hdr->th_win = ntohs(tmp->th_win);
        hdr->th_sum = ntohs(tmp->th_sum);
        hdr->th_urp = ntohs(tmp->th_urp);

        return hdr;
}
udphdr*
packet_parse_udphdr(const char* p)
{
    udphdr *hdr, *tmp;
    tmp = (udphdr*)p;

    hdr = MALLOC(udphdr, 1);
    memset(hdr, '\0', sizeof(udphdr));

    hdr->uh_sport = ntohs(tmp->uh_sport);
    hdr->uh_dport = ntohs(tmp->uh_dport);
    hdr->uh_len = ntohs(tmp->uh_len);
    return hdr;
}
/* Free the ethernet header */
void free_ethhdr(ethhdr *h)
{
	free(h);
}

/* Free the IP header */
void free_iphdr(iphdr *h)
{
	free(h);
}

/* Free the TCP header */
void free_tcphdr(tcphdr *h)
{
	free(h);
}
void free_udphdr(udphdr* h)
{
    free(h);
}

int main( int argc, char *argv[] )
{

   std::ofstream myfile, FP;
  //char ip[32];
  //char s[32]="ipv4(src=";
  //char port[6];char port1[6];
   char errbuf[PCAP_ERRBUF_SIZE];
   memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    char on_off_line[1], token[32];//char *token=NULL;
    char* raw = NULL;
    pcap_t* cap = NULL;
    struct pcap_pkthdr pkthdr;
    u_int8_t tcp_hl = 0;
    u_int16_t tcp_dl = 0;
    u_int8_t ip_hl=0; 
    u_int16_t sport, dport;
    char buf[55];
    int b = 0;
    char* saddr = (char*)malloc(sizeof("aaa.bbb.ccc.ddd"));
    char* daddr = (char*)malloc(sizeof("aaa.bbb.ccc.ddd"));
   
    vector<struct flow*> flowarray;

    setup_server(); // prepares server to incoming client tcp connection
    receive_message(on_off_line); // receive indication if using live mode or not
    receive_message(token); // receive network interface name (live) or name of pcap file (offline)

    if(token !=NULL)
    {

        printf("Starting to sniff for packets\n");
    
        time_t start, end;
        double elapsed;
        if(on_off_line[0] == 'l')
        {
            printf("Opening live thread on %s\n", token);
            cap = pcap_open_live(token, 65535, 1, 1000, errbuf);
                
            if( cap == NULL) {
                    printf("errbuf");
                    printf("%s\n",errbuf); exit(1);
            }
            start = time(NULL);  
            end = time(NULL);
            elapsed = difftime(end, start);
        }
        else
        {
            string capture = "captures/";
            capture.append(token);
            cap = pcap_open_offline(capture.c_str(), errbuf);
            
            if( cap == NULL) {
                    printf("errbuf");
                    printf("%s\n",errbuf); exit(1);
            }
        }

        while((on_off_line[0] == 'l' && elapsed <= 30.0) || on_off_line[0] == 'o')
        {
        //printf("mode, time: %c, %f", on_off_line[0], elapsed);
        raw = (char *)pcap_next(cap, &(pkthdr));
        if( NULL != raw)
{
        char* cp = raw;

        ethhdr* eth_hdr = NULL;
        iphdr* ip_hdr = NULL;
        tcphdr* tcp_hdr = NULL;
        udphdr* udp_hdr = NULL;
        struct Ack_time* cap_time;

        int foundIndex = 0, tp,tp_l;
        bool Pfound = false;
        bool found = false;
	    int b = 0;
        eth_hdr = packet_parse_ethhdr(cp);
        
       if (eth_hdr->ether_type != 0x0800) // not an IP packet
            {printf("eth");free_ethhdr(eth_hdr);}
        else {
            cp = cp + sizeof(ethhdr);
            ip_hdr = packet_parse_iphdr(cp);
            strncpy(saddr, ip_ntos(ip_hdr->saddr), sizeof("aaa.bbb.ccc.ddd"));
            strncpy(daddr, ip_ntos(ip_hdr->daddr), sizeof("aaa.bbb.ccc.ddd"));
            ip_hl = (ip_hdr->ihl) << 2; /* bytes */
            tp_l=ip_hdr->tot_len - ip_hl;
            tp=ip_hdr->protocol;
            cp = cp + ip_hl; 
        if (tp==17) // UDP packet
            {
            udp_hdr = packet_parse_udphdr(cp);
            sport=udp_hdr->uh_sport;
            dport= udp_hdr->uh_dport;
            tcp_dl = tp_l - 8 ;
            cp= cp+8;
}
         else  // TCP packet
{
            
            tcp_hdr = packet_parse_tcphdr(cp);
            sport=tcp_hdr->th_sport;
            dport= tcp_hdr->th_dport;
            tcp_hl = tcp_hdr->th_off << 2; /* bytes */
            tcp_dl = tp_l - tcp_hl;
            cp = cp + tcp_hl;
 }     
           snprintf(buf, sizeof(buf), "%s-%s--%" PRIu16 "-%" PRIu16 "-%d", saddr, daddr, sport, dport,tp);
           for (int i = 0; i < flowarray.size(); i++) {
                if (flowarray[i]->flowID == NULL ) continue;
                if(strstr(buf, flowarray[i]->flowID) != NULL) {
                    found = true;
                    flowarray[i]->NumBytes+=tcp_dl;
                    if (strstr(flowarray[i]->proto,"Unknown") != NULL) {
                        Pfound = true;
                    }

                    foundIndex = i;
                    break;
                }
              }

            if (!found) {
                // allocate memory for one `struct flow'
                struct flow* f = (struct flow*)calloc(sizeof(struct flow), 1);
                if (f == NULL)
                    printf("NULL");
                
                // copy the data into the new element (structure)
                f->flowID = strdup(buf);
                f->saddr = strdup(saddr);
  		f->daddr = strdup(daddr);
                f->sport=new char[sizeof(sport)+1];
                f->dport=new char[sizeof(dport)+1];
                sprintf(f->sport, "%u", sport);
                sprintf(f->dport, "%u", dport);
                f->NumBytes=tcp_dl;
                f->protof = false;
                f->proto = strdup("Unknown");
                flowarray.push_back(f);
                Pfound = false;
                foundIndex = flowarray.size() - 1;
            }
if (tcp_hdr !=NULL)
{
if (tcp_hdr->th_flags ==  TH_ACK)
    {cap_time = (struct Ack_time*)calloc(sizeof(struct Ack_time), 1);cap_time->sec=pkthdr.ts.tv_sec;cap_time->usec=pkthdr.ts.tv_usec;flowarray[foundIndex]->Ack_times.push_back(cap_time);
}
}
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
// here is the service identification module. This is the one should be replaced by calling the python script with flows.csv as an input
                   
        if((!Pfound)){
        cp = cp + tcp_hl;
       if (dport == 80|| dport == 8080  || dport == 8000 || dport == 8079)
            {flowarray[foundIndex]->dport=strdup(strcat(flowarray[foundIndex]->dport,"http"));flowarray[foundIndex]->protof=true;Pfound=true;}
        else if (sport == 80 || sport == 8080 || sport == 8000 || sport == 8079 )
           {flowarray[foundIndex]->sport=strdup(strcat(flowarray[foundIndex]->sport,"http"));flowarray[foundIndex]->protof=true;Pfound=true;}
        else if (dport == 3306)
              {flowarray[foundIndex]->dport=strdup(strcat(flowarray[foundIndex]->dport,"mysql"));flowarray[foundIndex]->protof=true;Pfound=true;}
        else if (sport == 3306)
           {flowarray[foundIndex]->sport=strdup(strcat(flowarray[foundIndex]->sport,"mysql"));flowarray[foundIndex]->protof=true;Pfound=true;}
         else if (dport == 11211)
              {flowarray[foundIndex]->dport=strdup(strcat(flowarray[foundIndex]->dport,"memcached"));flowarray[foundIndex]->protof=true;Pfound=true;}
       	else if (sport == 11211)
           {flowarray[foundIndex]->sport=strdup(strcat(flowarray[foundIndex]->sport,"memcached"));flowarray[foundIndex]->protof=true;Pfound=true;}

}          


if(tcp_hdr !=NULL)            
free_tcphdr(tcp_hdr);
if(udp_hdr !=NULL)
free_udphdr(udp_hdr);
free_ethhdr(eth_hdr);
free_iphdr(ip_hdr);

} // else eth_type

    }
else //if raw == NULL
{ 
    printf("raw is null \n");
    if(on_off_line[0] == 'o') {
        break;
    }
}
    if(on_off_line[0] == 'l') {
        end = time(NULL);
        elapsed = difftime(end, start);
    }
 
} //30s duration


myfile.open("flows/flows.csv", std::ios_base::out);
 for (int i = 0; i < flowarray.size(); i++) {
       
        if (flowarray[i]->Packets.size() == 100 ) { 
             for (int j = 0; j < 100; j++) {     
                for (int l = 0; l <36; l++) {    
                     b = ( unsigned char )flowarray[i]->Packets[j][l];
                    if((j*l)!=3465)
                    myfile << b << ",";
                    else     // last byte is followed by new line instead of ","
                    myfile << b << "\n"; 
                }
            }
           
        }
}
    myfile.close();

 // performance metrics clacualation and dumping into file
FP.open("logs/log.txt", std::ios_base::out); // using standard ports
 double diff, RST;

 for(int i = 0; i < flowarray.size(); i++) {
if (flowarray[i]->Packets.size() == 100 ) {
   if(flowarray[i]->Ack_times.size()>1)
{
   diff=0.0;
   for(int j = 0; j < flowarray[i]->Ack_times.size(); j++) 
      {	if (j!=flowarray[i]->Ack_times.size()-1)
 diff+=(flowarray[i]->Ack_times[j+1]->sec+flowarray[i]->Ack_times[j+1]->usec*0.000001)-(flowarray[i]->Ack_times[j]->sec+flowarray[i]->Ack_times[j]->usec*0.000001);
      }
      RST= abs(diff/( flowarray[i]->Ack_times.size() -1)); 
     FP<<flowarray[i]->saddr << ":"<<flowarray[i]->sport<< " " << flowarray[i]->daddr<< ":"<< flowarray[i]->dport<< " "<< flowarray[i]->NumBytes/30<< "-"<< RST<<"\n";
     
     add_to_flow_array(flowarray[i], RST);

}
else
     { FP<<flowarray[i]->saddr << ":"<<flowarray[i]->sport<< " " << flowarray[i]->daddr<< ":"<< flowarray[i]->dport<< " "<< flowarray[i]->NumBytes/30<< "\n";
     
     add_to_flow_array(flowarray[i]);
     
     }

}
 }

 send_message(flowarray);

FP.close();

 for(int i = 0; i < flowarray.size(); i++)
{ 
    for (int j=0; j<flowarray[i]->Ack_times.size(); j++)
         free(flowarray[i]->Ack_times[j]);
     free(flowarray[i]);
}


  

if( cap != NULL)
                pcap_close(cap);

}

free(saddr);
free(daddr); 
return 0;
}
