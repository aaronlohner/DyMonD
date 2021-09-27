#include <string.h>
#include <pcap/pcap.h>
#include <time.h>

// Moved here from the new sniffer.cpp:
#include <assert.h> /* assert */
#include <iostream>
#include <pthread.h>
#include <mutex>          // std::mutex
#include <bits/stdc++.h>
#include <boost/filesystem.hpp>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <time.h>
#include <queue>
#include <ctime>

#include <sniffer.hpp> // added, removed some struct defns below instead

using namespace std;

#define MALLOC(type, num)  (type *) check_malloc((num) * sizeof(type))

std::vector<const char*> methodsName;

std::vector<std::string> StopWords;
void InitStopWords()
{

    StopWords.push_back("http");
    StopWords.push_back("https");           
    StopWords.push_back("\n");
    StopWords.push_back("\r");
    StopWords.push_back("com");
    StopWords.push_back("rest");
    StopWords.push_back("asp");
    StopWords.push_back("html");
    StopWords.push_back("xml");
    StopWords.push_back("css");
    StopWords.push_back("js");
    StopWords.push_back("aspx");
    StopWords.push_back("php");         
   
}
void InitMethodName()

{

    methodsName.push_back("NONE");
    methodsName.push_back("OPTIONS");           /* RFC2616 */
    methodsName.push_back("GET");
    methodsName.push_back("HEAD");
    methodsName.push_back("POST");
    methodsName.push_back("PUT");
    methodsName.push_back("DELETE");
    methodsName.push_back("TRACE");
    methodsName.push_back("CONNECT");
    methodsName.push_back("PATCH");
    methodsName.push_back("LINK");
    methodsName.push_back("UNLINK");
    methodsName.push_back("PROPFIND");          /* RFC2518 */
    methodsName.push_back("MKCOL");
    methodsName.push_back("COPY");
    methodsName.push_back("MOVE");
    methodsName.push_back("LOCK");
    methodsName.push_back("UNLOCK");
    methodsName.push_back("POLL");              /* Outlook Web Access */
    methodsName.push_back("BCOPY");
    methodsName.push_back("BMOVE");
    methodsName.push_back("SEARCH");
    methodsName.push_back("BDELETE");
    methodsName.push_back("PROPPATCH");
    methodsName.push_back("BPROPFIND");
    methodsName.push_back("BPROPPATCH");
    methodsName.push_back("LABEL");             /* RFC 3253 8.2 */
    methodsName.push_back("MERGE");             /* RFC 3253 11.2 */
    methodsName.push_back("REPORT");            /* RFC 3253 3.6 */
    methodsName.push_back("UPDATE");            /* RFC 3253 7.1 */
    methodsName.push_back("CHECKIN");           /* RFC 3253 4.4"); 9.4 */
    methodsName.push_back("CHECKOUT");          /* RFC 3253 4.3"); 9.3 */
    methodsName.push_back("UNCHECKOUT");        /* RFC 3253 4.5 */
    methodsName.push_back("MKACTIVITY");        /* RFC 3253 13.5 */
    methodsName.push_back("MKWORKSPACE");       /* RFC 3253 6.3 */
    methodsName.push_back("VERSION_CONTROL");   /* RFC 3253 3.5 */
    methodsName.push_back("BASELINE_CONTROL");  /* RFC 3253 12.6 */
    methodsName.push_back("NOTIFY");            /* uPnP forum */
    methodsName.push_back("SUBSCRIBE");
    methodsName.push_back("UNSUBSCRIBE");
    methodsName.push_back("ICY");               /* Shoutcast client (forse) */

}

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

//typedef struct _raw_pkt raw_pkt;
struct raw_pkt {
	char *raw;
	struct pcap_pkthdr pkthdr;
};



// struct Ack_time {
//  time_t sec;  // Ack time in seconds
//  time_t usec; // Ack time in usec
// };

// struct flow {
//  char *flowID;
//  char *saddr;
//  char *daddr;
//  char *sport;
//  char *dport;
//  char *proto;
//  int NumBytes;
//  bool protof;
//  std::vector<char*> Packets;
//  std::vector<struct Ack_time*> Ack_times;

// };

// typedef struct ethernet_header ethhdr;
// struct ethernet_header
// {
//   u_int8_t  ether_dhost[6];		/* Destination addr	*/
//   u_int8_t  ether_shost[6];		/* Source addr */
//   u_int16_t ether_type;			/* Packet type */
// };

// /* IP header structure */
// typedef struct ip_header iphdr;
// struct ip_header
// {
//     u_int8_t ihl:4;
//     u_int8_t version:4;
//     u_int8_t tos;
//     u_int16_t tot_len;
//     u_int16_t id;
//     u_int16_t frag_off;
// #define	IP_RF 0x8000			/* Reserved fragment flag */
// #define	IP_DF 0x4000			/* Dont fragment flag */
// #define	IP_MF 0x2000			/* More fragments flag */
// #define	IP_OFFMASK 0x1fff		/* Mask for fragmenting bits */
//     u_int8_t ttl;
//     u_int8_t protocol;
//     u_int16_t check;
//     u_int32_t saddr;
//     u_int32_t daddr;
//     /*The options start here. */
// };

// /* TCP header structure */
// typedef struct tcp_header tcphdr;
// struct tcp_header
// {
//     u_int16_t th_sport;         /* Source port */
//     u_int16_t th_dport;         /* Destination port */
//     u_int32_t th_seq;           /* Sequence number */
//     u_int32_t th_ack;           /* Acknowledgement number */
//     u_int8_t th_x2:4;           /* (Unused) */
//     u_int8_t th_off:4;          /* Data offset */
//     u_int8_t th_flags;
// #  define TH_FIN        0x01
// #  define TH_SYN        0x02
// #  define TH_RST        0x04
// #  define TH_PUSH	0x08
// #  define TH_ACK        0x10
// #  define TH_URG        0x20
//     u_int16_t th_win;           /* Window */
//     u_int16_t th_sum;           /* Checksum */
//     u_int16_t th_urp;           /* Urgent pointer */
// };

// typedef struct udp_header udphdr;
// struct udp_header {
// u_short	uh_sport;		/* source port */
// 	u_short	uh_dport;		/* destination port */
// 	u_short	uh_len;		/* datagram length */
// 	u_short	uh_sum;			/* datagram checksum */
// };

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

void raw_packet_free(raw_pkt* p) {
    free(p->raw);
    free(p);
}


   int parseMethod(const char *data, int linelen)
{
    const char *ptr;
    int	index = 0;

    /*
     * From RFC 2774 - An HTTP Extension Framework
     *
     * Support the command prefix that identifies the presence of
     * a "mandatory" header.
     */
    if (linelen >= 2) {
        if (strncmp(data, "M-", 2) == 0 || strncmp(data, "\r\n", 2) == 0) { /* \r\n necesary for bug in client POST */
            data += 2;
            linelen -= 2;
        }
    }

    /*
     * From draft-cohen-gena-client-01.txt, available from the uPnP forum:
     *	NOTIFY, SUBSCRIBE, UNSUBSCRIBE
     *
     * From draft-ietf-dasl-protocol-00.txt, a now vanished Microsoft draft:
     *	SEARCH
     */
    ptr = (const char *)data;
    /* Look for the space following the Method */
    while (index < linelen) {
        if (*ptr == ' ')
            break;
        else {
            ptr++;
            index++;
        }
    }

    for (std::size_t i = 0; i != methodsName.size(); ++i) {
        if (strncmp(data, methodsName[i], index) == 0) {
            return i;
        }
    }

    return 0;
}

char* find_header_end(const char *data, const char *dataend, int *line_cnt) {
    const char *lf, *nxtlf, *end;

    end = NULL;
    lf = (const char*) memchr(data, '\n', (dataend - data + 1));
    if (lf == NULL)
        return NULL;
    (*line_cnt)++;
    lf++; /* next charater */
    nxtlf = (const char*) memchr(lf, '\n', (dataend - lf + 1));
    while (nxtlf != NULL) {
        if (nxtlf-lf < 2) {
            end = nxtlf;
            break;
        }
        (*line_cnt)++;
        nxtlf++;
        lf = nxtlf;
        nxtlf = (const char*) memchr(nxtlf, '\n', dataend - nxtlf + 1);
    }
    return (char *)end;
}
char* find_line_end(const char *data, const char *dataend, const char **eol) {
	const char *lineend;

	lineend = (const char*)memchr(data, '\n', dataend - data + 1);

	if (lineend == NULL) {
		/*
		 * No LF - line is probably continued in next TCP segment.
		 */
		lineend = dataend;
		*eol = dataend;
	} else {
		/*
		 * Is the LF at the beginning of the line?
		 */
		if (lineend > data) {
			/*
			 * No - is it preceded by a carriage return?
			 * (Perhaps it's supposed to be, but that's not guaranteed....)
			 */
			if (*(lineend - 1) == '\r') {
				/*
				 * Yes.  The EOL starts with the CR.
				 */
				*eol = lineend - 1;

			} else {
				/*
				 * No.  The EOL starts with the LF.
				 */
				*eol = lineend;

				/*
				 * I seem to remember that we once saw lines ending with LF-CR
				 * in an HTTP request or response, so check if it's *followed*
				 * by a carriage return.
				 */
				if (lineend < (dataend - 1) && *(lineend + 1) == '\r') {
					/*
					 * It's <non-LF><LF><CR>; say it ends with the CR.
					 */
					lineend++;
				}
			}
		} else {

			/*
			 * Yes - the EOL starts with the LF.
			 */
			*eol = lineend;
		}
	}
	return (char*)lineend;
}
int get_token_len(const char *linep, const char *lineend, const char **next_token) {
    const char *tokenp;
    int token_len;

    tokenp = linep;

    /*
     * Search for a blank, a CR or an LF, or the end of the buffer.
     */
    while (linep < lineend && *linep != ' ' && *linep != '\r' && *linep != '\n')
        linep++;
    token_len = linep - tokenp;

    /*
     * Skip trailing blanks.
     */
    while (linep < lineend && *linep == ' ')
        linep++;

    *next_token = linep;

    return token_len;
}

char* parseUri(const char *line, int len) {
    const char *next_token;
    const char *lineend;
    int tokenlen;
    char *uri;

    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return NULL;
    }
    line = next_token;

    /* The next token is the URI. */
    tokenlen =get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return NULL;

    uri = MALLOC(char, tokenlen+1);
    if (uri != NULL) {
        memcpy(uri, line, tokenlen);
        uri[tokenlen] = '\0';
    }

    return uri;
}
bool Alpha(std::string str )

{
  bool AP= true;
  for (int i=0; i<str.size(); i++)
 {
 if (!std::isalpha(str[i]))
     {AP=false;break;}
 }
 return AP;
}



bool SearchList(std::vector<std::string> list, std::string str )
{
 
bool found=false;
for (int i=0; i<list.size(); i++){
 if (str.compare(StopWords[i]) == 0)
     {found=true;break;}
 }
 return found;
}
