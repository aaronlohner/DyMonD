#ifndef SNIFFER_HPP
#define SNIFFER_HPP
#include <assert.h> /* assert */
#include <inttypes.h>
#include <iostream>
#include <fstream>
#include <bits/stdc++.h>
#include <boost/filesystem.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <pcap/pcap.h>
#include <limits>
#include <stdint.h>
#include <map>

using namespace std;
using namespace boost::filesystem;

#define MALLOC(type, num)  (type *) check_malloc((num) * sizeof(type))

struct Ack_time {
 time_t sec;  // Ack time in seconds
 time_t usec; // Ack time in usec
};

struct flow {
 char *flowID;
 char *saddr;
 char *daddr;
 char *sport;
 char *dport;
 char proto[32];
 int isServer;
 int specialType;
 float score;
 int NumBytes;
 bool protof;
 std::vector<char*> Packets;
 std::vector<struct Ack_time*> Ack_times;

};

typedef struct ethernet_header ethhdr;
struct ethernet_header
{
  u_int8_t  ether_dhost[6];             /* Destination addr     */
  u_int8_t  ether_shost[6];             /* Source addr */
  u_int16_t ether_type;                 /* Packet type */
};

/* IP header structure */
typedef struct ip_header iphdr;
struct ip_header
{
    u_int8_t ihl:4;
    u_int8_t version:4;
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
#define IP_RF 0x8000                    /* Reserved fragment flag */
#define IP_DF 0x4000                    /* Dont fragment flag */
#define IP_MF 0x2000                    /* More fragments flag */
#define IP_OFFMASK 0x1fff               /* Mask for fragmenting bits */
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

/* TCP header structure */
typedef struct tcp_header tcphdr;
struct tcp_header
{
    u_int16_t th_sport;         /* Source port */
    u_int16_t th_dport;         /* Destination port */
    u_int32_t th_seq;           /* Sequence number */
    u_int32_t th_ack;           /* Acknowledgement number */
    u_int8_t th_x2:4;           /* (Unused) */
    u_int8_t th_off:4;          /* Data offset */
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;           /* Window */
    u_int16_t th_sum;           /* Checksum */
    u_int16_t th_urp;           /* Urgent pointer */
};

typedef struct udp_header udphdr;
struct udp_header {
u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_len;         /* datagram length */
        u_short uh_sum;                 /* datagram checksum */
};
#endif /* SNIFFER_HPP */
