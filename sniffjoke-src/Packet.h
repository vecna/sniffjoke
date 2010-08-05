#ifndef SJ_PACKET_H
#define SJ_PACKET_H

#include "TTLFocus.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

/* Maximum Transfert Unit */
#define MTU     1500

enum status_t { ANY_STATUS = 16, SEND = 5, KEEP = 10, YOUNG = 82 };
enum source_t { ANY_SOURCE = 3, TUNNEL = 80, LOCAL = 5, NETWORK = 13, TTLBFORCE = 28 };
enum proto_t { ANY_PROTO = 11, TCP = 6, ICMP = 9, OTHER_IP = 7 };
enum judge_t { PRESCRIPTION = 10, GUILTY = 315, INNOCENT = 1 };

class Packet {
public:

    Packet *prev;
    Packet *next;

    /* 
     * this packet_id are useful for avoid packet duplication
     * due to sniffjoke queue, I don't want avoid packet 
     * retrasmission (one of TCP best feature :) 
     */
    unsigned int packet_id;

    proto_t proto;
    source_t source;
    status_t status;
    judge_t wtf;

    TTLFocus *tf;

    struct iphdr *ip;
    struct tcphdr *tcp;
    struct icmphdr *icmp;
    unsigned char *payload;

    unsigned char *pbuf;
    int pbuf_size;  
    int orig_pktlen;

    Packet( int );
    Packet( int, const unsigned char*, int) ;
    Packet( const Packet * );
    ~Packet();
    void updatePointers();
    /* functions required in TCP/IP packets forging */
    void resizePayload( int );
    unsigned int half_cksum( const void *, int );
    unsigned short compute_sum( unsigned int );
    void fixIpTcpSum();
    unsigned int make_pkt_id( const unsigned char* );
};

#endif /* SJ_PACKET_H */
