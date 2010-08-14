#ifndef SJ_PACKET_H
#define SJ_PACKET_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

enum status_t { ANY_STATUS = 0, SEND = 2, KEEP = 3, YOUNG = 4 };
enum source_t { ANY_SOURCE = 0, TUNNEL = 2, LOCAL = 3, NETWORK = 4, TTLBFORCE = 5 };
enum proto_t { ANY_PROTO = 0, TCP = 1, ICMP = 2, OTHER_IP = 3 };
enum judge_t { PRESCRIPTION = 0, GUILTY = 1, INNOCENT = 2 };

class Packet {
private:
	unsigned int make_pkt_id(const unsigned char*);

public:

	Packet* prev;
	Packet* next;

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

	struct iphdr *ip;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	unsigned char *payload;

	unsigned char *pbuf;
	int pbuf_size;  
	int orig_pktlen;

	Packet(int, const unsigned char*, int) ;
	Packet(const Packet *);
	~Packet();

	void updatePointers();
	/* functions required in TCP/IP packets forging */
	void resizePayload(int);
	unsigned int half_cksum(const void *, int);
	unsigned short compute_sum(unsigned int);
	void fixIpChecksum();
	void fixTcpChecksum();
};

#endif /* SJ_PACKET_H */
