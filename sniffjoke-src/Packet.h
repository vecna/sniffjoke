#ifndef SJ_PACKET_H
#define SJ_PACKET_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define MAXHACKS	7   // Max num of injected hacks
#define MAXOPTINJ	48  // Max num of byte for option injection: 8 byte ipopt, 40 byte tcpopt

enum source_t { SOURCEUNASSIGNED = 0, ANY_SOURCE = 1, TUNNEL = 2, LOCAL = 3, NETWORK = 4, TTLBFORCE = 5 };
enum status_t { STATUSUNASSIGNED = 0, ANY_STATUS = 1, SEND = 2, KEEP = 3, YOUNG = 4 };
enum judge_t { JUDGEUNASSIGNED = 0, INNOCENT = 1, PRESCRIPTION = 2, GUILTY = 3 };
enum proto_t { PROTOUNASSIGNED = 0, ANY_PROTO = 1, TCP = 2, ICMP = 3, OTHER_IP = 4 };
enum checksum_fix_t { NO = 0, FIX_IP_CHECKSUM = 1, FIX_TCP_CHECKSUM = 2, FIX_BOTH_CHECKSUM = 3 };

class Packet {
public:

	Packet* prev;
	Packet* next;

	/* 
	 * this packet_id are useful for avoid packet duplication
	 * due to sniffjoke queue, I don't want avoid packet 
	 * retrasmission (one of TCP best feature :) 
	 */
	unsigned int packet_id;

	source_t source;
	status_t status;
	judge_t wtf;
	proto_t proto;

	struct iphdr *ip;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	unsigned char *payload;

	unsigned char *pbuf;
	int pbuf_size;  
	int orig_pktlen;
	
	Packet(int, const unsigned char*, int) ;
	Packet(const Packet &);
	virtual ~Packet();

	unsigned int make_pkt_id(const unsigned char*) const;
	void mark(source_t, status_t, judge_t);
	void updatePointers();
	/* functions required in TCP/IP packets forging */
	void increasePbuf(unsigned int);
	void resizePayload(unsigned int);
	unsigned int half_cksum(const void *, int);
	unsigned short compute_sum(unsigned int);
	void fixIpTcpSum();
};

class HackPacket : public Packet {
public:

	HackPacket(const Packet &);

	/* sniffjoke hacks applied on the packets */
	void SjH__fake_data();
	void SjH__fake_seq();
	void SjH__fake_close();
	void SjH__zero_window();
	void SjH__valid_rst_fake_seq();
	void SjH__fake_syn();
	void SjH__shift_ack();

	/* void SjH__half_fake_syn(); NOT IMPLEMENTED */
	/* void SjH__half_fake_ack(); NOT IMPLEMENTED */

	void SjH__inject_ipopt();
	void SjH__inject_tcpopt();
};

#endif /* SJ_PACKET_H */
