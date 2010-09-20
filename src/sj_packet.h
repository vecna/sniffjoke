/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010 vecna <vecna@delirandom.net>
 *                      evilaliv3 <giovanni.pellerano@evilaliv3.org>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SJ_PACKET_H
#define SJ_PACKET_H

#include "sj_defines.h"

#include <vector>
using namespace std;

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define MAXHACKS	7   // Max num of injected hacks for each packet
#define MAXOPTINJ	48  // Max num of byte for option injection: 8 byte ipopt, 40 byte tcpopt

enum source_t { SOURCEUNASSIGNED = 0, ANY_SOURCE = 1, TUNNEL = 2, LOCAL = 3, NETWORK = 4, TTLBFORCE = 5 };
enum status_t { STATUSUNASSIGNED = 0, ANY_STATUS = 1, SEND = 2, KEEP = 3, YOUNG = 4 };
enum judge_t { JUDGEUNASSIGNED = 0, INNOCENT = 1, PRESCRIPTION = 2, GUILTY = 3 };
enum proto_t { PROTOUNASSIGNED = 0, ANY_PROTO = 1, TCP = 2, ICMP = 3, OTHER_IP = 4 };
enum position_t { ANY_POSITION = 0, ANTICIPATION = 1, POSTICIPATION = 2 };
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

	vector<unsigned char> pbuf;
	int pbuf_size;  
	int orig_pktlen;
	
	Packet(int, const unsigned char*, int) ;
	Packet(const Packet &);
	virtual ~Packet(void);

	unsigned int make_pkt_id(const unsigned char*) const;
	void mark(source_t, status_t, judge_t);
	void updatePointers(void);
	/* functions required in TCP/IP packets forging */
	void increasePbuf(unsigned int);
	void resizePayload(unsigned int);
	unsigned int half_cksum(const void *, int);
	unsigned short compute_sum(unsigned int);
	void fixIpTcpSum(void);
};

class HackPacket : public Packet {
public:
	position_t position;

	HackPacket(const Packet &);

	/* sniffjoke hacks applied on the packets */
	void SjH__fake_data(void);
	void SjH__fake_seq(void);
	void SjH__fake_close(void);
	void SjH__zero_window(void);
	void SjH__valid_rst_fake_seq(void);
	void SjH__fake_syn(void);
	void SjH__shift_ack(void);
	void SjH__fake_data_anticipation(void);
	void SjH__fake_data_posticipation(void);

	/* void SjH__half_fake_syn(void); NOT IMPLEMENTED */
	/* void SjH__half_fake_ack(void); NOT IMPLEMENTED */

	void SjH__inject_ipopt(void);
	void SjH__inject_tcpopt(void);
};

#endif /* SJ_PACKET_H */
