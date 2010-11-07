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

#include "UserConf.h"
#include "hardcoded-defines.h"

#include <vector>
using namespace std;

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include <cstdio>
#include <cstdlib>

#include <netinet/in.h>
#include <arpa/inet.h>


/* if the packet is inject from sniffjoke is marked with the evilbit */
enum evilbit_t { MORALITYUNASSIGNED = 0, GOOD = 1, EVIL = 2 };

/* the source_t is the nature of the packet, ANY_SOURCE is used at catch-all */
enum source_t { SOURCEUNASSIGNED = 0, ANY_SOURCE = 1, TUNNEL = 2, LOCAL = 3, NETWORK = 4, TTLBFORCE = 5 };

/* status mean what sniffjoke has to do with the packet. KEEP is used when a packet is 
 * delayed, YOUNG when a packet was created by sniffjoke, SEND has to be send */
enum status_t { STATUSUNASSIGNED = 0, ANY_STATUS = 1, SEND = 2, KEEP = 3, YOUNG = 4 };

/* Every sniffjoke packet is based on be discarged from the remote host and accepted from
 * the sniffer, in order to obtain the sniffer tracking poisoning, those marker mean if the
 * packet need to be plain and correct (INNOCENT) to expire prematurely (PRESCRIPTION) to be 
 * consider bad and discarged (GUILTY, corrupt the TCP checksum), MALFORMED (weird ip options)
 * or a random choose of those */
enum judge_t { JUDGEUNASSIGNED = 0, INNOCENT = 1, PRESCRIPTION = 2, GUILTY = 3, MALFORMED = 4, RANDOMDAMAGE = 5 };

/* an enum for the proto. ANY_PROTO is the catch-all used when the queue(s) are queryed */
enum proto_t { PROTOUNASSIGNED = 0, ANY_PROTO = 1, TCP = 2, ICMP = 3, OTHER_IP = 4 };

/* a sniffjoke packet should be send before the oroginal packet or after the original packet */
enum position_t { POSITIONUNASSIGNED = 0, ANY_POSITION = 1, ANTICIPATION = 2, POSTICIPATION = 3 };

class Packet {
public:

	Packet* prev;
	Packet* next;

	/* 
	 * this packet_id are useful to avoid packet duplication
	 * due to sniffjoke queue, I don't want avoid packet 
	 * retrasmission, one of TCP best features :) 
	 * 
	 * example of this are duplicated SYN that can happens
	 * when the first SYN is blocked for TTL bruteforce routine. 
	 * 
	 */
	unsigned int packet_id;

	evilbit_t evilbit;
	source_t source;
	status_t status;
	judge_t wtf;
	proto_t proto;
	position_t position;	

	struct iphdr *ip;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	unsigned char *payload;

	vector<unsigned char> pbuf;
	int orig_pktlen;
	
	Packet(const unsigned char*, int);
	Packet(const Packet &);
	virtual ~Packet(void) {};

	unsigned int make_pkt_id(const unsigned char*) const;
	void mark(source_t, status_t, evilbit_t);
	void mark(source_t, status_t, judge_t, evilbit_t);
	void updatePointers(void);
	
	unsigned int half_cksum(const void*, int);
	unsigned short compute_sum(unsigned int);
	void fixIpTcpSum(void);

	/* autochecking */
	bool checkUncommonTCPOPT(void);
	bool checkUncommonIPOPT(void);
	bool SelfIntegrityCheck(const char *);
	
	/* functions required in TCP/IP packets forging */
	void increasePbuf(unsigned int);
	void resizePayload(unsigned int);
	void fillRandomPayload(void);

	/* MALFORMED hacks and distortion of INNOCENT packets */
	void Inject_BAD_IPOPT(void);
	void Inject_GOOD_IPOPT(void);
        void Inject_BAD_TCPOPT(void);
	void Inject_GOOD_TCPOPT(void);

	/* utilities */
	void selflog(const char *, const char *);
	char debugbuf[LARGEBUF];
};

/* 
 * HackPacket - pure virtual methods 
 *
 * Following this howto: http://www.faqs.org/docs/Linux-mini/C++-dlopen.html
 * we understand how to do. HackPacket classes is implemented by the external
 * module and the programmer should implement Condition and createHack, constructor
 * and distructor methods.
 *
 * at the end of every plugin code, is required the two extern "C", pointing
 * to the constructor and the destructor method. the constructon instace
 * your/the plugin with your/the Condition and createHack code.
 *
****/

/* the Frequency meaning is explained in http://www.delirandom.net/sniffjoke/plugin */
enum Frequency { RARE = 1, COMMON = 2, PACKETS10PEEK = 3, PACKETS30PEEK = 4,
		 TIMEBASED5S = 5, TIMEBASED20S = 6, STARTPEEK = 7, LONGPEEK = 8 };

class HackPacket {
public:
	Frequency hack_frequency;
	const char *hackName;

	/* set by constructor of the hacks classess */
	int track_index;

	/* number of packets generated from the hack */
	int num_pkt_gen;

	virtual bool Condition(const Packet &) { return true; };
	virtual Packet *createHack(Packet &) = 0;
};

typedef HackPacket * constructor_f(const int); 
	// extern(ed) "C" as HackPacket* CreateHackObject
typedef void destructor_f(HackPacket *);  
	// extern(ed) "C" as void DeleteHackObject

#endif /* SJ_PACKET_H */
