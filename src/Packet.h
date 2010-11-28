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

#include "Utils.h"
#include "UserConf.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

using namespace std;

/* IT'S FUNDAMENTAL TO HAVE ALL ENUMS VALUES AS POWERS OF TWO TO PERMIT OR MASKS */

enum queue_t { QUEUEUNASSIGNED = -1, YOUNG = 0,	KEEP = 1, SEND = 2, PRIORITY_SEND = 3 };

/* if the packet is inject from sniffjoke is marked with the evilbit */
enum evilbit_t { MORALITYUNASSIGNED = 0, GOOD = 1, EVIL = 2 };

/* the source_t is the nature of the packet, ANY_SOURCE is used at catch-all */
enum source_t { SOURCEUNASSIGNED = 0, TUNNEL = 1, NETWORK = 2, LOCAL = 4, TTLBFORCE = 8 };

/* Every sniffjoke packet is based on be discarged from the remote host and accepted from
 * the sniffer, in order to obtain the sniffer tracking poisoning, those marker mean if the
 * packet need to be plain and correct (INNOCENT) to expire prematurely (PRESCRIPTION) to be 
 * consider bad and discarged (GUILTY, corrupt the TCP checksum), MALFORMED (weird ip options)
 * or a random choose of those */
enum judge_t { JUDGEUNASSIGNED = 0, INNOCENT = 1, PRESCRIPTION = 2, GUILTY = 4, MALFORMED = 8, RANDOMDAMAGE = 16 };

/* an enum for the proto. ANY_PROTO is the catch-all used when the queue(s) are queryed */
enum proto_t { PROTOUNASSIGNED = 0, TCP = 1, ICMP = 2, OTHER_IP = 4 };

/* a sniffjoke packet should be send before the oroginal packet or after the original packet */
enum position_t { POSITIONUNASSIGNED = 0, ANY_POSITION = 1, ANTICIPATION = 2, POSTICIPATION = 4 };

class Packet {
private:
	queue_t queue;
	Packet *prev;
	Packet *next;
	friend class PacketQueue;

	bool check_evil_packet(const unsigned char *buff, unsigned int nbyte);

public:
	evilbit_t evilbit;
	source_t source;
	judge_t wtf;
	proto_t proto;
	position_t position;	

	vector<unsigned char> pbuf;

	struct iphdr *ip;
	unsigned int iphdrlen;

	struct tcphdr *tcp;
	unsigned int tcphdrlen;

	unsigned char *payload;
	unsigned int datalen;

	struct icmphdr *icmp;
	
	Packet(const unsigned char *, int);
	Packet(const Packet &);
	virtual ~Packet(void) {};

	void updatePacketMetadata(void);

	void mark(source_t, evilbit_t);
	void mark(source_t, judge_t, evilbit_t);
	
	/* IP/TCP checksum functions */
	unsigned int half_cksum(const void *, int);
	unsigned short compute_sum(unsigned int);
	void fixIpTcpSum(void);

	/* autochecking */
	bool selfIntegrityCheck(const char *);
	
	/* functions required in TCP/IP packets forging */
	void IPHDR_resize(unsigned int);
	void TCPHDR_resize(unsigned int);
	void TCPPAYLOAD_resize(unsigned int);
	void TCPPAYLOAD_fillrandom(void);

	/* MALFORMED hacks and distortion of INNOCENT packets */
	bool Inject_IPOPT(bool, bool);
	bool Inject_TCPOPT(bool, bool);

	/* utilities */
	void selflog(const char *, const char *) const;
	char debug_buf[LARGEBUF];
};

#endif /* SJ_PACKET_H */
