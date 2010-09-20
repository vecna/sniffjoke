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
#ifndef SJ_TCPTRACK_H
#define SJ_TCPTRACK_H

#include "sj_conf.h"
#include "sj_packet.h"
#include "sj_packetqueue.h"
#include "sj_sessiontrack.h"
#include "sj_ttlfocus.h"

class TCPTrack {
private:
	PacketQueue p_queue;
	SessionTrackMap sex_map;
	TTLFocusMap ttlfocus_map;

	struct sj_config *runcopy;

	/* main function of packet analysis, called by analyze_packets_queue */
	Packet* analyze_incoming_icmp(Packet&);
	Packet* analyze_incoming_synack(Packet&);
	Packet* analyze_incoming_rstfin(Packet&);
	void manage_outgoing_packets(Packet&);

	/* functions forging/mangling packets que, ttl analysis */
	bool check_evil_packet(const unsigned char*, int);
	void inject_hack_in_queue(Packet&, const SessionTrack*);
	void enque_ttl_probe(const Packet&, TTLFocus&);
	bool analyze_ttl_stats(TTLFocus&);
	void mark_real_syn_packets_SEND(unsigned int);
	void last_pkt_fix(Packet&);

	/* functions for decrete which, and if, inject hacks */
	bool check_uncommon_tcpopt(const struct tcphdr*);
	bool percentage(float, int);
	float logarithm(int);

	/* functions for working on queues and lists */
	SessionTrack* init_sessiontrack(const Packet&);
	SessionTrack* clear_session(SessionTrackMap::iterator stm_it);
	TTLFocus* init_ttlfocus(unsigned int);

public:
	TCPTrack(SjConf*);
	~TCPTrack(void);

	bool writepacket(const source_t, const unsigned char*, int);
	Packet* readpacket(void);
	void analyze_packets_queue(void);

	/* force all packets sendable, used from NetIO for avoid Sn mangling */
	void force_send(void);
};

#endif /* SJ_TCPTRACK_H */
