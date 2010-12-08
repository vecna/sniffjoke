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

#include "Utils.h"
#include "UserConf.h"
#include "Packet.h"
#include "PacketQueue.h"
#include "SessionTrack.h"
#include "TTLFocus.h"
#include "HackPool.h"

class TCPTrack {
private:
	const struct sj_config &runconfig;
	
	struct timespec clock;			/* clock time updated by analyze_packet_queue */
		
#define APQ_MANAGMENT_ROUTINE_TIMER	60	/* manager routine time interval in seconds */

	PacketQueue p_queue;
	SessionTrackMap &sessiontrack_map;
	TTLFocusMap &ttlfocus_map;
	HackPool &hack_pool;

	bool percentage(uint32_t, Frequency, Strength);

	void inject_ttlprobe_in_queue(TTLFocus &);

	/* this functions are called inside analyze_packets_queue;
	 * boolean functions return true if the packet must be sended */ 
	bool analyze_incoming_icmp(Packet &);
	void analyze_incoming_tcp_ttl(Packet &);
	bool analyze_incoming_tcp_synack(Packet &);
	bool analyze_incoming_tcp_rstfin(Packet &);
	bool analyze_outgoing(Packet &);
	bool analyze_keep(Packet &);

	void inject_hack_in_queue(Packet &);
	bool last_pkt_fix(Packet &);

public:
	TCPTrack(const sj_config &, HackPool &, SessionTrackMap &, TTLFocusMap &);
	~TCPTrack(void);

	void writepacket(source_t, const unsigned char *, int);
	Packet* readpacket(source_t);
	deadline analyze_packets_queue();
	void force_send(void);
};

#endif /* SJ_TCPTRACK_H */
