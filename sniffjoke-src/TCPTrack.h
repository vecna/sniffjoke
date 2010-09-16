#ifndef SJ_TCPTRACK_H
#define SJ_TCPTRACK_H

#include "defines.h"

#include "SjConf.h"
#include "Packet.h"
#include "PacketQueue.h"
#include "SessionTrack.h"
#include "TTLFocus.h"


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
	void inject_hack_in_queue(const Packet&, const SessionTrack*);
	void enque_ttl_probe(const Packet&, TTLFocus&);
	bool analyze_ttl_stats(TTLFocus&);
	void mark_real_syn_packets_SEND(unsigned int);
	void last_pkt_fix(Packet&);

	/* functions for decrete which, and if, inject hacks */
	bool check_uncommon_tcpopt(const struct tcphdr*);
	HackPacket* packet_orphanotrophy(const Packet&, int, judge_t, int);
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
