#ifndef SJ_TCPTRACK_H
#define SJ_TCPTRACK_H

#include "SjConf.h"
#include "Packet.h"
#include "PacketQueue.h"
#include "SessionTrack.h"
#include "SessionTrackList.h"
#include "TTLFocus.h"


class TCPTrack {
private:
	int maxttlprobe;	/* max probe for discern ttl*/

	PacketQueue p_queue;
	SessionTrackList sex_list;
	TTLFocusMap ttlfocus_map;

	/* as usually in those classes*/
	struct sj_config *runcopy;

	/* main function of packet analysis, called by analyze_packets_queue*/
	Packet* analyze_incoming_icmp(Packet&);
	Packet* analyze_incoming_synack(Packet&);
	Packet* analyze_incoming_rstfin(Packet&);
	void manage_outgoing_packets(Packet&);

	/* functions forging/mangling packets que, ttl analysis*/
	bool check_evil_packet(const unsigned char*, int);
	void inject_hack_in_queue(const Packet&, const SessionTrack*);
	void enque_ttl_probe(const Packet&, TTLFocus&);
	bool analyze_ttl_stats(TTLFocus&);
	void mark_real_syn_packets_SEND(unsigned int);
	void last_pkt_fix(Packet&);

	/* functions for decrete which, and if, inject hacks*/
	bool check_uncommon_tcpopt(const struct tcphdr*);
	Packet* packet_orphanotrophy(const Packet&, int);
	bool percentage(float, int);
	float logarithm(int);

	/* the sniffjoke hack apply on the packets*/
	void SjH__fake_data(Packet&);
	void SjH__fake_seq(Packet&);
	void SjH__fake_syn(Packet&);
	void SjH__fake_close(Packet&);
	void SjH__zero_window(Packet&);

	/* sadly, those hacks require some analysis*/
	void SjH__shift_ack(Packet&);
	void SjH__valid_rst_fake_seq(Packet&);

	/* void SjH__half_fake_syn(Packet&); NOT IMPLEMENTED*/
	/* void SjH__half_fake_ack(Packet&); NOT IMPLEMENTED*/

	/* size of header to fill with wild IP/TCP options*/
	void SjH__inject_ipopt(Packet&);
	void SjH__inject_tcpopt(Packet&);

	/* functions for working on queues and lists*/
	SessionTrack* init_sessiontrack(const Packet&);
	TTLFocus* init_ttlfocus(unsigned int);

public:
	TCPTrack(SjConf*);
	~TCPTrack();

	bool writepacket(const source_t, const unsigned char*, int);
	Packet* readpacket();
	void analyze_packets_queue();

	/* force all packets sendable, used from NetIO for avoid Sn mangling*/
	void force_send(void);
};

#endif /* SJ_TCPTRACK_H*/
