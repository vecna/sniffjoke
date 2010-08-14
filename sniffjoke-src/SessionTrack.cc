#include "SessionTrack.h"

SessionTrack::SessionTrack(const Packet *pkt)
{
	daddr = pkt->ip->daddr;
	sport = pkt->tcp->source;
	dport = pkt->tcp->dest;
	isn = pkt->tcp->seq;
	packet_number = 1;
	shutdown = false;
}

bool SessionTrack::operator==(const SessionTrack& st) {
	return (st.daddr == daddr && st.sport == sport && st.dport == dport);
}
