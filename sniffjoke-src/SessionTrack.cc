#include "SjUtils.h"
#include "SessionTrack.h"

SessionTrack::SessionTrack(const Packet &pkt) :
	daddr(pkt.ip->daddr),
	sport(pkt.tcp->source),
	dport(pkt.tcp->dest),
	isn(pkt.tcp->seq),
	packet_number(1),
	shutdown(false)
{}

bool SessionTrackKey::operator<(SessionTrackKey comp) const {
	if (daddr < comp.daddr) {
		return true;
	} else if (daddr > comp.daddr) {
		return false;
	} else if (daddr == comp.daddr) {
		if (sport < comp.sport) {
			return true;
		} else if (sport > comp.sport) {
			return false;
		} else if (sport == comp.sport) {
			if (dport < comp.dport)
				return true;
			else
				return false;
		}
	}
}
