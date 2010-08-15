#ifndef SJ_SESSIONTRACK_H
#define SJ_SESSIONTRACK_H

#include "Packet.h"
#include "TTLFocus.h"

class SessionTrack {
public:
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned int isn;
	unsigned int packet_number;
	bool shutdown;

	SessionTrack(const Packet &pb);
	bool operator==(const SessionTrack&);
};

#endif /* SJ_SESSIONTRACK_H */
