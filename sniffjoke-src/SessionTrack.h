#ifndef SJ_SESSIONTRACK_H
#define SJ_SESSIONTRACK_H

#include "defines.h"

#include "Packet.h"
#include "TTLFocus.h"

#include <cstdio>

#include <map>
using namespace std;

class SessionTrack {
public:
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
	unsigned int isn;
	unsigned int packet_number;
	bool shutdown;

	SessionTrack(const Packet &pb);
};

class SessionTrackKey {
public:
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
	bool operator<(SessionTrackKey comp) const;
};

typedef map<SessionTrackKey, SessionTrack> SessionTrackMap;

#endif /* SJ_SESSIONTRACK_H */
