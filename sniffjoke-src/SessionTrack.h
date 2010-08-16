#ifndef SJ_SESSIONTRACK_H
#define SJ_SESSIONTRACK_H

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

struct SessionTrackKey {
public:
	unsigned int daddr;
	unsigned short sport;
	unsigned short dport;
};

struct SessionTrackCmp {
	bool operator()(struct SessionTrackKey a, struct SessionTrackKey b) const {
		if(a.daddr < b.daddr) {
			return true;
		} else if(a.daddr > b.daddr) {
			return false;
		} else if(a.daddr == b.daddr) {
			if(a.sport < b.sport) {
				return true;
			} else if(a.sport > b.sport) {
				return false;
			} else if(a.sport == b.sport) {
				if(a.dport < b.dport)
					return true;
				else
					return false;
			}
		}
	}	
};

typedef map<SessionTrackKey, SessionTrack, SessionTrackCmp> SessionTrackMap;

#endif /* SJ_SESSIONTRACK_H */
