#ifndef SJ_SESSIONTRACK_H
#define SJ_SESSIONTRACK_H

#include "Packet.h"
#include "TTLFocus.h"

class SessionTrack {
public:

    SessionTrack *prev;
    SessionTrack *next;

    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int isn;
    unsigned int packet_number;
    bool shutdown;

    TTLFocus *tf;

    SessionTrack( const Packet *pb );
};

#endif /* SJ_SESSIONTRACK_H */
