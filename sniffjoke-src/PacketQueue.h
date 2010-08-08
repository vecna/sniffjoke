#ifndef SJ_PACKET_QUEUE_H
#define SJ_PACKET_QUEUE_H

#include "Packet.h"

enum priority_t { HIGH = 0, LOW = 1 };

class PacketQueue {
public:
	Packet *front[2];
	Packet *back[2];

	PacketQueue();
	~PacketQueue();
	void insert( priority_t, Packet * );
	void remove( const Packet * );
	void drop( Packet * );
	Packet* get( bool );
	Packet* get( status_t, source_t, proto_t, bool );
	Packet* get( unsigned int );
};

#endif /* SJ_PACKET_QUEUE_H */
