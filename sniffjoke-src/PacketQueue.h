#ifndef SJ_PACKET_QUEUE_H
#define SJ_PACKET_QUEUE_H

#include "Packet.h"

class PacketQueue {
public:
	Packet **front;
	Packet **back;

	PacketQueue(int);
	~PacketQueue();
	void insert(int, Packet *);
	void remove(const Packet *);
	Packet* get(bool);
	Packet* get(status_t, source_t, proto_t, bool);
	Packet* get(unsigned int);
};

#endif /* SJ_PACKET_QUEUE_H */
