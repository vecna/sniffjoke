#ifndef SJ_PACKET_QUEUE_H
#define SJ_PACKET_QUEUE_H

#include "defines.h"

#include "Packet.h"

class PacketQueue {
private:
	Packet **front;
	Packet **back;
	unsigned int queue_levels;
	unsigned int cur_prio;
	Packet *cur_pkt;
public:

	PacketQueue(int);
	~PacketQueue();
	void insert(int, Packet &);
	void remove(const Packet &);
	Packet* get(bool);
	Packet* get(status_t, source_t, proto_t, bool);
	Packet* get(unsigned int);
};

#endif /* SJ_PACKET_QUEUE_H */
