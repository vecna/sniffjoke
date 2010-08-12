#include "PacketQueue.h"

#include <cstdlib>

PacketQueue::PacketQueue(int queue_levels)
{
	front = new Packet*[queue_levels];
	back = new Packet*[queue_levels];
	for(int i = 0; i < queue_levels; i++) {
		front[i] = NULL;
		back[i] = NULL;
	}
}

PacketQueue::~PacketQueue()
{
	Packet *tmp = get(false);
	while (tmp != NULL) {
		delete tmp;
		tmp = get(true);
	}

	delete front;
	delete back;
}

void PacketQueue::insert(int prio, Packet *pkt)
{
	if (pkt->packet_id) {
		Packet* tmp = get(pkt->packet_id);
		if (tmp != NULL) {
			remove(tmp);
			delete tmp;
		}
	}
	if (front[prio] == NULL) {
		pkt->prev = NULL;
		pkt->next = NULL;
		front[prio] = back[prio] = pkt;
	} else {
		pkt->prev = back[prio];
		pkt->next = NULL;
		back[prio]->next = pkt;
		back[prio] = pkt;
	}
}

void PacketQueue::remove(const Packet *pkt)
{
	for (int i = 0; i<= 1; i++) {
		if (front[i] == pkt) {
			if (back[i] == pkt) {
				front[i] = back[i] = NULL;
			} else {
				front[i] = front[i]->next;
				front[i]->prev = NULL;
			}
			return;
		} else if (back[i] == pkt) {
			back[i] = back[i]->prev;
			back[i]->next = NULL;
			return;
		}
	}

	pkt->prev->next = pkt->next;
	pkt->next->prev = pkt->prev;
	return;
}

Packet* PacketQueue::get(bool must_continue)
{
	static int prio = 0;
	static Packet *tmp;
	Packet *ret;

	if (!must_continue) {
		prio = 0;
		tmp = front[prio];
	}
	
	while (1) {
		while (tmp != NULL) {
			ret = tmp;
			tmp = tmp->next;
			return ret;
		}
		
		while (tmp == NULL) {
			if (prio < 1) {
				prio++;
				tmp = front[prio];
			} else {
				return NULL;
			}
		}
	}
}

Packet* PacketQueue::get(status_t status, source_t source, proto_t proto, bool must_continue) 
{
	Packet *tmp = get(must_continue);
	
	if (tmp == NULL) return NULL;

	do {

		if (status != ANY_STATUS && tmp->status != status)
			continue;

		if (source != ANY_SOURCE && tmp->source != source)
			continue;

		if (proto != ANY_PROTO && tmp->proto != proto)
			continue;

		return tmp;

	} while ((tmp = get(true)) != NULL);

	return NULL;
}

Packet* PacketQueue::get(unsigned int packet_id)
{
	Packet *tmp = get(false);
	while (tmp != NULL) {
		if (tmp->packet_id == packet_id)
			return tmp;		
		tmp = get(true);
	}
	return NULL;
}
