#include "SjUtils.h"
#include "PacketQueue.h"

PacketQueue::PacketQueue(int queue_levels) :
	queue_levels(queue_levels),
{
	internal_log(NULL, DEBUG_LEVEL, "PacketQueue()");	
	front = new Packet*[queue_levels];
	back = new Packet*[queue_levels];
	for(int i = 0; i < queue_levels; i++) {
		front[i] = NULL;
		back[i] = NULL;
	}
	
	int cur_prio = 0;
	Packet *cur_pkt = NULL;
}

PacketQueue::~PacketQueue(void)
{
	internal_log(NULL, DEBUG_LEVEL, "~PacketQueue()");
	Packet *tmp = get(false);
	while (tmp != NULL) {
		delete tmp;
		tmp = get(true);
	}
}

void PacketQueue::insert(int prio, Packet &pkt)
{
	if (pkt.packet_id) {
		Packet* tmp = get(pkt.packet_id);
		if (tmp != NULL) {
			remove(*tmp);
			delete tmp;
		}
	}
	if (front[prio] == NULL) {
		pkt.prev = NULL;
		pkt.next = NULL;
		front[prio] = back[prio] = &pkt;
	} else {
		pkt.prev = back[prio];
		pkt.next = NULL;
		back[prio]->next = &pkt;
		back[prio] = &pkt;
	}
}

void PacketQueue::remove(const Packet &pkt)
{
	for (int i = 0; i < queue_levels; i++) {
		if (front[i] == &pkt) {
			if (back[i] == &pkt) {
				front[i] = back[i] = NULL;
			} else {
				front[i] = front[i]->next;
				front[i]->prev = NULL;
			}
			return;
		} else if (back[i] == &pkt) {
			back[i] = back[i]->prev;
			back[i]->next = NULL;
			return;
		}
	}

	pkt.prev->next = pkt.next;
	pkt.next->prev = pkt.prev;
	return;
}

Packet* PacketQueue::get(bool must_continue)
{
	Packet *ret;

	if (!must_continue) {
		cur_prio = 0;
		cur_pkt = front[cur_prio];
	}
	
	while (1) {
		while (cur_pkt != NULL) {
			ret = cur_pkt;
			cur_pkt = cur_pkt->next;
			return ret;
		}
		
		while (cur_pkt == NULL) {
			cur_prio++;
			if (cur_prio < queue_levels) {
				cur_pkt = front[cur_prio];
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
