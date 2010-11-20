/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010 vecna <vecna@delirandom.net>
 *                      evilaliv3 <giovanni.pellerano@evilaliv3.org>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "PacketQueue.h"

PacketQueue::PacketQueue() :
	front(new Packet*[LAST_QUEUE + 1]),
	back(new Packet*[LAST_QUEUE + 1]),
	iterate_through_all(true),
	cur_queue(FIRST_QUEUE),
	cur_pkt(NULL),
	next_pkt(NULL)
{
	debug.log(DEBUG_LEVEL, __func__);

	memset(front, NULL, sizeof(Packet*)*LAST_QUEUE + 1);
	memset(back, NULL, sizeof(Packet*)*LAST_QUEUE + 1);
}


PacketQueue::~PacketQueue(void)
{
	debug.log(DEBUG_LEVEL, __func__);

	select(Q_ANY);
	while (get() && cur_pkt != NULL) {
		delete cur_pkt;
	}

	delete[] front;
	delete[] back;
}

void PacketQueue::insert(queue_t queue, Packet &pkt)
{
	if (front[queue] == NULL) {
		pkt.prev = NULL;
		pkt.next = NULL;
		front[queue] = back[queue] = &pkt;
	} else {
		pkt.prev = back[queue];
		pkt.next = NULL;
		back[queue]->next = &pkt;
		back[queue] = &pkt;
	}
}

void PacketQueue::insert_before(Packet &pkt, Packet &ref)
{
	for (unsigned int i = FIRST_QUEUE; i <= LAST_QUEUE; i++) {
		if (front[i] == &ref) {
			pkt.prev = NULL;
			pkt.next = &ref;
			ref.prev = &pkt;
			front[i] = &pkt;
			return;
		}
	}
	
	pkt.prev = ref.prev;
	if(ref.prev != NULL)
		ref.prev->next = &pkt;
	pkt.next = &ref;
	ref.prev = &pkt;
}

void PacketQueue::insert_after(Packet &pkt, Packet &ref)
{
	for (unsigned int i = FIRST_QUEUE; i <= LAST_QUEUE; i++) {
		if (back[i] == &ref) {
			pkt.prev = &ref;
			pkt.next = NULL;
			ref.next = &pkt;
			back[i] = &pkt;
			return;
		}
	}
	
	pkt.next = ref.next;
	if(ref.next != NULL)
		ref.next->prev = &pkt;
	pkt.prev = &ref;
	ref.next = &pkt;
}

void PacketQueue::remove(const Packet &pkt)
{
	for (unsigned int i = FIRST_QUEUE; i <= LAST_QUEUE; i++) {
		if (front[i] == &pkt) {
			if (back[i] == &pkt) {
				front[i] = NULL;
				back[i] = NULL;
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

	if(pkt.prev != NULL)
		pkt.prev->next = pkt.next;

	if(pkt.next != NULL)
		pkt.next->prev = pkt.prev;

	return;
}

void PacketQueue::select(queue_t queue) {
	if(queue == Q_ANY) {
		cur_queue = FIRST_QUEUE;
		iterate_through_all = true;
	} else {
		cur_queue = queue;
		iterate_through_all = false;
	}

	cur_pkt = NULL;
	next_pkt = front[cur_queue];
}

Packet* PacketQueue::get()
{
	while (1) {
		if (next_pkt != NULL) {
			cur_pkt = next_pkt;
			next_pkt = next_pkt->next;
			return cur_pkt; /* FOUND */
		}
		
		if (iterate_through_all && cur_queue != LAST_QUEUE) {
			cur_queue++;
			next_pkt = front[cur_queue];
		} else {
			return NULL; /* NOT FOUND */
		}
	}
}
