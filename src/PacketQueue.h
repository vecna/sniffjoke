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

#ifndef SJ_PACKET_QUEUE_H
#define SJ_PACKET_QUEUE_H

#include "Utils.h"
#include "Packet.h"

enum queue_t { Q_ANY = -1, Q_PRIORITY_SEND = 0, Q_SEND = 1, Q_YOUNG = 2, Q_KEEP = 3 };
#define FIRST_QUEUE (Q_PRIORITY_SEND)
#define LAST_QUEUE (Q_KEEP)

class PacketQueue {
private:
	Packet **front;
	Packet **back;
	bool iterate_through_all;
	unsigned int cur_queue;
	Packet *cur_pkt;
	Packet *next_pkt;
public:

	PacketQueue();
	~PacketQueue(void);
	void insert(queue_t, Packet &);
	void insert_before(Packet &, Packet &);
	void insert_after(Packet &, Packet &);
	void remove(const Packet &);
	void select(queue_t);
	Packet* get();
	Packet* get(source_t, proto_t);
	Packet* get(unsigned int);
};

#endif /* SJ_PACKET_QUEUE_H */
