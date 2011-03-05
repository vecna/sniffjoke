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

#define FIRST_QUEUE (YOUNG)
#define LAST_QUEUE  (SEND)
#define QUEUE_NUM   (LAST_QUEUE + 1)

class PacketQueue
{
private:
    uint32_t pkt_count;
    Packet *front[QUEUE_NUM];
    Packet *back[QUEUE_NUM];
    queue_t cur_queue;
    Packet *cur_pkt;
    Packet *next_pkt;

public:
    PacketQueue(void);
    ~PacketQueue(void);
    void insert(Packet &, queue_t);
    void insertBefore(Packet &, Packet &);
    void insertAfter(Packet &, Packet &);
    void extract(Packet &);
    void drop(Packet &);
    void select(queue_t);
    Packet* get(void);
    Packet* getSource(source_t);

    uint32_t size(void)
    {
        return pkt_count;
    };
};

#endif /* SJ_PACKET_QUEUE_H */
