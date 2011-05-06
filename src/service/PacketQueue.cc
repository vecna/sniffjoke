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

PacketQueue::PacketQueue(void) :
pkt_count(0),
cur_queue(FIRST_QUEUE),
cur_pkt(NULL),
next_pkt(NULL)
{
    LOG_DEBUG("");

    memset(front, 0, sizeof (Packet*)*(QUEUE_NUM));
    memset(back, 0, sizeof (Packet*)*(QUEUE_NUM));
}

PacketQueue::~PacketQueue(void)
{
    LOG_DEBUG("");

    for (uint8_t i = FIRST_QUEUE; i <= LAST_QUEUE; ++i)
    {
        select((queue_t) i);
        while (get() && cur_pkt != NULL)
            delete cur_pkt;
    }
}

void PacketQueue::insert(Packet &pkt, queue_t queue)
{
    if (pkt.queue != QUEUEUNASSIGNED)
        extract(pkt);

    /*
      pkt is not in any queue so:
            pkt.prev == NULL;
            pkt.next == NULL;
     */

    ++pkt_count;
    pkt.queue = queue;
    if (front[queue] == NULL)
    {
        front[queue] = &pkt;
        back[queue] = &pkt;
    }
    else
    {
        pkt.prev = back[queue];
        pkt.next = NULL;
        back[queue]->next = &pkt;
        back[queue] = &pkt;
    }
}

void PacketQueue::insertBefore(Packet &pkt, Packet &ref)
{
    if (pkt.queue != QUEUEUNASSIGNED)
        extract(pkt);

    /*
      pkt is not in any queue so:
            pkt.prev == NULL;
            pkt.next == NULL;
     */

    ++pkt_count;
    pkt.queue = ref.queue;

    if (front[ref.queue] == &ref)
    {
        pkt.prev = NULL;
        pkt.next = &ref;
        ref.prev = &pkt;
        front[ref.queue] = &pkt;
        return;
    }

    /*
     * ref is not front of the queue;
     * so it always has prev that we cand dereference without checking != NULL
     */
    pkt.prev = ref.prev;
    pkt.next = &ref;
    ref.prev->next = &pkt;
    ref.prev = &pkt;
}

void PacketQueue::insertAfter(Packet &pkt, Packet &ref)
{
    if (pkt.queue != QUEUEUNASSIGNED)
        extract(pkt);

    /*
      pkt is not in any queue so:
            pkt.prev == NULL;
            pkt.next == NULL;
     */

    ++pkt_count;
    pkt.queue = ref.queue;

    if (back[ref.queue] == &ref)
    {
        pkt.prev = &ref;
        ref.next = &pkt;
        back[ref.queue] = &pkt;
        return;
    }

    /*
     * ref is not back of the queue;
     * so it always has next that we can dereference without checking != NULL
     */
    pkt.prev = &ref;
    pkt.next = ref.next;
    ref.next->prev = &pkt;
    ref.next = &pkt;
}

void PacketQueue::extract(Packet &pkt)
{
    --pkt_count;
    queue_t queue = pkt.queue;

    if (front[queue] == &pkt)
    {
        if (back[queue] == &pkt)
        {
            front[queue] = NULL;
            back[queue] = NULL;
        }
        else
        {
            /*
             * in this case we have always a next;
             * so we can dereference it without checking != NULL
             */
            front[queue] = front[queue]->next;
            front[queue]->prev = NULL;
        }
        goto remove_reset_pkt;
    }
    else if (back[queue] == &pkt)
    {
        /*
         * in this case we have always a prev;
         * so we can dereference it without checking != NULL
         */
        back[queue] = back[queue]->prev;
        back[queue]->next = NULL;
        goto remove_reset_pkt;
    }

    /*
     * pkt is not front or back of any queue;
     * so it always has prev and next that we cand dereference without checking != NULL
     */
    pkt.prev->next = pkt.next;
    pkt.next->prev = pkt.prev;

remove_reset_pkt:

    pkt.queue = QUEUEUNASSIGNED;
    pkt.prev = NULL;
    pkt.next = NULL;
}

void PacketQueue::drop(Packet &pkt)
{
    if (pkt.queue != QUEUEUNASSIGNED)
        extract(pkt);

    delete &pkt;
}

void PacketQueue::select(queue_t queue)
{
    cur_queue = queue;
    cur_pkt = NULL;
    next_pkt = front[queue];
}

Packet* PacketQueue::get(void)
{
    if (next_pkt != NULL)
    {
        cur_pkt = next_pkt;
        next_pkt = next_pkt->next;
        return cur_pkt; /* FOUND */
    }
    return NULL; /* NOT FOUND */
}

Packet* PacketQueue::getSource(source_t requestSrc)
{
    while (next_pkt != NULL)
    {
        cur_pkt = next_pkt;
        next_pkt = next_pkt->next;

        if (cur_pkt->source == requestSrc)
            return cur_pkt; /* FOUND */
    }
    return NULL; /* NOT FOUND */
}
