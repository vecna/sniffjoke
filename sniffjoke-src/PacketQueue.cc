#include "PacketQueue.h"

#include <cstdlib>
#include <stdio.h>

PacketQueue::PacketQueue()
{
    front[HIGH] = NULL;
    back[HIGH] = NULL;

    front[LOW] = NULL;
    back[LOW] = NULL;
}

PacketQueue::~PacketQueue()
{
    Packet *tmp = get(false);
    while(tmp != NULL) {
        delete tmp;
        tmp = get(true);
    }
}

void PacketQueue::insert(priority_t prio, Packet *pkt)
{
    if(pkt->packet_id) {
        Packet* tmp = get(pkt->packet_id);
        if(tmp != NULL)
            drop(tmp);
    }
    if(front[prio] == NULL) {
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
    bool found = false;
    
    for(int i = 0; i<= 1; i++) {
        if(front[i] == pkt && back[i] == pkt) {
            front[i] = back[i] = NULL;
            found = true;
            break;
        } else if(front[i] == pkt) {
            front[i] = front[i]->next;
            front[i]->prev = NULL;
            found = true;
            break;
        } else if (back[i] == pkt) {
            back[i] = back[i]->prev;
            back[i]->next = NULL;
            found = true;
            break;
        }
    }

    if(!found) {
        pkt->prev->next = pkt->next;
        pkt->next->prev = pkt->prev;
    }
    return;
}

void PacketQueue::drop(Packet *pkt)
{
    remove(pkt);
    delete pkt;
}

Packet* PacketQueue::get(bool must_continue)
{
    static int prio = 0;
    static Packet *tmp;
    Packet *ret;
    bool ended = false;

    if (!must_continue) {
        prio = 0;
        tmp = front[prio];
    }
    
    while(!ended) {
        while(tmp != NULL) {
            ret = tmp;
            tmp = tmp->next;
            return ret;
        }
        
        while (tmp == NULL) {
            if(prio < 1) {
                prio++;
                tmp = front[prio];
            } else {
                ended = true;
                break;
            }
        }
    }

    return NULL;
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
    while(tmp != NULL) {
        if (tmp->packet_id == packet_id)
            return tmp;        
        tmp = get(true);
    }
    return NULL;
}
