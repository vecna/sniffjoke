#include "TTLFocusList.h"

#include <cstdlib>

TTLFocusList::TTLFocusList()
{
    front = back = NULL;
}

TTLFocusList::~TTLFocusList()
{
    TTLFocus *tmp = get(false);
    while(tmp != NULL) {
        delete tmp;
        tmp = get(true);
    }
}

void TTLFocusList::insert(TTLFocus* ttlfocus)
{
    if(front == NULL) {
        ttlfocus->prev = NULL;
        ttlfocus->next = NULL;
        front = back = ttlfocus;
    } else {
        ttlfocus->prev = back;
        ttlfocus->next = NULL;
        back->next = ttlfocus;
        back = ttlfocus;
    }
}

void TTLFocusList::remove(TTLFocus* ttlfocus)
{
    if(front == ttlfocus && back == ttlfocus) {
        front = back = NULL;
        return;         
    } else if(front == ttlfocus) {
        front = front->next;
        front->prev = NULL;
        return;
    } else if (back == ttlfocus) {
        back = back->prev;
        back->next = NULL;
        return;
    }

    ttlfocus->prev->next = ttlfocus->next;
    ttlfocus->next->prev = ttlfocus->prev;
    return;
}


TTLFocus* TTLFocusList::get(bool must_continue)
{
    static TTLFocus *tmp;
    TTLFocus *ret;

    if (!must_continue) {
        tmp = front;
    }
    
    while(tmp != NULL) {
        ret = tmp;
        tmp = tmp->next;
        return ret;
    }
        
    return NULL;
}

/* 
 * get(unsigned int daddr) is used whenever you need a ttlfocus, this struct is used
 * as reference for each conntrack with the same distination address. every session
 * had access in the same ttlfocus.
 * 
 * in ttlfocus are keep the informations for ttl bruteforcing
 */
TTLFocus* TTLFocusList::get(unsigned int daddr)
{
    TTLFocus *tmp = get(false);
    while(tmp != NULL) {
         if (tmp->daddr == daddr)
            return tmp;
        tmp = get(true);
    }
    return NULL;
}
