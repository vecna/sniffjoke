#include "TTLFocusList.h"

/* 
 * get(unsigned int daddr) is used whenever you need a ttlfocus, this struct is used
 * as reference for each conntrack with the same distination address. every session
 * had access in the same ttlfocus.
 * 
 * in ttlfocus are keep the informations for ttl bruteforcing
 */
 
TTLFocus* TTLFocusList::get(bool must_continue)
{
	static list<TTLFocus>::iterator i = begin();
	
	if (!must_continue)
		i = begin();
	
	if (i++ != end())
		return &(*i);

	return NULL;
}

TTLFocus* TTLFocusList::get(unsigned int daddr)
{
	for (list<TTLFocus>::iterator i = begin(); i != end(); i++) {
		if (i->daddr == daddr)
			return &(*i);
	}
	return NULL;
}
