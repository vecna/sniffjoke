#ifndef SJ_TTLFOCUS_H
#define SJ_TTLFOCUS_H

#include "defines.h"

#include <map>
using namespace std;

enum ttlsearch_t { TTL_KNOWN = 1, TTL_BRUTALFORCE = 3, TTL_UNKNOWN = 9 };

class TTLFocus {
public:

	unsigned int daddr;
	unsigned char expiring_ttl;
	unsigned char min_working_ttl;
	unsigned char sent_probe;
	unsigned char received_probe;
	unsigned short puppet_port;
	unsigned int rand_key;
	ttlsearch_t status;

	TTLFocus(unsigned int);
	TTLFocus(const TTLFocus& cpy);
};

class TTLFocusMap : public map<const unsigned int, TTLFocus> {
public:
	TTLFocusMap();
        ~TTLFocusMap();
        void dump();
        void load();
};


#endif /* SJ_TTLFOCUS_H */
