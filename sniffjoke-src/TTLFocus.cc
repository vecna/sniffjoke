#include "TTLFocus.h"
#include "defines.h"
#include "SjUtils.h"

#include <cerrno>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

TTLFocus::TTLFocus(unsigned int destip) :
	daddr(destip),
	min_working_ttl(0xff),
	expiring_ttl(0),
	sent_probe(0),
	received_probe(0),
	puppet_port(htons((random() % 15000) + 1100)),
	rand_key(random()),
	status(TTL_BRUTALFORCE)
{}

TTLFocus::TTLFocus(const TTLFocus& cpy) :
	daddr(cpy.daddr),
	min_working_ttl(cpy.min_working_ttl),
	expiring_ttl(cpy.expiring_ttl),
	sent_probe(cpy.sent_probe),
	received_probe(cpy.received_probe),
	puppet_port(cpy.puppet_port),
	rand_key(cpy.rand_key),
	status(cpy.status)
{}


TTLFocusMap::TTLFocusMap() {
	load();
}
TTLFocusMap::~TTLFocusMap() {
	dump();
}

void TTLFocusMap::load() {
	FILE *loadfd;
	int i, ret;
	TTLFocus *tmp = (TTLFocus*)malloc(sizeof(TTLFocus));

	internal_log(NULL, VERBOSE_LEVEL, "loading ttlfocusmap from %s",  TTLFOCUSMAP_FILE);
	
	loadfd = fopen(TTLFOCUSMAP_FILE, "r");
	if(loadfd == NULL) {
		internal_log(NULL, ALL_LEVEL, "unable to access %s: sniffjoke will start without a ttl cache", TTLFOCUSMAP_FILE);
        	return;
        }

	while( ret = (fread(tmp, sizeof(TTLFocus), 1, loadfd) == sizeof(TTLFocus)) ) {
		insert(pair<int, TTLFocus>(tmp->daddr, *tmp));
	}

	fclose(loadfd);

	if(ret != 0) {
		unlink(TTLFOCUSMAP_FILE);
		internal_log(NULL, ALL_LEVEL, "unable to read ttlfocus from %s: %s",
			TTLFOCUSMAP_FILE, strerror(errno)
		);
		check_call_ret("reading ttlfocus file", errno, (ret - 1), false);
	}
}


void TTLFocusMap::dump() {
	FILE *dumpfd;
	int i, ret;
	TTLFocus *tmp;

	internal_log(NULL, VERBOSE_LEVEL, "dumping ttlfocusmap to %s",  TTLFOCUSMAP_FILE);

	dumpfd = fopen(TTLFOCUSMAP_FILE, "w");
        if(dumpfd == NULL) {
                internal_log(NULL, ALL_LEVEL, "unable to access %s: sniffjoke will not dump ttl cache", TTLFOCUSMAP_FILE);
                return;
        }


	for ( TTLFocusMap::iterator it = this->begin(); it != this->end(); it++ ) {
		i++;

		tmp = &(it->second);
		ret = fwrite(tmp, sizeof(TTLFocus), 1, dumpfd);
		if(ret != 1)
		{
			fclose(dumpfd);
			unlink(TTLFOCUSMAP_FILE);
			internal_log(NULL, ALL_LEVEL, "unable to write ttlfocus to %s: %s",
				TTLFOCUSMAP_FILE, strerror(errno)
			);
			check_call_ret("writing ttlfocus file", errno, (ret - 1), false);
			return;
		}
	}
	fclose(dumpfd);
}
