#include "TTLFocus.h"
#include "defines.h"

#include <fstream>

#include <stdlib.h>
#include <arpa/inet.h>

TTLFocus::TTLFocus(unsigned int destip)
{
	daddr = destip;
	min_working_ttl = 0xff;
	expiring_ttl = 0;
	sent_probe = 0;
	received_probe = 0;
	puppet_port = htons((random() % 15000) + 1100);
	rand_key = random();
	status = TTL_BRUTALFORCE;
}

TTLFocusMap::TTLFocusMap() {
	load();

}
TTLFocusMap::~TTLFocusMap() {
	dump();
}

void TTLFocusMap::dump() {
}

void TTLFocusMap::load() {
	
}
