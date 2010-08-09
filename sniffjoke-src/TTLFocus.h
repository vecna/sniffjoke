#ifndef SJ_TTLFOCUS_H
#define SJ_TTLFOCUS_H

enum ttlsearch_t { TTL_KNOW = 1, TTL_BRUTALFORCE = 3, TTL_UNKNOW = 9 };

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
};

#endif /* SJ_TTLFOCUS_H */
