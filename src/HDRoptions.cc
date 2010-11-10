
#include "HDRoptions.h"

/*
 * Handling randomized ip/tcp options.. WHAT dirty job!
 * 
 * good ipoption mean options that don't cause the discarging of packets,
 * they need to exist in order to avoid arbitrary discrimination. 
 *        *
 * the future focus of those routine is to integrate the choosing of be
 * a bad or a good ipoptions analyzing the remote OS.
 *           *
 * - rules for adding: check the link :
 *   http://www.iana.org/assignments/ip-parameters 
 *   test versus BSD/win/Linux, submit to our, we are happy every bit 
 *   of randomization available.
 */


int HDRoptions::IPOPT_SSRR(bool isgood, char *optptr) 
{
	int i, proposed_size = (target_length - actual_length);
	int maxsize = MAX_LSRR_SIZE - actual_length;

	if(proposed_size < MIN_SSRR_SIZE)
		return;

	/* prop size will be max of 40, 4 + 9 ipaddress,
	 * when is_good = true, is acceptable the entire ip options
	 * is filled with *SRR opt, but when is evil, we need other
	 * options able to invalidate it.
	 */
	proposed_size = 4 + (random() %  (is_good ? maxsize : (maxsize / 2) / 4));

	if(is_good && (ssrr_set | lsrr_set) )
		return;

	ssrr_set = true;

	*optptr = IPOPT_SSRR;
	*++optptr = proposed_size;
	*++optptr = 4;
	*++optptr = IPOPT_NOOP;

	for(i = 4, ++optptr; i < proposed_size; i += 4) {
		unsigned int fake = random();
		memcpy(optptr, &fake, sizeof(unsigned int));
	}

	/* corrupt or set the next able to generate error */
	if(is_good == false && lsrr_set == false) {
		/* RANDOM20PERCENT */
		*next = LSRR_SJ_OPT;
	}

	actual_length += proposed_size;
}

void HDRoptions::IPOPT_LSRR(unsigned int *next, bool is_good) 
{
	int i, proposed_size = (target_length - actual_length);
	int maxsize = MAX_LSRR_SIZE - actual_length;

	if(proposed_size < MIN_LSRR_SIZE)
		return;

	/* prop size will be max of 40, 4 + 9 ipaddress,
	 * when is_good = true, is acceptable the entire ip options
	 * is filled with *SRR opt, but when is evil, we need other
	 * options able to invalidate it.
	 */
	proposed_size = 4 + (random() %  (is_good ? maxsize : (maxsize / 2) / 4));

	if(is_good && (ssrr_set | lsrr_set) )
		return;

	lsrr_set = true;

	*optptr = IPOPT_LSRR;
	*++optptr = proposed_size;
	*++optptr = 4;
	*++optptr = IPOPT_NOOP;

	for(i = 4, ++optptr; i < proposed_size; i += 4) {
		unsigned int fake = random();
		memcpy(optptr, &fake, sizeof(unsigned int));
	}

	/* corrupt or set the next able to generate error */
	if(is_good == false && ssrr_set == false) {
		/* RANDOM20PERCENT */
		*next = SSRR_SJ_OPT;
	}

	actual_length += proposed_size;
}

void HDRoptions::IPOPT_RA(unsigned int *next, bool is_good) 
{
}

void HDRoptions::IPOPT_SEC(unsigned int *next, bool is_good) { }
void HDRoptions::IPOPT_SID(unsigned int *next, bool is_good) { }
void HDRoptions::IPOPT_NOOP(unsigned int *next, bool is_good) { }
void HDRoptions::IPOPT_TIMESTAMP(unsigned int *next, bool is_good) { }
void HDRoptions::IPOPT_TS_TSONLY(unsigned int *next, bool is_good) { }
void HDRoptions::IPOPT_TS_TSANDADDR(unsigned int *next, bool is_good) { }
void HDRoptions::IPOPT_TS_PRESPEC(unsigned int *next, bool is_good) { }

void HDRoptions::IPOPT_CIPSO(unsigned int *next, bool is_good) { }

int HDRoptions::randomInjector(bool is_good) 
{
	int randomval = random();

	/* 
	 * force next is used in BAD condition, when an option may force 
	 * the next one, in order to cause mayhem 
	 */
	if(force_next != 0) {
		randomval = force_next;
		force_next = 0;
	}

	if(selected_proto == IP) 
	{
		/* % 10 of force_next return the same value */
		switch(randomval % 12) 
		{
			case 0:
				return IPOPT_SSRR(&force_next, is_good);
			case 1:
				return IPOPT_LSRR(&force_next, is_good);
			case 2:
				return IPOPT_RA(&force_next, is_good);
			case 4:
				return IPOPT_CIPSO(&force_next, is_good);
			case 5:
				return IPOPT_SEC(&force_next, is_good);
			case 6:
				return IPOPT_SID(&force_next, is_good);
			case 7:
				return IPOPT_NOOP(&force_next, is_good);
			case 8:
				return IPOPT_TIMESTAMP(&force_next, is_good);
			case 10:
				return IPOPT_TS_TSONLY(&force_next, is_good);
			case 11:
				return IPOPT_TS_TSANDADDR(&force_next, is_good);
			case 12:
				return IPOPT_TS_PRESPEC(&force_next, is_good);
		}
	} else /* TCP */ {
		switch(random % 6) 
		{
			case 0:
			case 1:
			case 2:
			case 3:
			case 4:
		}
	}
}

HDRoptions::HDRoptions(unsigned char *header_end, protocol_t proto) :
	selected_proto(proto),
	optptr(header_end)
{
	force_next = -1;
	lsrr_set = ssrr_set = false;
}

HDRoptions::~HDRoptions() { }


/* ENDIANESS possibile problem here ? */
void HDRoptions::OptApply(unsigned int offset, unsigned int abcd) {
        unsigned int *ptr = (unsigned char *)&(pbuf[offset]);
        ptr[0] = abcd;
}

void Packet::Inject_GOOD_IPOPT(void)
{
        struct injipopt {
                unsigned char OPT;
                unsigned char tot_len;
                unsigned char opt_len;
        };
#define VARIABLE        0xff
        struct injipopt supported[] = {
        /*        IPOPT_OPVAL, IPOPT_OLEN       */
                { IPOPT_SSRR, VARIABLE },
                { IPOPT_LSRR, VARIABLE },
                { IPOPT_RR,   VARIABLE }
        };
#define SUPPORTED_NUM   (sizeof(supported) / sizeof(struct injipopt))

        int wannabeinjected = random() % 6;
        int done = 0;

        do {
                int i = random() % SUPPORTED_N;

                if(supported[i].opt_len == VARIABLE) {
                }

        } while(done != wannabeinject);
/*
 *
