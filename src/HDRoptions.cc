
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
 *
 * I'm based a lot of consideration on:
 * http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L250
 *
 * but checking:
 * http://www.faqs.org/rfcs/rfc1812.html
 * seem that some weird ipoptions will cause a packet to be discarged
 * on the route, without ever reach the server. we aim to create 
 * ipoptions accepted by the router, and discarded from the remote host
 */

int HDRoptions::m_IPOPT_SSRR(bool isgood, char *optptr) 
{
	int i, available_size = (target_length - actual_length);

	if( available_size < CONST_SSRR_SIZE)
		return;

	if(isgood && (ssrr_set | lsrr_set) )
		return;

	ssrr_set = true;

	optptr[0] = IPOPT_SSRR;
	optptr[1] = CONST_SSRR_SIZE;
	optptr[2] = 4;
	optptr[3] = IPOPT_NOOP;

	for(i = 4; i < CONST_SSRR_SIZE ; i += 4) {
		unsigned int fake = random();
		memcpy(&optptr[i], &fake, sizeof(unsigned int));
	}

	/* corrupt or set the next able to generate error */
	if(isgood == false && lsrr_set == false) {
		/* 
		 * VERIFY two kind of elements:
		 * 1) if the option arrive in fact to the remote host
		 * 2) if a corruption of the option is not a better way
		 */
		*next = LSRR_SJ_OPT;
	}

	actual_length += CONST_SSRR_SIZE;
	optptr += CONST_SSRR_SIZE;
}

void HDRoptions::m_IPOPT_LSRR(unsigned int *next, bool isgood) 
{
	int i, available_size = (target_length - actual_length);

	if( available_size < CONST_LSRR_SIZE )
		return;

	if(isgood && (ssrr_set | lsrr_set) )
		return;

	lsrr_set = true;

	optptr[0] = IPOPT_LSRR;
	optptr[1] = CONST_LSRR_SIZE;
	optptr[2] = 4;
	optptr[3] = IPOPT_NOOP;

	for(i = 4; i < CONST_LSRR_SIZE; i += 4) {
		unsigned int fake = random();
		memcpy(&optptr[i], &fake, sizeof(unsigned int));
	}

	/* corrupt or set the next able to generate error */
	if(isgood == false && ssrr_set == false) {
		/* SAME VERIFY of SSRR method before */
		*next = SSRR_SJ_OPT;
	}

	actual_length += CONST_LSRR_SIZE;
	optptr += CONST_LSRR_SIZE;
}

void HDRoptions::m_IPOPT_RA(unsigned int *next, bool isgood) 
{
	optptr[0] = IPOPT_RA;
	optptr[1] = CONST_RA_SIZE;
	/* VERIFY: http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L428 */
	optptr[2] = 0;
	optptr[3] = 0;

	actual_length += CONST_RA_SIZE;
	optptr += CONST_RA_SIZE;
}

void HDRoptions::m_IPOPT_SEC(bool isgood)
{
	/* TODO - data for security TODO - how much is good ? */
	/* http://www.faqs.org/rfcs/rfc791.html "Security" */
	optptr[0] = IPOPT_SEC;
	optptr[1] = CONST_SEC_SIZE; // 11
	optptr[2] = 0;
	optptr[3] = 0;
	optptr[4] = 0;
	optptr[5] = 0;
	optptr[6] = 0;
	optptr[7] = 0;
	optptr[8] = 0;
	optptr[9] = 0;
	optptr[10] = 0;
	optptr[11] = IPOPT_NOP;

	actual_length += CONST_RA_SIZE + 1;
	optptr += CONST_RA_SIZE + 1;
}

void HDRoptions::m_IPOPT_SID(unsigned int *, bool ); 
void HDRoptions::m_IPOPT_NOOP(unsigned int *, bool );
void HDRoptions::m_IPOPT_TIMESTAMP(unsigned int *, bool );
void HDRoptions::m_IPOPT_TS_TSONLY(unsigned int *, bool );
void HDRoptions::m_IPOPT_TS_TSANDADDR(unsigned int *, bool );
void HDRoptions::m_IPOPT_TS_PRESPEC(unsigned int *, bool );
void HDRoptions::m_IPOPT_CIPSO(unsigned int *, bool );

void HDRoptions::m_TCPOPT_TIMESTAMP(unsigned int *, bool);
void HDRoptions::m_TCPOPT_EOL(unsigned int *, bool);
void HDRoptions::m_TCPOPT_NOP(unsigned int *, bool);
void HDRoptions::m_TCPOPT_MAXSEG(unsigned int *, bool);
void HDRoptions::m_TCPOPT_WINDOW(unsigned int *, bool);
void HDRoptions::m_TCPOPT_SACK_PERMITTED( bool);
void HDRoptions::m_TCPOPT_SACK(unsigned int *, bool);


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
		switch(randomval % 13) 
		{
			case SSRR_SJ_OPT:
				m_IPOPT_SSRR(is_good);
				return actual_length;
			case LSRR_SJ_OPT:
				m_IPOPT_LSRR(is_good);
				return actual_length;
			case RA_SJ_OPT:
				m_IPOPT_RA(is_good);
				return actual_length;
			case 4:
				m_IPOPT_CIPSO(is_good);
				return actual_length;
			case 5:
				m_IPOPT_SEC(is_good);
				return actual_length;
			case 6:
				m_IPOPT_SID(is_good);
				return actual_length;
			case 7:
				m_IPOPT_NOOP(is_good);
				return actual_length;
			case 8:
				m_IPOPT_TIMESTAMP(is_good);
				return actual_length;
			case 10:
				m_IPOPT_TS_TSONLY(is_good);
				return actual_length;
			case 11:
				m_IPOPT_TS_TSANDADDR(is_good);
				return actual_length;
			case 12:
				m_IPOPT_TS_PRESPEC(is_good);
				return actual_length;
		}
	} else /* TCP */ {
		switch(random % 7) 
		{
			case 0:
				m_TCPOPT_TIMESTAMP(is_good);
				return actual_length;
			case 1:
				m_TCPOPT_EOL(is_good);
				return actual_length;
			case 2:
				m_TCPOPT_NOP(is_good);
				return actual_length;
			case 3:
				m_TCPOPT_MAXSEG(is_good);
				return actual_length;
			case 4:
				m_TCPOPT_WINDOW(&force_next, is_good);
				return actual_length;
			case 5:
				m_TCPOPT_SACK_PERMITTED(is_good);
				return actual_length;
			case 6:
				m_TCPOPT_SACK(, is_good);
				return actual_length;
		}
	}
}

HDRoptions::HDRoptions(unsigned char *header_end, protocol_t proto, int actual_size, int target_size) :
	selected_proto(proto),
	optptr(header_end),
	actual_length(actual_size),
	target_length(target_size)
{
	force_next = -1;
	lsrr_set = ssrr_set = false;
}

HDRoptions::~HDRoptions() { }
