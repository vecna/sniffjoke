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

#include "HDRoptions.h"
#include "Packet.h"

void HDRoptions::m_IPOPT_SSRR(bool isgood) 
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
		force_next = LSRR_SJIP_OPT;
	}

	actual_length += CONST_SSRR_SIZE;
	optptr += CONST_SSRR_SIZE;
}

void HDRoptions::m_IPOPT_LSRR(bool isgood) 
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
		force_next = SSRR_SJIP_OPT;
	}

	actual_length += CONST_LSRR_SIZE;
	optptr += CONST_LSRR_SIZE;
}

void HDRoptions::m_IPOPT_RA(bool isgood) 
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
	/* in Linux kernel is like SID: not handler, return -EINVAL */

	/* VERIFY - where is used ? should be remotely tested in TTLdiscovery ?
	 *        - in this case, should be used for "good" option
	 */ 
	if(isgood)
		return;

	/* TODO - cohorent data for security OPT */
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
	optptr[11] = IPOPT_NOOP;

	/* NOP not included in the option size */
	actual_length += CONST_SEC_SIZE + CONST_NOOP_SIZE;
	optptr += CONST_SEC_SIZE + CONST_NOOP_SIZE;
}

void HDRoptions::m_IPOPT_SID(bool isgood ) {

	/* http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L448 */
	if(isgood)
		return;

	/* http://www.faqs.org/rfcs/rfc791.html "Security" */
	optptr[0] = IPOPT_SID;
	optptr[1] = CONST_SID_SIZE; // 4
	optptr[2] = 0;
	optptr[3] = 0;

	actual_length += CONST_SID_SIZE ;
	optptr += CONST_SID_SIZE ;
}

void HDRoptions::m_IPOPT_NOOP(bool isgood) {
	optptr[0] = IPOPT_NOOP;

	actual_length += CONST_NOOP_SIZE ;
	optptr += CONST_NOOP_SIZE;
}

void HDRoptions::m_IPOPT_TIMESTAMP(bool isgood) 
{
	/* GOOD option! */
	optptr[0] = IPOPT_TIMESTAMP;

	if( true /* RANDOM30PERCENTAGE */ ) 
	{
		optptr[1] = TMP_TIMESTAMP_SIZE; // 8
		optptr[2] = 4; // TMP_TIMESTAMP_SIZE; // 8
		actual_length += 4;
		optptr += 4;
		optptr[3] = (0xF | IPOPT_TS_TSONLY);

		force_next = TSONLY_SJIP_OPT;
	}
	else {
		optptr[1] = 4;
		actual_length += 4;
		optptr += 4;
	}
}

void HDRoptions::m_IPOPT_TS_TSONLY(bool isgood) 
{
	/* pseudo emulated http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L362 */
	optptr[0] = IPOPT_TS_TSONLY;
	actual_length += 4;
	optptr += 4;
}

/* not emulated ATM */
void HDRoptions::m_IPOPT_TS_TSANDADDR( bool isgood) {
}
void HDRoptions::m_IPOPT_TS_PRESPEC(bool isgood) {
}

void HDRoptions::m_IPOPT_CIPSO(bool isgood) 
{
	if(isgood)
		return;
	/* CIPSO need be enabled in the remote host, and coherent data
	 * at the moment follow the same rule of _SEC_, default: bad option */

	/* http://lxr.oss.org.cn/ident?v=2.6.34;i=cipso_v4_validate */
	optptr[0] = IPOPT_CIPSO;
	optptr[1] = CONST_CIPSO_SIZE;
	/* http://www.faqs.org/rfcs/rfc2828.html */

	/* optptr[2] .. optptr[7] = uninitialized */

	actual_length += CONST_CIPSO_SIZE;
	optptr += CONST_CIPSO_SIZE;
}

/*
 * TCP OPTIONS 
 */
#if 0
void HDRoptions::m_TCPOPT_TIMESTAMP(bool); {
}
void HDRoptions::m_TCPOPT_EOL(bool); {
}
void HDRoptions::m_TCPOPT_NOP(bool);{
}
void HDRoptions::m_TCPOPT_MAXSEG(bool);{
}
void HDRoptions::m_TCPOPT_WINDOW(bool);{
}
void HDRoptions::m_TCPOPT_SACK_PERMITTED( bool);{
}
void HDRoptions::m_TCPOPT_SACK(unsigned int *, bool);{
}
#endif

int HDRoptions::randomInjector(bool is_good) 
{
	/* 
	 * force next is used in BAD and GOOD condition, when an option may force 
	 * the next one, for mayhem reason or for coherence
	 */

	int switchval;

	if(force_next != -1) {
		switchval = force_next;
		force_next = -1;
	} else {
		if(is_good) {
			switchval = (random() % 8);
			// 8 are the randomily choosable option, 11 - the three TIMESTAMP
		} else {
			switchval = (random() % 11);
			// with the TIMESTAMP subopt too
		}
	}

	switch(switchval) 
	{
		case SSRR_SJIP_OPT:
			m_IPOPT_SSRR(is_good);
			return actual_length;
		case LSRR_SJIP_OPT:
			m_IPOPT_LSRR(is_good);
			return actual_length;
		case RA_SJIP_OPT:
			m_IPOPT_RA(is_good);
			return actual_length;
		case CIPSO_SJIP_OPT:
			m_IPOPT_CIPSO(is_good);
			return actual_length;
		case SEC_SJIP_OPT:
			m_IPOPT_SEC(is_good);
			return actual_length;
		case SID_SJIP_OPT:
			m_IPOPT_SID(is_good);
			return actual_length;
		//case NOOP_SJIP_OPT: // VERIFY/THINK ABOUT: use NOOP, or not ?
			//m_IPOPT_NOOP(is_good);
			//return actual_length;
		case TS_SJIP_OPT:
			m_IPOPT_TIMESTAMP(is_good);
			return actual_length;
		/* those case will not be called by random check */
		case TSONLY_SJIP_OPT:
			m_IPOPT_TS_TSONLY(is_good);
			return actual_length;
		case 11:
			m_IPOPT_TS_TSANDADDR(is_good);
			return actual_length;
		case 12:
			m_IPOPT_TS_PRESPEC(is_good);
			return actual_length;
	}

	return actual_length;
} 

#if 0
else /* TCP */ 
{
	int switchval;

	if(force_next != -1) {
		switchval = force_next;
			force_next = -1;
		} else {
			if(is_good) {
				switchval = (random() % 8);
				// 8 are the randomily choosable option, 11 - the three TIMESTAMP
			} else {
				switchval = (random() % 11);
				// with the TIMESTAMP subopt too
			}
		}

		switch(switchval) 
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
				m_TCPOPT_WINDOW(is_good);
				return actual_length;
			case 5:
				m_TCPOPT_SACK_PERMITTED(is_good);
				return actual_length;
			case 6:
				m_TCPOPT_SACK(is_good);
				return actual_length;
		}
	}
}
#endif

HDRoptions::HDRoptions(unsigned char *header_end, unsigned int actual_size, unsigned int target_size) :
	actual_length(actual_size),
	target_length(target_size),
	optptr(header_end)
{
	force_next = -1;
	lsrr_set = ssrr_set = false;
}

HDRoptions::~HDRoptions() { }
