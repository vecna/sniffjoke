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
 * good ipoptions mean options that don't cause the discarging of packets,
 * they need to exist in order to avoid arbitrary discrimination. 
 *        *
 * the future focus of those routine is to integrate the choosing of be
 * a bad or a good ipoptions analyzing the remote OS.
 *           *
 * - rules for adding: check the link :
 *   http://www.iana.org/assignments/ip-parameters 
 *   test versus Linux/BSD/win, submit to us, we are happy to add
 *   every bit of randomization available.
 *
 * I've based a lot of consideration on:
 * http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L250
 *
 * but checking:
 * http://www.faqs.org/rfcs/rfc1812.html
 * seems that some weird ipoptions will cause a packet to be discarged
 * on the route, without ever reach the server. We aim to create 
 * ipoptions accepted by the router, and discarded from the remote host.
 */ 

#include "HDRoptions.h"
#include "Packet.h"
#include "Debug.h"

HDRoptions::HDRoptions(unsigned char *header_end, unsigned int &actual_header_length, unsigned int &target_header_length) :
	optptr(header_end),
	actual_length(actual_header_length),
	target_length(target_header_length),
	available_length(target_length - actual_length)
{
	force_next = -1;
	lsrr_set = false;
	ssrr_set = false;
}

HDRoptions::~HDRoptions() { }

unsigned int HDRoptions::m_IPOPT_SSRR(bool isgood) 
{
	if(isgood && (ssrr_set | lsrr_set))
		return 0;
	
	if( available_length < CONST_SSRR_SIZE)
		return 0;

	ssrr_set = true;

	optptr[0] = IPOPT_SSRR;
	optptr[1] = CONST_SSRR_SIZE;
	optptr[2] = 4;
	optptr[3] = IPOPT_NOOP;

	for(int i = 4; i < CONST_SSRR_SIZE ; i += 4) {
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

	return CONST_SSRR_SIZE;
}

unsigned int HDRoptions::m_IPOPT_LSRR(bool isgood) 
{
	if(isgood && (ssrr_set | lsrr_set))
		return 0;
		
	if( available_length < CONST_LSRR_SIZE )
		return 0;
	
	lsrr_set = true;

	optptr[0] = IPOPT_LSRR;
	optptr[1] = CONST_LSRR_SIZE;
	optptr[2] = 4;
	optptr[3] = IPOPT_NOOP;

	for(int i = 4; i < CONST_LSRR_SIZE; i += 4) {
		unsigned int fake = random();
		memcpy(&optptr[i], &fake, sizeof(unsigned int));
	}

	/* corrupt or set the next able to generate error */
	if(isgood == false && ssrr_set == false) {
		/* SAME VERIFY of SSRR method before */
		force_next = SSRR_SJIP_OPT;
	}

	return CONST_LSRR_SIZE;
}

unsigned int HDRoptions::m_IPOPT_RA(bool isgood) 
{
	if(available_length < CONST_RA_SIZE)
		return 0;

	optptr[0] = IPOPT_RA;
	optptr[1] = CONST_RA_SIZE;
	/* VERIFY: http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L428 */
	optptr[2] = 0;
	optptr[3] = 0;

	return CONST_RA_SIZE;
}

unsigned int HDRoptions::m_IPOPT_SEC(bool isgood)
{
	/* in Linux kernel is like SID: not handler, return -EINVAL */

	/* VERIFY - where is used ? should be remotely tested in TTLdiscovery ?
	 *        - in this case, should be used for "good" option
	 */ 
	if(isgood)
		return 0;

	if( available_length < CONST_SEC_SIZE + CONST_NOOP_SIZE )
		return 0;

	/* TODO - cohorent data for security OPT */
	/* http://www.faqs.org/rfcs/rfc791.html "Security" */
	optptr[0] = IPOPT_SEC;
	optptr[1] = CONST_SEC_SIZE;
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
	return CONST_SEC_SIZE + CONST_NOOP_SIZE;
}

unsigned int HDRoptions::m_IPOPT_SID(bool isgood) {

	/* http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L448 */
	if(isgood)
		return 0;

	if( available_length < CONST_SID_SIZE )
		return 0;

	/* http://www.faqs.org/rfcs/rfc791.html "Security" */
	optptr[0] = IPOPT_SID;
	optptr[1] = CONST_SID_SIZE;
	optptr[2] = 0;
	optptr[3] = 0;

	return CONST_SID_SIZE ;
}

unsigned int HDRoptions::m_IPOPT_NOOP(bool isgood) {

	if(available_length < CONST_NOOP_SIZE)
		return 0;

	optptr[0] = IPOPT_NOOP;

	return CONST_NOOP_SIZE;
}

unsigned int HDRoptions::m_IPOPT_TIMESTAMP(bool isgood) 
{
	if(available_length < 4)
		return 0;

	/* GOOD option! */
	optptr[0] = IPOPT_TIMESTAMP;

	if( true /* RANDOM30PERCENTAGE */ ) 
	{
		optptr[1] = TMP_TIMESTAMP_SIZE; // 8
		optptr[2] = 4; // TMP_TIMESTAMP_SIZE; // 8
		optptr[3] = (0xF | IPOPT_TS_TSONLY);

		force_next = TSONLY_SJIP_OPT;

		return 4;
	}
	else {
		optptr[1] = 4;
		/* optptr[2] .. optptr[3] = uninitialized */

		return 4;
	}
}

unsigned int HDRoptions::m_IPOPT_TS_TSONLY(bool isgood) 
{
	if(available_length < 4)
		return 0;

	/* pseudo emulated http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.34#L362 */
	optptr[0] = IPOPT_TS_TSONLY;
	
	/* optptr[1] .. optptr[3] = uninitialized */

	return 4;
}

/* not emulated ATM */
unsigned int HDRoptions::m_IPOPT_TS_TSANDADDR( bool isgood) {
	return 0;
}
unsigned int HDRoptions::m_IPOPT_TS_PRESPEC(bool isgood) {
	return 0;
}

unsigned int HDRoptions::m_IPOPT_CIPSO(bool isgood) 
{
	if(isgood)
		return 0;

	if(available_length < CONST_CIPSO_SIZE)
		return 0;

	/* CIPSO need be enabled in the remote host, and coherent data
	 * at the moment follow the same rule of _SEC_, default: bad option */

	/* http://lxr.oss.org.cn/ident?v=2.6.34;i=cipso_v4_validate */
	optptr[0] = IPOPT_CIPSO;
	optptr[1] = CONST_CIPSO_SIZE;
	/* http://www.faqs.org/rfcs/rfc2828.html */

	/* optptr[2] .. optptr[7] = uninitialized */

	return CONST_CIPSO_SIZE;
}

/*
 * TCP OPTIONS 
 */
#if 0
unsigned int HDRoptions::m_TCPOPT_TIMESTAMP(bool); {
}
unsigned int HDRoptions::m_TCPOPT_EOL(bool); {
}
unsigned int HDRoptions::m_TCPOPT_NOP(bool);{
}
unsigned int HDRoptions::m_TCPOPT_MAXSEG(bool);{
}
unsigned int HDRoptions::m_TCPOPT_WINDOW(bool);{
}
unsigned int HDRoptions::m_TCPOPT_SACK_PERMITTED( bool);{
}
unsigned int HDRoptions::m_TCPOPT_SACK(unsigned int *, bool);{
}
#endif

void HDRoptions::randomInjector(bool is_good) 
{
	const char* optstr;
	unsigned int injectetdopt_size = 0;
	unsigned int lprev = actual_length;
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
			optstr = "SSRR";
			injectetdopt_size = m_IPOPT_SSRR(is_good);
		case LSRR_SJIP_OPT:
			optstr = "LSRR";
			injectetdopt_size = m_IPOPT_LSRR(is_good);
			break;
		case RA_SJIP_OPT:
			optstr = "RA";
			injectetdopt_size = m_IPOPT_RA(is_good);
			break;
		case CIPSO_SJIP_OPT:
			optstr = "CIPSO";
			injectetdopt_size = m_IPOPT_CIPSO(is_good);
			break;
		case SEC_SJIP_OPT:
			optstr = "SEC";
			injectetdopt_size = m_IPOPT_SEC(is_good);
			break;
		case SID_SJIP_OPT:
			optstr = "SID";
			injectetdopt_size = m_IPOPT_SID(is_good);
			break;
		//case NOOP_SJIP_OPT: // VERIFY/THINK ABOUT: use NOOP, or not ?
			//optstr = "NOOP";
			//injectetdopt_size = m_IPOPT_NOOP(is_good);
			//break;
		case TS_SJIP_OPT:
			optstr = "TS";
			injectetdopt_size = m_IPOPT_TIMESTAMP(is_good);
			break;
		/* those case will not be called by random check */
		case TSONLY_SJIP_OPT:
			optstr = "TSONLY";
			injectetdopt_size = m_IPOPT_TS_TSONLY(is_good);
			break;
		case TS_TSANDADDR_SJIP_OPT:
			optstr = "TS_TSANDADDR";
			injectetdopt_size = m_IPOPT_TS_TSANDADDR(is_good);
			break;
		case TS_PRESPEC_SJIP_OPT:
			optstr = "TS_PRESPEC";
			injectetdopt_size = m_IPOPT_TS_PRESPEC(is_good);
			break;
	}
	
	if(injectetdopt_size) {
		optptr += injectetdopt_size;
		actual_length += injectetdopt_size;
		available_length = (target_length - actual_length);
		debug.log(DEBUG_LEVEL, "Injected IPOPT %s size %u previous len %u actual %u", optstr, injectetdopt_size, lprev, actual_length);
	}
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
				injectetdopt_size = m_TCPOPT_TIMESTAMP(is_good);
				break;
			case 1:
				injectetdopt_size = m_TCPOPT_EOL(is_good);
				break;
			case 2:
				injectetdopt_size = m_TCPOPT_NOP(is_good);
				break;
			case 3:
				injectetdopt_size = m_TCPOPT_MAXSEG(is_good);
				break;
			case 4:
				injectetdopt_size = m_TCPOPT_WINDOW(is_good);
				break;
			case 5:
				injectetdopt_size = m_TCPOPT_SACK_PERMITTED(is_good);
				break;
			case 6:
				injectetdopt_size = m_TCPOPT_SACK(is_good);
				break;
		}
	}

	if(injectetdopt_size) {
		optptr += injectetdopt_size;
		actual_length += injectetdopt_size;
		available_length = (target_length - actual_length);
		debug.log(DEBUG_LEVEL, "Injected TCPOPT %s size %u previous len %u actual %u", optstr, injectetdopt_size, lprev, actual_length);
	}
}
#endif
