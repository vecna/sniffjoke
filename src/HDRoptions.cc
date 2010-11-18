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
 *
 * the future focus of those routine is to integrate the choosing of be
 * a bad or a good ipoptions analyzing the remote OS.
 *
 * - rules for adding: check the link :
 *   http://www.iana.org/assignments/ip-parameters 
 *   test versus Linux/BSD/win, submit to us, we are happy to add
 *   every bit of randomization available.
 *
 * I've based a lot of consideration on:
 * http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.36#L250
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

HDRoptions::HDRoptions(injector_t t, unsigned char *header_end, unsigned int &actual_header_length, unsigned int &target_header_length) :
	type(t),
	optptr(header_end),
	actual_length(actual_header_length),
	target_length(target_header_length),
	available_length(target_length - actual_length),
	force_next(-1),
	lsrr_set(false),
	ssrr_set(false)
{}

HDRoptions::~HDRoptions() { }

unsigned int HDRoptions::m_IPOPT_SSRR(bool isgood) 
{
	/* http://tools.ietf.org/html/rfc1812
	 * 
	 * "A router MUST NOT originate a datagram containing multiple
	 * source route options.  What a router should do if asked to
	 * forward a packet containing multiple source route options is
	 * described in Section [5.2.4.1]."
	 * 
	 * From [5.2.4.1]:
	 * "It is an error for more than one source route option to appear in a
	 * datagram.  If it receives such a datagram, it SHOULD discard the
	 * packet and reply with an ICMP Parameter Problem message whose pointer
	 * points at the beginning of the second source route option.
	 * 
	 * This option it's based on analysis of the linux kernel. (2.6.36)
	 * 
	 * Extract from: net/ipv4/ip_options.c
	 * 
	 *    case IPOPT_SSRR:
	 *    case IPOPT_LSRR:
	 * 
	 *        [...]
	 * 
	 *        if (opt->srr) {
	 *            pp_ptr = optptr;
	 *            goto error;
         *    }
	 */
	
	if(isgood && (ssrr_set | lsrr_set))
		return 0;
	
	if( available_length < CONST_SSRR_SIZE)
		return 0;

	ssrr_set = true;

	optptr[0] = IPOPT_SSRR;
	optptr[1] = CONST_SSRR_SIZE;
	optptr[2] = 4;
	optptr[3] = IPOPT_NOOP;

	for(unsigned int i = 4; i < CONST_SSRR_SIZE ; i += 4) {
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
		force_next = SJIP_OPT_LSRR;
	}

	return CONST_SSRR_SIZE;
}

unsigned int HDRoptions::m_IPOPT_LSRR(bool isgood) 
{
	/* for verbose description see the m_IPOPT_SSRR comment */
	
	if(isgood && (ssrr_set | lsrr_set))
		return 0;
		
	if( available_length < CONST_LSRR_SIZE )
		return 0;
	
	lsrr_set = true;

	optptr[0] = IPOPT_LSRR;
	optptr[1] = CONST_LSRR_SIZE;
	optptr[2] = 4;
	optptr[3] = IPOPT_NOOP;

	for(unsigned int i = 4; i < CONST_LSRR_SIZE; i += 4) {
		unsigned int fake = random();
		memcpy(&optptr[i], &fake, sizeof(unsigned int));
	}

	/* corrupt or set the next able to generate error */
	if(isgood == false && ssrr_set == false) {
		/* SAME VERIFY as SSRR method before */
		force_next = SJIP_OPT_SSRR;
	}

	return CONST_LSRR_SIZE;
}

unsigned int HDRoptions::m_IPOPT_RR(bool isgood)
{
	/*
	 * This option it's based on analysis of the linux kernel. (2.6.36)
	 *
	 * Extract from: net/ipv4/ip_options.c
	 * 
	 *   if (optptr[2] < 4) {
	 *       pp_ptr = optptr + 2;
	 *       goto error;
	 *   }
	 * 
	 *   if (optptr[2] <= optlen) {
	 *       if (optptr[2]+3 > optlen) {
	 *           pp_ptr = optptr + 2;
	 *           goto error;
	 *       }
	 *
	 *       [...]
	 * 
	 *   so here have two conditions We can disattend;
	 *   It's possible to create a unique hack that
	 *   due tu random() exploit one or the other.
	 */

	if(isgood)
		return 0;

	if(available_length < CONST_RR_SIZE)
		return 0;

	optptr[0] = IPOPT_RR;
	optptr[1] = 3; /* MIN SIZE */

	if( RANDOMPERCENT(50) )
		optptr[2] = random() % 4;
	else
		optptr[2] = 4 + random() % 4;
	
	optptr[3] = IPOPT_NOOP;
	
	return CONST_RR_SIZE;
}


unsigned int HDRoptions::m_IPOPT_RA(bool isgood) 
{
	if(available_length < CONST_RA_SIZE)
		return 0;

	optptr[0] = IPOPT_RA;
	optptr[1] = CONST_RA_SIZE;
	optptr[2] = 0;
	optptr[3] = 0;

	return CONST_RA_SIZE;
}

unsigned int HDRoptions::m_IPOPT_CIPSO(bool isgood) 
{
	/*
	 * http://www.faqs.org/rfcs/rfc2828.html
	 * 
	 * This option it's based on analysis of the linux kernel. (2.6.36)
	 *
	 * Extract from: net/ipv4/ip_options.c
	 * 
	 *   case IPOPT_CIPSO:
	 *       if ((!skb && !capable(CAP_NET_RAW)) || opt->cipso) {
	 *           pp_ptr = optptr;
	 *           goto error;
	 *       }
	 *       opt->cipso = optptr - iph;
	 *       if (cipso_v4_validate(skb, &optptr)) {
	 *	    pp_ptr = optptr;
	 *          goto error;
	 *       }
	 *       break;
	 * 
	 *   so here have two conditions We can disattend;
	 *     - The CIPSO option can be not setted on the socket
	 *     - also if CIPSO option is setted the random data would
	 *       lead the packet to be discarded.
	 */

	if(isgood)
		return 0;

	if(available_length < CONST_CIPSO_SIZE)
		return 0;

	optptr[0] = IPOPT_CIPSO;
	optptr[1] = CONST_CIPSO_SIZE;

	memset_random(&optptr[2], 6);


	return CONST_CIPSO_SIZE;
}


unsigned int HDRoptions::m_IPOPT_SEC(bool isgood)
{
	/* 
	 * This option it's based on analysis of the linux kernel. (2.6.36)
	 *
	 * Extract from: net/ipv4/ip_options.c
	 * 
	 *   case IPOPT_SEC:
	 *   case IPOPT_SID:
	 *   default:
	 *       if (!skb && !capable(CAP_NET_RAW)) {
	 *           pp_ptr = optptr;
	 *           goto error;
	 *       }
	 * 
	 * Sidenote:
	 *   It's interesting also the default switch case,
	 *   but not used in hacks at the moment
	 */

	if(isgood)
		return 0;

	if( available_length < CONST_SEC_SIZE + CONST_NOOP_SIZE )
		return 0;

	/* TODO - cohorent data for security OPT */
	/* http://www.faqs.org/rfcs/rfc791.html "Security" */
	optptr[0] = IPOPT_SEC;
	optptr[1] = CONST_SEC_SIZE;
	
	memset_random(&optptr[2], 9);
	
	optptr[11] = IPOPT_NOOP;

	/* NOP not included in the option size */
	return CONST_SEC_SIZE + CONST_NOOP_SIZE;
}

unsigned int HDRoptions::m_IPOPT_SID(bool isgood)
{
	/* for verbose description see the m_IPOPT_SEC comment */

	if(isgood)
		return 0;

	if( available_length < CONST_SID_SIZE )
		return 0;

	optptr[0] = IPOPT_SID;
	optptr[1] = CONST_SID_SIZE;
	
	memset_random(&optptr[2], 2);

	return CONST_SID_SIZE;
}

unsigned int HDRoptions::m_IPOPT_NOOP(bool isgood)
{
	if(available_length < CONST_NOOP_SIZE)
		return 0;

	optptr[0] = IPOPT_NOOP;

	return CONST_NOOP_SIZE;
}

unsigned int HDRoptions::m_IPOPT_TIMESTAMP(bool isgood) 
{
	/*
	 * This option it's based on analysis of the linux kernel. (2.6.36)
	 *
	 * Extract from: net/ipv4/ip_options.c
	 * 
	 *   if (optptr[2] < 5) {
	 *       pp_ptr = optptr + 2;
	 *       goto error;
	 *   }
	 * 
	 *   if (optptr[2] <= optlen) {
	 *       __be32 *timeptr = NULL;
	 *       if (optptr[2]+3 > optptr[1]) {
	 *           pp_ptr = optptr + 2;
	 *           goto error;
	 *       }
	 *
	 *       [...]
	 * 
	 *   so here have two conditions We can disattend;
	 *   It's possible to create a unique hack that
	 *   due tu random() exploit one or the other.
	 */

	if(isgood)
		return 0;

	if(available_length < CONST_TIMESTAMP_SIZE)
		return 0;

	optptr[0] = IPOPT_TIMESTAMP;
	optptr[1] = 4; /* MIN SIZE */

	if( RANDOMPERCENT(50) )
		optptr[2] = random() % 5;
	else
		optptr[2] = 5 + random() % 5;
	
	optptr[3] = random();
	
	return CONST_TIMESTAMP_SIZE;
}

/*
 * TCP OPTIONS 
 */
unsigned int HDRoptions::m_TCPOPT_TIMESTAMP(bool) {
	return 0;
}
unsigned int HDRoptions::m_TCPOPT_EOL(bool) {
	return 0;
}
unsigned int HDRoptions::m_TCPOPT_NOP(bool) {
	return 0;
}
unsigned int HDRoptions::m_TCPOPT_MAXSEG(bool) {
	return 0;
}
unsigned int HDRoptions::m_TCPOPT_WINDOW(bool) {
	return 0;
}
unsigned int HDRoptions::m_TCPOPT_SACK_PERMITTED(bool) {
	return 0;
}
unsigned int HDRoptions::m_TCPOPT_SACK(bool) {
	return 0;
}

void HDRoptions::randomInjector(bool is_good) 
{
	const char* typestr = NULL;
	const char* optstr = NULL;
	unsigned int injectetdopt_size = 0;
	unsigned int lprev = actual_length;
	/* 
	 * force next is used in BAD and GOOD condition, when an option may force 
	 * the next one, for mayhem reason or for coherence
	 */
	 
	int switchval;
	
	if(type == IPOPTS_INJECTOR) {
		
		typestr = "IP";

		if(force_next != -1) {
			switchval = force_next;
			force_next = -1;
		} else {
			/* random value between 0 and SJIP_OPT_TS (last option) */
			switchval = (random() % (SJIP_OPT_TS + 1));
		}

		switch(switchval) {
			case SJIP_OPT_SSRR:
				optstr = "SSRR";
				injectetdopt_size = m_IPOPT_SSRR(is_good);
			case SJIP_OPT_LSRR:
				optstr = "LSRR";
				injectetdopt_size = m_IPOPT_LSRR(is_good);
				break;
			case SJIP_OPT_RA:
				optstr = "RA";
				injectetdopt_size = m_IPOPT_RA(is_good);
				break;
			case SJIP_OPT_CIPSO:
				optstr = "CIPSO";
				injectetdopt_size = m_IPOPT_CIPSO(is_good);
				break;
			case SJIP_OPT_SEC:
				optstr = "SEC";
				injectetdopt_size = m_IPOPT_SEC(is_good);
				break;
			case SJIP_OPT_SID:
				optstr = "SID";
				injectetdopt_size = m_IPOPT_SID(is_good);
				break;
			case SJIP_OPT_NOOP: // VERIFY/THINK ABOUT: use NOOP, or not ?
				optstr = "NOOP";
				injectetdopt_size = m_IPOPT_NOOP(is_good);
				break;
			case SJIP_OPT_TS:
				optstr = "TS";
				injectetdopt_size = m_IPOPT_TIMESTAMP(is_good);
				break;
		}
		
	} else {
		
		typestr = "TCP";

		if(force_next != -1) {
			switchval = force_next;
				force_next = -1;
		} else {
			/* at this time we have no BAD options
			 * so we can do a random value between 0 and SJTCP_OPT_SACK (last option) */
			switchval = (random() % (SJTCP_OPT_SACK + 1));
		}

		switch(switchval) {
			case SJTCP_OPT_TIMESTAMP:
				injectetdopt_size = m_TCPOPT_TIMESTAMP(is_good);
				break;
			case SJTCP_OPT_EOL:
				injectetdopt_size = m_TCPOPT_EOL(is_good);
				break;
			case SJTCP_OPT_NOP:
				injectetdopt_size = m_TCPOPT_NOP(is_good);
				break;
			case SJTCP_OPT_MAXSEG:
				injectetdopt_size = m_TCPOPT_MAXSEG(is_good);
				break;
			case SJTCP_OPT_WINDOW:
				injectetdopt_size = m_TCPOPT_WINDOW(is_good);
				break;
			case SJTCP_OPT_SACK_PERMITTED:
				injectetdopt_size = m_TCPOPT_SACK_PERMITTED(is_good);
				break;
			case SJTCP_OPT_SACK:
				injectetdopt_size = m_TCPOPT_SACK(is_good);
				break;
		}
	}	

	if(injectetdopt_size) {
		optptr += injectetdopt_size;
		actual_length += injectetdopt_size;
		available_length = (target_length - actual_length);
		debug.log(DEBUG_LEVEL, "Injected %sOPT %s size %u previous len %u actual %u", typestr, optstr, injectetdopt_size, lprev, actual_length);
	}
}
