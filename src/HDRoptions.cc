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
 *   test versus Linux/BSD/win/lose, submit to us, we are happy to add
 *   every bit of randomization available.
 *
 * I've based a lot of consideration on:
 * http://lxr.oss.org.cn/source/net/ipv4/ip_options.c?v=2.6.36#L250
 *
 * but checking:
 * http://www.faqs.org/rfcs/rfc1812.html
 * seems that some weird ipoptions will cause a packet to be discarged
 * on the route, without ever reach the server. we aim to create 
 * ipoptions accepted by the router, and discarded from the remote host.
 */ 

#include "HDRoptions.h"
#include "Packet.h"
#include "Debug.h"

uint8_t HDRoptions::m_IPOPT_NOOP(void)
{
#define IPOPT_NOOP_SIZE 1

	if(corrupt) /* this option never corrupts the packet */
		return 0;

	if(available_opts_len < IPOPT_NOOP_SIZE)
		return 0;

	optptr[0] = IPOPT_NOOP;

	return IPOPT_NOOP_SIZE;
}


uint8_t HDRoptions::m_IPOPT_LSRR(void) 
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
	 *        if (optlen < 3) {
	 *                pp_ptr = optptr + 1;
	 *                goto error;
	 *         }
	 *         if (optptr[2] < 4) {
	 *                pp_ptr = optptr + 2;
	 *                goto error;
	 *         }
	 *         / * NB: cf RFC-1812 5.2.4.1 * /
	 *         if (opt->srr) {
	 *                pp_ptr = optptr;
	 *                goto error;
	 *         }
	 *         if (!skb) {
	 *                if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
	 *                        pp_ptr = optptr + 1;
	 *                        goto error;
	 *                }
	 *                memcpy(&opt->faddr, &optptr[3], 4);
	 *                if (optlen > 7)
	 *                        memmove(&optptr[3], &optptr[7], optlen-7);
	 *         }
	 *         opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
	 *         opt->srr = optptr - iph;
	 *         break;
	 * 
	 *  we want to send LSRR option 2 times.
	 *  so we have to respect all checks that lead to an error. 
	 *  using SSRR is also possibile but the packet will be trashed by the
	 *  first router.
	 */

	if(!corrupt) /* this option always corrupts the packet */
		return 0;

	const uint8_t routes_1 = 1 + random() % 3; /* 1 - 3 */
	const uint8_t routes_2 = 1 + random() % 3; /* 1 - 3 */
	const uint8_t size_lsrr_1 = 3 + 4 * routes_1;
	const uint8_t size_lsrr_2 = 3 + 4 * routes_2;
	const uint8_t req_size = size_lsrr_1 + size_lsrr_2;

	if(available_opts_len < req_size)
		return 0;

	optptr[0] = IPOPT_LSRR;
	optptr[1] = size_lsrr_2;
	optptr[2] = 4;
	memset_random(&optptr[3], size_lsrr_1 - 3);
	
	optptr[size_lsrr_1 + 0] = IPOPT_LSRR;
	optptr[size_lsrr_1 + 1] = size_lsrr_2;
	optptr[size_lsrr_1 + 2] = 4;
	memset_random(&optptr[size_lsrr_1 + 3], size_lsrr_2 - 3);

	return req_size;
}

uint8_t HDRoptions::m_IPOPT_RR(void)
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
	 *   so here have two conditions we can disattend;
	 *   It's possible to create a unique hack that
	 *   due to random() exploits the first or the latter.
	 */

	const uint8_t routes = 1 + random() % 5; /* 1 - 5 */
	const uint8_t size_rr = 3 + routes * 4;

	if(!corrupt && opt_ip_rr) /* this option corrupts the packet if repeated */
		return 0;

	if(available_opts_len < size_rr)
		return 0;
		
	if(!corrupt)
		return 0;

	optptr[0] = IPOPT_RR;
	optptr[1] = size_rr;

	if(!corrupt) { /* good option */
		optptr[2] = routes * 4;

	} else { /* bad option */

		if(RANDOMPERCENT(50)) {
			/* reference code : if (optptr[2] < 5) { */
			optptr[2] = random() % 4;
		} else {
			/* reference code : if (optptr[2] <= optlen) {
			              and : if (optptr[2]+3 > optptr[1]) { */
			optptr[2] = optptr[1] - (1 + random() % 2);
		}
			
	}
	
	memset_random(&optptr[3], 4 * routes);

	opt_ip_rr = true;

	return size_rr;
}


uint8_t HDRoptions::m_IPOPT_RA(void)
{
#define IPOPT_RA_SIZE 4

	if(corrupt) /* this option never corrupts the packet */
		return 0;

	if(available_opts_len < IPOPT_RA_SIZE)
		return 0;

	optptr[0] = IPOPT_RA;
	optptr[1] = IPOPT_RA_SIZE;
	memset_random(&optptr[2], 2);

	return IPOPT_RA_SIZE;
}

uint8_t HDRoptions::m_IPOPT_CIPSO(void) 
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
	 *   so here have two conditions we can disattend;
	 *     - The CIPSO option can be not setted on the socket
	 *     - also if CIPSO option is setted the random data would
	 *       lead the packet to be discarded.
	 */

#define IPOPT_CIPSO	(6 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_CIPSO_SIZE 8

	if(!corrupt) /* this option always corrupts the packet */
		return 0;

	if(available_opts_len < IPOPT_CIPSO_SIZE)
		return 0;

	optptr[0] = IPOPT_CIPSO;
	optptr[1] = IPOPT_CIPSO_SIZE;
	memset_random(&optptr[2], 6);

	return IPOPT_CIPSO_SIZE;
}


uint8_t HDRoptions::m_IPOPT_SEC(void)
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

#define IPOPT_SEC_SIZE 11

	if(!corrupt) /* this options always corrupts the packet */
		return 0;

	if(available_opts_len < IPOPT_SEC_SIZE)
		return 0;

	/* TODO - cohorent data for security OPT */
	/* http://www.faqs.org/rfcs/rfc791.html "Security" */
	optptr[0] = IPOPT_SEC;
	optptr[1] = IPOPT_SEC_SIZE;
	memset_random(&optptr[2], 9);

	/* NOP not included in the option size */
	return IPOPT_SEC_SIZE;
}

uint8_t HDRoptions::m_IPOPT_SID(void)
{
	/* for verbose description see the m_IPOPT_SEC comment */

#define IPOPT_SID_SIZE 4

	if(!corrupt) /* this option always corrupts the packet */
		return 0;

	if(available_opts_len < IPOPT_SID_SIZE)
		return 0;

	optptr[0] = IPOPT_SID;
	optptr[1] = IPOPT_SID_SIZE;
	memset_random(&optptr[2], 2);

	return IPOPT_SID_SIZE;
}

uint8_t HDRoptions::m_IPOPT_TIMESTAMP(void) 
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
	 *   so here have two conditions we can disattend;
	 *   It's possible to create a unique hack that
	 *   due tu random() exploit one or the other.
	 */

	const uint8_t timestamps = 1 + random() % 5; /* 1 - 5 */
	const uint8_t size_timestamp = 4 + timestamps * 8;

	if(!corrupt && opt_ip_timestamp) /* this option corrupts the packet if repeated */
		return 0;

	if(available_opts_len < size_timestamp)
		return 0;

	optptr[0] = IPOPT_TIMESTAMP;
	optptr[1] = size_timestamp;
	
	if(!corrupt) {	/* good */
		
		/* 
		 * we set the same IPOPT_TS_TSANDADDR suboption we will
		 * set for the corrupted injection.
		 * This suboption tells router to register their ip and
		 * to put a timestamp.
		 * we set the pointer (optr[2]) as full because of course
		 * we does not help the sniffer offering him so precious informations =)
		 */ 

		optptr[2] = size_timestamp;
		optptr[3] = IPOPT_TS_TSANDADDR;
		
	} else { /* corrupted */
		
		if(RANDOMPERCENT(50)) {
			/* reference code : if (optptr[2] < 5) { */
			optptr[2] = random() % 5;
		} else {
			/* reference code : if (optptr[2] <= optlen) {
			              and : if (optptr[2]+3 > optptr[1]) { */
			optptr[2] = optptr[1] - (1 + random() % 2);
		}
	
		optptr[3] = random();

	}

	memset_random(&optptr[4], timestamps * 4);
	
	opt_ip_timestamp = true;
	
	return size_timestamp;
}

/*
 * TCP OPTIONS 
 */

uint8_t HDRoptions::m_TCPOPT_TIMESTAMP(void) {
	return 0;
}
uint8_t HDRoptions::m_TCPOPT_EOL(void) {
	return 0;
}
uint8_t HDRoptions::m_TCPOPT_NOP(void) {
	return 0;
}
uint8_t HDRoptions::m_TCPOPT_MAXSEG(void) {
	return 0;
}
uint8_t HDRoptions::m_TCPOPT_WINDOW(void) {
	return 0;
}
uint8_t HDRoptions::m_TCPOPT_SACK_PERMITTED(void) {
	return 0;
}
uint8_t HDRoptions::m_TCPOPT_SACK(void) {
	return 0;
}

/*
 *	returns true if injection is possible, false instead;
 *      in addition it registers the presence of some options.
 */
bool HDRoptions::checkIPOPTINJPossibility(void) {
	
	for (uint8_t i = sizeof(struct iphdr); i < actual_opts_len;) {
		unsigned char* const option = &optptr[i];
		uint8_t option_len;

		switch(*option) {
			case IPOPT_END:
				if(corrupt) /* on corrupt : end can be stripped off */
					*option =  IPOPT_NOOP;
				++i;
				continue;
			case  IPOPT_NOOP:
				++i;
				continue;
			case IPOPT_TIMESTAMP:
				opt_ip_timestamp = true; /* on !corrupt : we can't inject timestamp if just present */
				goto ip_opts_len_check;
			case IPOPT_RR:
				opt_ip_rr = true;	/* on !corrupt : we can't inject record route if just present */
				goto ip_opts_len_check;
			case IPOPT_CIPSO:
			case IPOPT_SEC:
			case IPOPT_SID:
				if(!corrupt) /* on !corrup : we always avoid to inject if this options ar present */
					return false;
				goto ip_opts_len_check;
ip_opts_len_check:	default:
				option_len = (uint8_t)optptr[i+1];
				if(option_len > (actual_opts_len - i)) {
					/* 
					 * the packet contains invalid options
					 * we avoid injection regardless of the corrupt value.
					 */
					return false;
				}
				i += option_len;
		}
	}

	return true;
}

/*
 *	returns true if injection is possible, false instead;
 *      in addition it registers the presence of some options.
 */
bool HDRoptions::checkTCPOPTINJPossibility(void) {
	for (uint8_t i = sizeof(struct tcphdr); i < actual_opts_len;) {
		unsigned char* const option = &optptr[i];
		uint8_t option_len;

		switch(*option) {
			case TCPOPT_EOL:
				if(corrupt) /* on corrupt : eol can be stripped off */
					*option = TCPOPT_NOP;
				++i;
				continue;
			case TCPOPT_NOP:
				++i;
				continue;
			case TCPOPT_MAXSEG:
			case TCPOPT_WINDOW:
			case TCPOPT_SACK_PERMITTED:
			case TCPOPT_SACK:
				if(!corrupt) /* on !corrupt : we always avoid to inject if this options ar present */
					return false;
				goto tcp_opts_len_check;
tcp_opts_len_check:	default:
				option_len = (uint8_t)optptr[i+1];
				if(option_len > (actual_opts_len - i)) {
					/* 
					 * the packet contains invalid options
					 * we avoid injection regardless of the corrupt value.
					 */
					return false;
				}
				i += option_len;
				break;
		}
	}

	return true;

}


HDRoptions::HDRoptions(injector_t t, bool corrupt, unsigned char *optptr, uint8_t &actual_opts_len, uint8_t &target_opts_len) :
	type(t),
	corrupt(corrupt),
	optptr(optptr),
	actual_opts_len(actual_opts_len),
	target_opts_len(target_opts_len),
	available_opts_len(target_opts_len - actual_opts_len),
	opt_ip_timestamp(false),
	opt_ip_rr(false)
{
	switch(type) {
		case IPOPTS_INJECTOR:
			if(!checkIPOPTINJPossibility())
				throw exception();
			break;
		case TCPOPTS_INJECTOR:
			if(!checkTCPOPTINJPossibility())
				throw exception();
			break;
	}
}

bool HDRoptions::randomInjector(void) 
{
	/*
	 * Every options must be self-contained because sniffjoke needs to know if
	 * it has invalidated the packet or not.
	 * So for options that need a COMBO (of one ore two options) the combo must
	 * be implemented inside the option call itself;
	 * For an example of this see the duplicated RR combo defined insied m_IPOPT_LSRR()
	 */ 

	const char* optstr = NULL;
	uint8_t injectetdopt_size = 0;
	uint8_t lprev = actual_opts_len;
	/* 
	 * force next is used in BAD and GOOD condition, when an option may force 
	 * the next one, for mayhem reason or for coherence
	 */
	 
	if(type == IPOPTS_INJECTOR) {
		/* random value between 0 and SJ_IPOPT_SID (last option) */
		switch(random() % (SJ_IPOPT_SID + 1)) {
			case SJ_IPOPT_NOOP:
				optstr = "NOOP";
				injectetdopt_size = m_IPOPT_NOOP();
				break;
			case SJ_IPOPT_TIMESTAMP:
				optstr = "TIMESTAMP";
				injectetdopt_size = m_IPOPT_TIMESTAMP();
				break;
			case SJ_IPOPT_LSRR:
				optstr = "LSRR";
				injectetdopt_size = m_IPOPT_LSRR();
				break;
			case SJ_IPOPT_RR:
				optstr = "RR";
				injectetdopt_size = m_IPOPT_RR();
				break;
			case SJ_IPOPT_RA:
				optstr = "RA";
				injectetdopt_size = m_IPOPT_RA();
				break;
			case SJ_IPOPT_CIPSO:
				optstr = "CIPSO";
				injectetdopt_size = m_IPOPT_CIPSO();
				break;
			case SJ_IPOPT_SEC:
				optstr = "SEC";
				injectetdopt_size = m_IPOPT_SEC();
				break;
			case SJ_IPOPT_SID:
				optstr = "SID";
				injectetdopt_size = m_IPOPT_SID();
				break;
		}
	
	} else {		
		/* random value between 0 and SJ_TCPOPT_SACK (last option) */
		switch(random() % (SJ_TCPOPT_SACK + 1)) {
			case SJ_TCPOPT_EOL:
				injectetdopt_size = m_TCPOPT_EOL();
				break;
			case SJ_TCPOPT_NOP:
				injectetdopt_size = m_TCPOPT_NOP();
				break;
			case SJ_TCPOPT_TIMESTAMP:
				injectetdopt_size = m_TCPOPT_TIMESTAMP();
				break;
			case SJ_TCPOPT_MAXSEG:
				injectetdopt_size = m_TCPOPT_MAXSEG();
				break;
			case SJ_TCPOPT_WINDOW:
				injectetdopt_size = m_TCPOPT_WINDOW();
				break;
			case SJ_TCPOPT_SACK_PERMITTED:
				injectetdopt_size = m_TCPOPT_SACK_PERMITTED();
				break;
			case SJ_TCPOPT_SACK:
				injectetdopt_size = m_TCPOPT_SACK();
				break;
		}
	}	

	if(injectetdopt_size) {
		optptr += injectetdopt_size;
		actual_opts_len += injectetdopt_size;
		available_opts_len = (target_opts_len - actual_opts_len);
		debug.log(DEBUG_LEVEL, "Injected %sOPT %s size %u previous len %u actual %u", 
			type == IPOPTS_INJECTOR ? "IP" : "TCP", optstr, injectetdopt_size, lprev, actual_opts_len);
		
		return true;
	} else {
		return false;
	}
}
