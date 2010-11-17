/*
 * SniffJoke is a software able to confuse the Internet traffic analysis,
 * developed with the aim to improve digital privacy in communications and
 * to show and test some securiy weakness in traffic analysis software.
 *    
 *      Copyright (C) 2010 vecna <vecna@delirandom.net>
 *                         evilaliv3 <giovanni.pellerano@evilaliv3.org>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HDROPTIONS_H
#define HDROPTIONS_H

#include "Packet.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>

/* present in linux/ip.h */
#define IPOPT_CIPSO	(6 |IPOPT_CONTROL|IPOPT_COPY)

enum injector_t { IPOPTS_INJECTOR = 0, TCPOPTS_INJECTOR = 1 };

class HDRoptions {
private:
	injector_t type;
	unsigned char *optptr;
	unsigned int &actual_length;
	unsigned int &target_length;
	unsigned int available_length;
	
	int force_next;
	
	/* IP HDR Injector specific status variables */
	bool lsrr_set, ssrr_set;

#define CONST_RA_SIZE 4
	unsigned int m_IPOPT_RA(bool);
#define CONST_RR_SIZE 4
	unsigned int m_IPOPT_RR(bool);
#define CONST_SEC_SIZE 11
	unsigned int m_IPOPT_SEC(bool);
#define CONST_SID_SIZE 4
	unsigned int m_IPOPT_SID(bool);
#define CONST_NOOP_SIZE	1
	unsigned int m_IPOPT_NOOP(bool);
#define CONST_CIPSO_SIZE 8
	unsigned int m_IPOPT_CIPSO(bool);
#define CONST_TIMESTAMP_SIZE 4
	unsigned int m_IPOPT_TIMESTAMP(bool);

	/* will be random between 8 and 40, but until we are not sure that is useful, is keep const */
#define CONST_LSRR_SIZE	8
	unsigned int m_IPOPT_LSRR(bool);

	/* little difference */
#define CONST_SSRR_SIZE	12
	unsigned int m_IPOPT_SSRR(bool);

	unsigned int m_TCPOPT_TIMESTAMP(bool);
	unsigned int m_TCPOPT_EOL(bool);
	unsigned int m_TCPOPT_NOP(bool);
	unsigned int m_TCPOPT_MAXSEG(bool);
	unsigned int m_TCPOPT_WINDOW(bool);
	unsigned int m_TCPOPT_SACK_PERMITTED(bool);
	unsigned int m_TCPOPT_SACK(bool);

public:
	/* used for internal definition of IP opt functions */
#define SJIP_OPT_SSRR			0
#define SJIP_OPT_LSRR			1
#define SJIP_OPT_RR			2
#define SJIP_OPT_RA			3
#define SJIP_OPT_CIPSO			4
#define SJIP_OPT_SEC			5
#define SJIP_OPT_SID			6
#define SJIP_OPT_NOOP			7
#define SJIP_OPT_TS			8

#define SJTCP_OPT_TIMESTAMP		0
#define SJTCP_OPT_EOL			1
#define SJTCP_OPT_NOP			2
#define SJTCP_OPT_MAXSEG		3
#define SJTCP_OPT_WINDOW		4
#define SJTCP_OPT_SACK_PERMITTED	5
#define SJTCP_OPT_SACK			6


	/* used for internal definition of TCP opt functions */

	HDRoptions(injector_t, unsigned char *, unsigned int &, unsigned int &);
	~HDRoptions();
	
	void randomInjector(bool);
};

#endif /* HDROPTIONS_H */
