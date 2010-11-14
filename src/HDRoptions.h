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

class HDRoptions {
private:
	int force_next;
	bool lsrr_set, ssrr_set;
	unsigned int actual_length, target_length;

#define CONST_RA_SIZE	4
	void m_IPOPT_RA(bool);
#define CONST_SEC_SIZE	11
	void m_IPOPT_SEC(bool);
#define CONST_SID_SIZE	4
	void m_IPOPT_SID(bool);
#define CONST_NOOP_SIZE	1
	void m_IPOPT_NOOP(bool);
#define CONST_CIPSO_SIZE 8
	void m_IPOPT_CIPSO(bool);

#define TMP_TIMESTAMP_SIZE	8
	// TMP because only TS_TSONLY is the next supported option
	void m_IPOPT_TIMESTAMP(bool);
	void m_IPOPT_TS_TSONLY(bool);
	void m_IPOPT_TS_PRESPEC(bool);
	void m_IPOPT_TS_TSANDADDR(bool);

	/* will be random between 8 and 40, but until we are not sure that is useful, is keep const */
#define CONST_LSRR_SIZE	8
	void m_IPOPT_LSRR(bool);

	/* little difference */
#define CONST_SSRR_SIZE	12
	void m_IPOPT_SSRR(bool);

private:
#if 0
	void m_TCPOPT_TIMESTAMP(unsigned int *, bool);
	void m_TCPOPT_EOL(unsigned int *, bool);
	void m_TCPOPT_NOP(unsigned int *, bool);
	void m_TCPOPT_MAXSEG(unsigned int *, bool);
	void m_TCPOPT_WINDOW(unsigned int *, bool);
	void m_TCPOPT_SACK_PERMITTED(unsigned int *, bool);
	void m_TCPOPT_SACK(unsigned int *, bool);
#endif
public:
	/* used for internal definition of IP opt functions */
#define SSRR_SJIP_OPT	0
#define LSRR_SJIP_OPT	1
#define RA_SJIP_OPT	2
#define CIPSO_SJIP_OPT	3
#define SEC_SJIP_OPT	4
#define SID_SJIP_OPT	5
#define NOOP_SJIP_OPT	6
#define TS_SJIP_OPT	7
#define TSONLY_SJIP_OPT	8

	/* used for internal definition of TCP opt functions */

	unsigned char *optptr;
	int randomInjector(bool);
	HDRoptions(unsigned char *, unsigned int, unsigned int);
	~HDRoptions();
};

#endif /* HDROPTIONS_H */
