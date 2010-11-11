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

class HDRoptions {
private:
	int force_next;
	bool lsrr_set, ssrr_set;
	int actual_length, target_length;

#define CONST_RA_SIZE	4
	int m_IPOPT_RA(unsigned int *, bool);
#define CONST_SEC_SIZE	11
	int m_IPOPT_SEC(unsigned int *, bool);
	int m_IPOPT_SID(unsigned int *, bool);
	int m_IPOPT_NOOP(unsigned int *, bool);
	int m_IPOPT_CIPSO(unsigned int *, bool);

	int m_IPOPT_TIMESTAMP(unsigned int *, bool);
	int m_IPOPT_TS_TSONLY(unsigned int *, bool);
	int m_IPOPT_TS_PRESPEC(unsigned int *, bool);
	int m_IPOPT_TS_TSANDADDR(unsigned int *, bool);

	/* will be random between 8 and 40, but until we are not sure that is useful, is keep const */
#define CONST_LSRR_SIZE	8
	int m_IPOPT_LSRR(unsigned int *, bool);

	/* little difference */
#define CONST_SSRR_SIZE	12
	int m_IPOPT_SSRR(unsigned int *, bool);

private:
	int m_TCPOPT_TIMESTAMP(unsigned int *, bool);
	int m_TCPOPT_EOL(unsigned int *, bool);
	int m_TCPOPT_NOP(unsigned int *, bool);
	int m_TCPOPT_MAXSEG(unsigned int *, bool);
	int m_TCPOPT_WINDOW(unsigned int *, bool);
	int m_TCPOPT_SACK_PERMITTED(unsigned int *, bool);
	int m_TCPOPT_SACK(unsigned int *, bool);

public:
#define SSRR_SJ_OPT	0
#define LSRR_SJ_OPT	1
#define RA_SJ_OPT	2
	int randomInjector(bool);
	HDRoptions(unsigned char *, proto_t, unsigned int, unsigned int);
	~HDRoptions();
};

#endif /* HDROPTIONS_H */
