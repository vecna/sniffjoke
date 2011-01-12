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
 
#ifndef SJ_INTERNALPROTOCOL_H
#define SJ_INTERNALPROTOCOL_H

#define START_COMMAND_TYPE	1
#define STOP_COMMAND_TYPE	2
#define QUIT_COMMAND_TYPE	3
#define DUMP_COMMAND_TYPE	4
#define STAT_COMMAND_TYPE	5
#define LOGLEVEL_COMMAND_TYPE	6
#define SETPORT_COMMAND_TYPE	7
#define SHOWPORT_COMMAND_TYPE	8
#define INFO_COMMAND_TYPE	9

#define COMMAND_ERROR_MSG	100

struct command_ret {
	uint32_t len;
	uint8_t command_type;
	/* follow in non error MSG the data dump */
};

/* this is the WHO value in SJStatus */
#define STAT_ACTIVE		1
#define STAT_MACGW		2
#define STAT_GWADDR		3
#define STAT_IFACE		4
#define STAT_LOIP		5
#define STAT_TUNN		6
#define STAT_DEBUGL		7
#define STAT_LOGFN		8
#define STAT_CHROOT		9
#define STAT_ENABLR		10
#define STAT_LOCAT		11
#define STAT_ONLYP		12
#define STAT_BINDA		13
#define STAT_BINDP		14
#define STAT_USER		15
#define STAT_GROUP		16

/* used for SJ_PortStat */
struct port_info {
	uint16_t start;
	uint16_t end;
	uint8_t weight;
};

/* port weight */
#define NONE            0
#define LIGHT           1
#define NORMAL          2
#define HEAVY           3

#endif /* SJ_INTERNALPROTOCOL_H */
