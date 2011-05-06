/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011 vecna <vecna@delirandom.net>
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

#include <stdint.h>
#include <time.h>

#define START_COMMAND_TYPE          1
#define STOP_COMMAND_TYPE           2
#define QUIT_COMMAND_TYPE           3
#define SAVECONF_COMMAND_TYPE       4
#define STAT_COMMAND_TYPE           5
#define LOGLEVEL_COMMAND_TYPE       6
#define SETPORT_COMMAND_TYPE        7
#define SHOWPORT_COMMAND_TYPE       8
#define INFO_COMMAND_TYPE           9
#define TTLMAP_COMMAND_TYPE        10
#define COMMAND_ERROR_MSG         100

/* this contain the description of the entire block */
struct command_ret
{
    uint32_t cmd_len;
    uint32_t cmd_type;
    /* follow in non error MSG the data dump */
};

/* this is the WHO value in SJStatus */
#define STAT_ACTIVE         1
#define STAT_DEBUGL         2
#define STAT_LOCAT          3
#define STAT_MACGW          4
#define STAT_GWADDR         5
#define STAT_NETIFACENAME   6
#define STAT_NETIFACEIP     7
#define STAT_NETIFACEMTU    8
#define STAT_TUNIFACENAME   9
#define STAT_TUNIFACEIP     10
#define STAT_TUNIFACEMTU    11
#define STAT_BINDA          12
#define STAT_BINDP          13
#define STAT_USER           14
#define STAT_GROUP          15
#define STAT_CHAINING       16
#define STAT_NO_TCP         17
#define STAT_NO_UDP         18
#define STAT_WHITELIST      19
#define STAT_BLACKLIST      20
#define STAT_ONLYP          21

/* and in SJStatus are used this struct for describe the single block */
struct single_block
{
    uint32_t len;
    uint32_t WHO;
};
/* WHO stay for: who do you choose between Yvonne Strahovski and 
 * Scarlett Johansson for repopulate the Heart after the 
 * nuclear fallout ? */

/* used for SJ_PortStat */
struct port_info
{
    uint16_t start;
    uint16_t end;
    uint16_t weight;
};

/* this struct is used for Info command handling, 
 * it contains a single session record */
struct sex_record
{
    uint8_t proto;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint32_t packet_number;
    uint32_t injected_pktnumber;
};

/* this struct used for ttlmap command handling */
struct ttl_record
{
    time_t access;
    time_t nextprobe;
    uint32_t daddr;
    uint8_t sentprobe;
    uint8_t receivedprobe;
    uint8_t synackval;
    uint8_t ttlestimate;
};

#endif /* SJ_INTERNALPROTOCOL_H */
