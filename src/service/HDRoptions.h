/*
 * SniffJoke is a software able to confuse the Internet traffic analysis,
 * developed with the aim to improve digital privacy in communications and
 * to show and test some securiy weakness in traffic analysis software.
 *    
 *  Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                           evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "Utils.h"

/* not all options are defined in  the standard library */
#define IPOPT_CIPSO         (6 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_CIPSO_SIZE    10

/* required info taken from http://www.networksorcery.com/enp/protocol/ip.htm */
#define IPOPT_SID_SIZE      4

/* TCP opt code from: http://www.networksorcery.com/enp/protocol/tcp.htm */
#define TCPOPT_MSS          2

#define RFC_UNEXISTENT_CODE 255

enum injector_t
{
    IPOPTS_INJECTOR = 0, TCPOPTS_INJECTOR = 1
};

/* NOT corrupt is an option that will never give an error, ONESHOT is an option that 
 * make the packet dischargable, twoshot because some option trigger a fult if present 
 * two time in the same header, and BOTH are option that will be either good or malformed
 * to be dumped by the remote host */
enum corruption_t
{
    UNASSIGNED_VALUE = 0, NOT_CORRUPT = 1, ONESHOT = 2, TWOSHOT = 4
};

struct option_tracking
{
    bool isPresent;
    uint8_t *offset;
    uint8_t optlen;
};

/* this is the option used in an array long 
 * #SUPPORTED_OPTIONS element and present in every TTLfocus. */
struct option_discovery
{
    bool underTesting;
    bool confirmed;
    bool defaultWorking;
};

/*
 * these are the IP/TCP options supported in detection, injection,
 * corruption and so on. in the start of HDRoptions.cc this index are
 * used for fill the description structure
 */
#define SJ_IPOPT_NOOP               0
#define SJ_IPOPT_TIMESTAMP          1
#define SJ_IPOPT_LSRR               2
#define SJ_IPOPT_RR                 3
#define SJ_IPOPT_RA                 4
#define SJ_IPOPT_CIPSO              5
#define SJ_IPOPT_SEC                6
#define SJ_IPOPT_SID                7
/* you need to update this, when another IP options is added */
#define LAST_IPOPT_NAME             SJ_IPOPT_SID

#define SJ_TCPOPT_PAWSCORRUPT       8
#define SJ_TCPOPT_TIMESTAMP         9 
#define SJ_TCPOPT_MSS              10
#define SJ_TCPOPT_SACK             11

/* this too */
#define LAST_TCPOPT_NAME           SJ_TCPOPT_SACK

/* the last code + 1 */
#define SUPPORTED_OPTIONS          (LAST_TCPOPT_NAME + 1)

/* get random options: this will not need to be updated */
#define GET_RANDOM_IPOPT  ( random() % (LAST_IPOPT_NAME + 1) )
#define GET_RANDOM_TCPOPT ( ( random() % (LAST_TCPOPT_NAME - LAST_IPOPT_NAME ) ) + LAST_IPOPT_NAME + 1 )

class HDRoptions
{
private:
    injector_t type;
    bool corruptRequest;

    uint8_t target_opts_len; /* max value 40 on IP and TCP too */

    /*
     * options we need to check the presence for;
     * some options are good but if repeated may corrupt the packet.
     */
    bool checkupIPopt(void);
    bool checkupTCPopt(void);
    bool checkCondition(uint32_t, uint8_t);
 
public:
    vector<unsigned char> optshdr;
    uint8_t actual_opts_len; /* max value 40 on IP and TCP too */
    uint8_t available_opts_len; /* max value 40 on IP and TCP too */
    bool corruptDone;

    struct option_tracking optTrack[SUPPORTED_OPTIONS];
    uint8_t (* nextPlannedInj)(HDRoptions *);

    HDRoptions(injector_t, uint8_t *, uint8_t, uint8_t);
    void setupOption(struct option_discovery *);

    /* this is used for MALFORMED pourpose */
    uint32_t randomInjector(bool);
    uint32_t alignOpthdr(uint32_t);
    void copyOpthdr(uint8_t *);

    /* this is used if a Plugin want inject a specific option, in this case,
     * the value corruptRequest and corruptDone are ignored */
    bool calledInjector(uint32_t);

    bool removeOption(uint32_t);
};

struct option_mapping
{
    corruption_t corruptionType;
    uint8_t (* optApply)(HDRoptions *);
    uint8_t optValue;
    uint8_t applyProto;
    const char *optName;
};


#endif /* HDROPTIONS_H */
