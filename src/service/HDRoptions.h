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
#include "Packet.h"
#include "TTLFocus.h"
#include "IPTCPopt.h"

#define MAXIPOPTIONS 40
#define MAXTCPOPTIONS 40
#define MINIPOPTION 4 /* excluded NOP/EOL */
#define MINTCPOPTION 4 /* excluded NOP/EOL */
#define MAXIPINJITERATIONS 5 /* max number of injected ip options / retries */
#define MAXTCPINJITERATIONS 5 /* max number of injected tcp options / retries */

/* 
 * not all options are defined in the standard library,
 * so some values are defined here.
 * 
 * references:
 * 
 *     http://www.networksorcery.com/enp/protocol/ip.htm
 *     http://www.networksorcery.com/enp/protocol/tcp.htm
 */

#define IPOPT_NOOP_SIZE     1
#define IPOPT_CIPSO         (6 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_CIPSO_SIZE    10
#define IPOPT_SID_SIZE      4

#define TCPOPT_NOP_SIZE     1
#define TCPOPT_MD5SIG       19
#define TCPOPT_MD5SIG_SIZE  18
#define TCPOPT_MSS          2
#define TCPOPT_MSS_SIZE     4

#define DUMMY_OPCODE        255

/* 
 * HDRoptions logic:
 *
 * The class optionLoaded, read from the file * 'option-support.conf' and setup
 * the optionImplement 
 *
 * the HDRoptions is called for every Packet needing a manipoulation over the
 * header options, and import the correctly loaded impelementation from optionImplement
 *
 * optionImplement has some virtual methods and are implemented in 
 * IPTCPoptApply.cc
 *
 * HDRoptions_probe.cc is plugin for option test and use those classess in a 
 * lighty different way 
 */

enum injector_t
{
    IPOPTS_INJECTOR = 0, TCPOPTS_INJECTOR = 1
};

/* these struct are used inside HDRoptions for an easy handling */
struct option_occurrence
{
    uint8_t off;
    uint8_t len;
};

struct protocolSpec
{
    const char *protoName;
    uint8_t startOpt;
    uint8_t endOpt;
    uint8_t NOP_code;
    uint8_t END_code;
};

class HDRoptions
{
private:

    injector_t type;

    Packet &pkt;
    TTLFocus &ttlfocus;

    bool corruptRequest;
    bool corruptDone;

    /* this struct is used to be passed to the optionImplement extensions */
    struct optHdrData oD;

    /* this struct is used to track protocol reference, to use the same methods 
     * both for IP and TCP where possible */
    struct protocolSpec protD;

    vector<IPTCPopt *> availOpts;
    vector<option_occurrence> optTrack[SUPPORTED_OPTIONS];

    IPTCPopt *nextPlannedInj;

    /*
     * options we need to check the presence for;
     * some options are good but if repeated may corrupt the packet.
     */
    bool acquirePresentOptions(void);

    /* the core selecting function */
    bool evaluateInjectCoherence(IPTCPopt *, struct optHdrData *, int8_t);

    /* after the call to optApply, HDRoptions need to be sync */
    void registerOptOccurrence(struct IPTCPopt *, uint8_t, uint8_t);

    /* alignment of option header to be divisible by 4 */
    uint32_t alignOpthdr();

    /* utilities functions */
    uint8_t availableOptsLen(void);
    void copyOpthdr(uint8_t *);
    bool isGoalAchieved();

    bool prepareInjection(bool, bool);
    void completeInjection();

    void injector(uint32_t);
    void randomInjector();

public:

    HDRoptions(injector_t, Packet &, TTLFocus &);
    ~HDRoptions();

    bool injectSingleOpt(bool, bool, uint32_t);
    bool injectRandomOpts(bool, bool);

    bool removeOption(uint32_t);
};

#endif /* HDROPTIONS_H */
