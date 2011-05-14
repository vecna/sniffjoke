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

/* protocol specification contains the difference between TCP and IP header 
 * manipoulation. is useful for make a simple code usable in both cases */
struct protocolSpec
{
    const char *protoName;
    uint8_t firstOptIndex;
    uint8_t lastOptIndex;
    uint8_t NOP_code;
    uint8_t EOL_code;
    void **hdrAddr;
    uint8_t *hdrLen;
    uint8_t hdrMinLen;
    uint8_t optsMaxLen;
    void (Packet::*hdrResize)(uint8_t);
};

class HDRoptions
{
private:

    injector_t type;

    Packet &pkt;
    TTLFocus &ttlfocus;

    bool corruptRequest;
    bool corruptDone;

    /* this struct is used to be passed to the IPTCPoptImpl extensions */
    struct optHdrData oD;

    /* this struct is used to track protocol reference, to use the same methods 
     * both for IP and TCP where possible */
    struct protocolSpec protD;

    vector<option_occurrence> optTrack[SUPPORTED_OPTIONS];

    /* validates present option and makes a working copy */
    void acquirePresentOptions(uint32_t);

    /* the core selecting function */
    bool evaluateInjectCoherence(uint8_t);

    /* registers the presence of an option and returns occurrences count */
    uint8_t registerOptOccurrence(uint8_t, uint8_t, uint8_t);

    /* alignment of option header to be divisible by 4 */
    void alignOpthdr(void);

    /* utilities functions */
    void copyOpthdr(void);
    bool isGoalAchieved(void);

    bool prepareInjection(bool, bool);
    void completeHdrEdit(void);

    void injector(uint8_t);
    void randomInjector(void);

public:

    HDRoptions(injector_t, Packet &, TTLFocus &);
    ~HDRoptions();

    bool injectSingleOpt(bool, bool, uint8_t);
    bool injectRandomOpts(bool, bool);

    bool stripOption(uint8_t);
    void stripAllOptions();
};

#endif /* HDROPTIONS_H */
