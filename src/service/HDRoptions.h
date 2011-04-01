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
    UNASSIGNED_VALUE = 0, NOT_CORRUPT = 1, ONESHOT = 2, TWOSHOT = 4, BOTH = 8
};

/*
 * The following class read the file 'option-support.conf' and setup
 * correctly the optMap struct when HDRoptions require it.
 *
 * Is called also from the HDRoptions_probe.cc plugin for option test
 */

struct optionInfo
{
    bool enabled;
    corruption_t availableUsage;
    uint8_t optValue;
    uint8_t optProtocol;
    const char *optName;
};

struct optHdrData
{
    vector<unsigned char> optshdr;
    uint8_t actual_opts_len; /* max value 40 on IP and TCP too */
    uint8_t available_opts_len; /* max value 40 on IP and TCP too */
    uint8_t target_opts_len; /* max value 40 on IP and TCP too */
};

class optionImplement
{
public:
    struct optionInfo info;
    uint8_t sjOptIndex;

    uint8_t getBestRandsize(struct optHdrData *, uint8_t, uint8_t, uint8_t, uint8_t);

    /* 
     * this is overloaded in the IPTCPoptions.cc implementation as protected virtual
     */
    virtual uint8_t optApply(struct optHdrData *);
    optionImplement(bool, uint8_t, const char *, uint8_t, uint8_t, corruption_t);
//    optionImplement();
    virtual ~optionImplement() = 0;
};

class optionLoader
{
private:
    static optionImplement *loadedOptions[SUPPORTED_OPTIONS];

    /* these static vars are used by getInitializedOpts, getNextOpts */
    static uint8_t settedProto;
    static uint8_t counter;

public:
    static bool isFileLoaded;

    /* methods for popoulate <vector>availOpts in HDRoptions */
    optionImplement * getSingleOption(uint8_t);
    void getInitializedOpts(uint8_t);
    optionImplement * getNextOpts(void);

    /* construction is overloaded because in the UserConf routine the 
     * configuration file is loaded and the static variable is setup.
     *
     * in hijacking time the constructor is called without any args */
    optionLoader(const char *);
    optionLoader(void);

    corruption_t lineParser(FILE *, uint8_t);
};

/* these struct are used inside HDRoptions for an easy handling */
struct option_occurrence
{
    uint8_t off;
    uint8_t len;
};

struct protocolSpec
{
    uint8_t NOP_code;
    uint8_t END_code;
    const char *protoName;
    
};

class HDRoptions
{
private:

    injector_t type;

    Packet &pkt;
    TTLFocus &ttlfocus;

    bool corruptRequest;
    bool corruptNow;
    bool corruptDone;

    /* this struct is used for be passed to the optionImplement extensions */
    struct optHdrData oD;

    /* this struct is used to track protocol reference, for use the same methods 
     * both for IP and TCP where possible */
    struct protocolSpec protD;

    vector<optionImplement *> availOpts;
    vector<option_occurrence> optTrack[SUPPORTED_OPTIONS];

    optionImplement *nextPlannedInj;

    /*
     * options we need to check the presence for;
     * some options are good but if repeated may corrupt the packet.
     */
    bool acquirePresentOptions(void);
    bool checkCondition(struct optionImplement *);

    /* after the call to optApply, HDRoptions need to be sync */
    optionImplement * updateCorruptAlign(optionImplement *, uint8_t);
    void registerOptOccurrence(uint8_t, uint8_t, uint8_t);

    uint32_t alignOpthdr();
    void copyOpthdr(uint8_t *);
    bool isGoalAchieved();

    bool prepareInjection(bool, bool);
    void completeInjection();

    void injector(uint8_t);
    void randomInjector();

public:

    HDRoptions(injector_t, Packet &, TTLFocus &);

    bool injectOpt(bool, bool, uint8_t);
    bool injectRandomOpts(bool, bool);

    bool removeOption(uint8_t);
};

#endif /* HDROPTIONS_H */
