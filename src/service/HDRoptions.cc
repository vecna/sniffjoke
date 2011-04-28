/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 * Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                          evilaliv3 <giovanni.pellerano@evilaliv3.org>
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
 * seems that some weird ipoptions will cause a packet to be discarded
 * on the route, without ever reach the server. we aim to create 
 * ipoptions accepted by the router, and discarded from the remote host.
 */
#include "hardcodedDefines.h"
/* defined at the bottom of hardcodedDefines.h */
#ifdef HEAVY_HDROPT_DEBUG
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "HDRoptions.h"
#include "IPTCPoptApply.h"
#include "Utils.h"

/* this class is a singleton one */
optionLoader* optionLoader::instance_ptr = NULL;

void optionLoader::select(uint8_t reqProto)
{
    settedProto = reqProto;
    counter = 0;
}

optionImplement* optionLoader::get(void)
{
    ++counter;

    if (counter == SUPPORTED_OPTIONS || loadedOptions[counter] == NULL)
        return NULL;

    if (loadedOptions[counter]->optProto == settedProto)
        return loadedOptions[counter];
    else
        return get();
}

optionImplement* optionLoader::getSingleOption(uint32_t sjOptIndex)
{
    if (sjOptIndex >= SUPPORTED_OPTIONS)
        RUNTIME_EXCEPTION("invalid use of optcode index");

    return (loadedOptions[sjOptIndex]);
}

corruption_t optionLoader::lineParser(FILE *flow, uint32_t optLooked)
{
    corruption_t retval = CORRUPTUNASSIGNED;
    char line[MEDIUMBUF];
    uint32_t linecnt = 0;

    do
    {
        uint32_t readedIndex, readedCorruption;

        fgets(line, MEDIUMBUF, flow);
        ++linecnt;

        if (feof(flow))
            break;

        if (strlen(line) < 2 || line[0] == '#')
            continue;

        sscanf(line, "%u,%u", &readedIndex, &readedCorruption);

        if (readedIndex < 1 || readedIndex > (SUPPORTED_OPTIONS - 1))
            RUNTIME_EXCEPTION("in option file invalid index at line %u", linecnt);

        if (readedIndex == optLooked)
            retval = (corruption_t) readedCorruption;
        else
            RUNTIME_EXCEPTION("found index %u instead of the expected %u (line %u)",
                              readedIndex, optLooked, linecnt);

    }
    while (retval == CORRUPTUNASSIGNED);

    if (retval == CORRUPTUNASSIGNED)
        RUNTIME_EXCEPTION("unable to found option index %u in the option config file", optLooked);

    LOG_VERBOSE("option index %d found value corruption value of %u", optLooked, (uint8_t) retval);

    return retval;
}

optionLoader::optionLoader(const char *fname)
{
    memset(loadedOptions, 0, sizeof (optionImplement*)*(SUPPORTED_OPTIONS));

    loadedOptions[SJ_IPOPT_NOOP] = new Io_NOOP(true);
    loadedOptions[SJ_IPOPT_TIMESTAMP] = new Io_TIMESTAMP(true);
    loadedOptions[SJ_IPOPT_TIMESTOVERFLOW] = new Io_TIMESTOVERFLOW(false);
    loadedOptions[SJ_IPOPT_LSRR] = new Io_LSRR(true);
    loadedOptions[SJ_IPOPT_RR] = new Io_RR(true);
    loadedOptions[SJ_IPOPT_RA] = new Io_RA(true);
    loadedOptions[SJ_IPOPT_CIPSO] = new Io_CIPSO(true);
    loadedOptions[SJ_IPOPT_SEC] = new Io_SEC(true);
    loadedOptions[SJ_IPOPT_SID] = new Io_SID(true);
    loadedOptions[SJ_TCPOPT_NOP] = new To_NOP(true);
    loadedOptions[SJ_TCPOPT_MD5SIG] = new To_MD5SIG(false);
    loadedOptions[SJ_TCPOPT_PAWSCORRUPT] = new To_PAWSCORRUPT(false);
    loadedOptions[SJ_TCPOPT_TIMESTAMP] = new To_TIMESTAMP(false);
    loadedOptions[SJ_TCPOPT_MSS] = new To_MSS(false);
    loadedOptions[SJ_TCPOPT_SACK] = new To_SACK(false);
    loadedOptions[SJ_TCPOPT_SACKPERM] = new To_SACKPERM(false);
    loadedOptions[SJ_TCPOPT_WINDOW] = new To_WINDOW(false);

    /* testing modality - all options are loaded without a corruption definitions */
    if (fname == NULL)
    {
        LOG_ALL("option configuration not supplied! Initializing in testing mode");
    }
    else
    {
        /* loading the configuration file, containings which option bring corruption for your ISP */
        /* NOW - sets with the default used by vecna & evilaliv3 */
        /* THESE DATA HAS TO BE LOADED FROM A Location-SPECIFIC CONFIGUATION FILE */
        corruption_t writUsage;
        FILE *optInput = fopen(fname, "r");

        if (optInput == NULL)
            RUNTIME_EXCEPTION("unable to open in reading options configuration %s: %s", fname, strerror(errno));

        for (uint8_t sjI = 1; sjI < SUPPORTED_OPTIONS; ++sjI)
        {
            writUsage = lineParser(optInput, sjI);
            loadedOptions[sjI]->optionConfigure(writUsage);
        }

        fclose(optInput);

        LOG_DEBUG("options configuration loaded correctly from %s: %d defs", fname, SUPPORTED_OPTIONS);
    }
}

optionLoader& optionLoader::get_instance(const char *fname)
{
    if (instance_ptr == NULL)
    {
        instance_ptr = new optionLoader(fname);
    }
    return *instance_ptr;
}

void optionLoader::del_instance(void)
{
    if (instance_ptr != NULL)
    {
        delete instance_ptr;
        instance_ptr = NULL;
    }
}

/* Now start the implementation of HDRoptions member */
HDRoptions::HDRoptions(injector_t t, Packet &pkt, TTLFocus &ttlfocus) :
type(t),
pkt(pkt),
ttlfocus(ttlfocus),
corruptRequest(false),
corruptDone(false),
nextPlannedInj(SJ_NULL_OPT)
{
    optionLoader &optConfigData = optionLoader::get_instance("");
    optionImplement *usableOption;

    /* initialization of header and indexes on specific proto basis */
    switch (type)
    {
    case IPOPTS_INJECTOR:

        protD.protoName = "IP";
        protD.startOpt = FIRST_IPOPT;
        protD.endOpt = LAST_IPOPT;
        protD.NOP_code = IPOPT_NOOP;
        protD.END_code = IPOPT_END;

        oD.actual_opts_len = pkt.iphdrlen - sizeof (struct iphdr);

        oD.optshdr.resize(MAXIPOPTIONS, IPOPT_EOL);
        memcpy((void *) &oD.optshdr[0], (uint8_t *) pkt.ip + sizeof (struct iphdr), oD.actual_opts_len);

        /* initialized the vector using the pointer of the static private data
         * in optionLoaded::loadedOptions */
        for (optConfigData.select(IPPROTO_IP); (usableOption = optConfigData.get()) != NULL;)
        {
            /* specific per-classes initialization need to be called here */
            if (usableOption->sjOptIndex == SJ_IPOPT_TIMESTOVERFLOW)
                (reinterpret_cast<Io_TIMESTOVERFLOW *> (usableOption))->setupTTLFocus(&ttlfocus);

            availOpts.push_back(usableOption);
        }
        break;

    case TCPOPTS_INJECTOR:

        protD.protoName = "TCP";
        protD.startOpt = FIRST_TCPOPT;
        protD.endOpt = LAST_TCPOPT;
        protD.NOP_code = TCPOPT_NOP;
        protD.END_code = TCPOPT_EOL;

        oD.actual_opts_len = pkt.tcphdrlen - sizeof (struct tcphdr);

        oD.optshdr.resize(MAXTCPOPTIONS, TCPOPT_EOL);
        memcpy((void *) &oD.optshdr[0], (uint8_t *) pkt.tcp + sizeof (struct tcphdr), oD.actual_opts_len);

        /* initialize the vector using the pointer of the static private data
         * in optionLoaded::loadedOptions */
        for (optConfigData.select(IPPROTO_TCP); (usableOption = optConfigData.get()) != NULL;)
            availOpts.push_back(usableOption);

        break;
    }

    acquirePresentOptions();
}

/*
 *    returns true if injection is possible, false instead;
 *    in addition it registers the presence of some options.
 */
bool HDRoptions::acquirePresentOptions(void)
{
    for (uint8_t i = 0; i < oD.actual_opts_len;)
    {
        uint8_t * const option = &oD.optshdr[i];

        /* remember :
         * NOP_code will be IPOPT_NOOP or TCPOPT_NOP either,
         * is set in the constructor, like every other protocol dependend values */
        if (*option == protD.NOP_code)
        {
            ++i;
            continue;
        }

        if (*option == protD.END_code)
            break;

        const uint8_t option_len = (uint8_t) oD.optshdr[i + 1];
        if (option_len == 0 || option_len > (oD.actual_opts_len - i))
        {
            /*
             * the packet contains invalid options
             * we avoid injection regardless of the corrupt value.
             *
             * REMIND: 
             * will this became a vulnerability if we check incoming packet 
             */
            RUNTIME_EXCEPTION("invalid %s opt: option|%02x option_len|%u residual|%u",
                              protD.protoName, *option, option_len, (oD.actual_opts_len - i));
        }

        bool identified = false;
        for (vector<optionImplement *>::iterator it = availOpts.begin(); it != availOpts.end(); ++it)
        {
            optionImplement *underVerify = *it;

            if (*option == underVerify->optValue)
            {
                identified = true;
                registerOptOccurrence(underVerify, i, option_len);
                break;
            }
        }

        if (!identified)
        {
            /*
             * analysis: will we make a malformed and stripping an option we don't know ?
             * I belive is better to return false if the code is running here, but I prefer
             * support every IP options available in the optMap[].
             * for this reason, in the beta and < 1.0 release the previous message
             * will be used for debug & progress pourposes.
             */
            RUNTIME_EXCEPTION("INFO: a non trapped %s-options (pkt %d): hex: %02x dec: %d length %d",
                              protD.protoName, pkt.SjPacketId, *option, *option, option_len);
        }

        i += option_len;
    }

    return true;
}

/*
 * this is a core method inside HDRoptions, it:
 * 1) check if a requested (will be random, will be by code) is enabled 
 * 2) check if the goal is corrupt or not, and choose the option by the counter data 
 */
bool HDRoptions::evaluateInjectCoherence(optionImplement *requested, struct optHdrData *oD, int8_t counterInj)
{

    /*
     * 1st global check: can we use this option ?
     * at the time a global enabled variable is used to permit selective testing
     */
    if (requested->enabled == false)
        return false;

    /*
     * 2nd global check: at which state of the injection are we?
     * we avoid corrupt options if we have just corrupted the packet
     * and we also alter the probability for the first injection
     * in favour of good injection.
     */
    switch (requested->availableUsage)
    {
    case NOT_CORRUPT:
        if (corruptRequest == false)
            return true;

        /* also on corruptRequest == true, the first options had not to be bad */
#if 0
        if ((oD->actual_opts_len < 8) && RANDOM_PERCENT(45))
            return true;
#endif  /* funny randomization BUT in the single Injection used by HDRoptions_probe is a bug */

        break;
    case ONESHOT:
        /* I like to corrupt only once */
        if (corruptRequest == true && corruptDone == false)
            return true;

        break;
    case TWOSHOT:
        if (corruptRequest == true && corruptDone == false)
        {
            if (counterInj == 0 || counterInj == 1)
                return true;
        }
        break;
    default:
        break;
    }

    /* if the requested option doesn't fit with the goal+status, and thus the
     * previous switch() has returned "true", the answer will be only a drop */
    return false;
}

/* this is called on acquiring present options and after the injection,
 * it keeps track of every option, absolute offset and length (because will be
 * request a selective deletion), and mark the corruption "done" if a
 * bad option has been used 
 */
void HDRoptions::registerOptOccurrence(struct optionImplement *oDesc, uint8_t offset, uint8_t len)
{
    struct option_occurrence occ;
    uint8_t sjOndx = oDesc->sjOptIndex;

    if (oDesc->availableUsage == ONESHOT)
        corruptDone = true;

    occ.off = offset;
    occ.len = len;

    if (oDesc->availableUsage == TWOSHOT && optTrack[sjOndx].size() > 1)
        corruptDone = true;

    optTrack[sjOndx].push_back(occ);
}

uint32_t HDRoptions::alignOpthdr()
{

    uint8_t alignBytes = (oD.actual_opts_len % 4) ? 4 - (oD.actual_opts_len % 4) : 0;
    if (alignBytes)
    {
        oD.optshdr[oD.actual_opts_len] = protD.END_code;

        oD.actual_opts_len += alignBytes;

        LOG_PACKET("*+ aligned to %u for %u bytes (avail %u)", oD.actual_opts_len, alignBytes, oD.getAvailableOptLen());
    }

    return oD.actual_opts_len;
}

void HDRoptions::copyOpthdr(uint8_t *dst)
{
    memcpy(dst, &oD.optshdr[0], oD.actual_opts_len);
}

bool HDRoptions::isGoalAchieved()
{
    return corruptRequest == corruptDone;
}

bool HDRoptions::prepareInjection(bool corrupt, bool strip_previous)
{
    uint16_t freespace = MTU - pkt.pbuf.size();

    LOG_PACKET("*? strip request [%s] freespace %d, actual opts %d", 
        strip_previous ? "YES strip" : "NO keep", freespace, oD.actual_opts_len);

    if (strip_previous)
    {
        freespace += oD.actual_opts_len;
        oD.actual_opts_len = 0;
    }

    // ip/tcp hdrlen must be a multiple of 4, we decrement by the modulus keeping count of MTU
    freespace -= freespace % 4;
    if (freespace == 0)
        return false;

    corruptRequest = corrupt;

    return true;
}

void HDRoptions::completeInjection()
{

    alignOpthdr();

    if (type == IPOPTS_INJECTOR)
    {
        LOG_PACKET("*- resize IPhdr to contain %d options len", oD.actual_opts_len);
        pkt.iphdrResize((sizeof (struct iphdr)) + oD.actual_opts_len);
        copyOpthdr((uint8_t *) pkt.ip + sizeof (struct iphdr));
    }
    else
    {
        LOG_PACKET("*- resize TCPhdr to contain %d options len", oD.actual_opts_len);
        pkt.tcphdrResize((sizeof (struct tcphdr)) + oD.actual_opts_len);
        copyOpthdr((uint8_t *) pkt.tcp + sizeof (struct tcphdr));
    }
}

void HDRoptions::injector(uint32_t sjOptIndex)
{
    optionImplement *requested = NULL;

    for (vector<optionImplement *>::iterator underVerify = availOpts.begin(); underVerify != availOpts.end(); ++underVerify)
    {
        if ((*underVerify)->sjOptIndex == sjOptIndex)
        {
            requested = *underVerify;
            break;
        }
    }

    if (requested == NULL)
        RUNTIME_EXCEPTION("invalid index %u in registered protocol %s", sjOptIndex, protD.protoName);

    LOG_PACKET("*1 %s single opt [%u] option: actual_opt_len(%u) (avail %u) goal %s",
               protD.protoName, sjOptIndex, oD.actual_opts_len, oD.getAvailableOptLen(),
               corruptRequest ? "CORRUPT" : "NOT CORRUPT");

    /* if needed by corruption method, make two time the injection, otherwise 1, otherwise 0 */
    for (int8_t counterInj = 0; evaluateInjectCoherence(requested, &oD, counterInj); ++counterInj)
    {
        uint8_t writtedLen = requested->optApply(&oD);

        if (writtedLen > 0)
        {

            LOG_PACKET("** %s at the index of %u options length of %u (avail %u)",
                       requested->sjOptName, requested->sjOptIndex, writtedLen, oD.getAvailableOptLen());

            oD.actual_opts_len += writtedLen;
            registerOptOccurrence(requested, oD.actual_opts_len, writtedLen);
        }
    }

    LOG_PACKET("*2 %s single opt [%u] option: actual_opt_len(%u) (avail %u) goal %s ",
               protD.protoName, sjOptIndex, oD.actual_opts_len, oD.getAvailableOptLen(),
               isGoalAchieved() ? "ACHIEVED" : "NOT ACHIEVED");
}

void HDRoptions::randomInjector()
{
    LOG_PACKET("*1 %s option: actual_opt_len(%u) (avail %u) goal %s",
               protD.protoName, oD.actual_opts_len, oD.getAvailableOptLen(),
               corruptRequest ? "CORRUPT" : "NOT CORRUPT");

    random_shuffle(availOpts.begin(), availOpts.end());
    for (vector<optionImplement *>::iterator it = availOpts.begin(); it != availOpts.end(); ++it)
    {
        optionImplement *randOpt = *it;

        for (uint8_t counterInj = 0; evaluateInjectCoherence(randOpt, &oD, counterInj); ++counterInj)
        {
            uint8_t writtedLen = randOpt->optApply(&oD);

            if (writtedLen > 0)
            {
                oD.actual_opts_len += writtedLen;
                registerOptOccurrence(randOpt, oD.actual_opts_len, writtedLen);
            }
            else
            {
                /* to avoid time consuming checks and loops:
                 * if there is not enougth space, skip! */
                break;
            }

            /* to avoid duplication of the same good option */
            if (randOpt->availableUsage == NOT_CORRUPT)
                break;
        }
    }

    LOG_PACKET("*2 %s option: actual_opt_len(%u) (avail %u) goal %s ",
               protD.protoName, oD.actual_opts_len, oD.getAvailableOptLen(),
               isGoalAchieved() ? "ACHIEVED" : "NOT ACHIEVED");
}

bool HDRoptions::injectSingleOpt(bool corrupt, bool strip_previous, uint32_t sjOptIndex)
{
    if (sjOptIndex >= SUPPORTED_OPTIONS)
        RUNTIME_EXCEPTION("invalid use of optcode index");

    if (prepareInjection(corrupt, strip_previous))
        injector(sjOptIndex);

    if (!isGoalAchieved())
        return false;

    completeInjection();
    return true;
}

bool HDRoptions::injectRandomOpts(bool corrupt, bool strip_previous)
{
    if (prepareInjection(corrupt, strip_previous))
        randomInjector();

    if (!isGoalAchieved())
        return false;

    completeInjection();
    return true;
}

/* off-topic naming base rule: 
 *
 * sjOptIndex is the uint32_t name of the index, defined in hardcodedDefines.h
 *            sometime, will be shortened with "sjI"
 * optValue is the uint8_t name used for the binary value copyed in the optHdr
 */
bool HDRoptions::removeOption(uint32_t sjI)
{
    if (sjI >= SUPPORTED_OPTIONS)
        RUNTIME_EXCEPTION("invalid use of optcode index");

    /* if an option is request to be deleted, we need to check if it exists! */
    if (optTrack[sjI].size() == 0)
        return false;

    for (vector<option_occurrence>::iterator it = optTrack[sjI].begin(); it != optTrack[sjI].end(); it = optTrack[sjI].erase(it))
    {

        vector<unsigned char>::iterator start = oD.optshdr.begin() + it->off;
        vector<unsigned char>::iterator end = start + it->len;
        oD.optshdr.erase(start, end);

        oD.actual_opts_len -= it->len;
    }

    completeInjection();

    return true;
}

HDRoptions::~HDRoptions(void)
{
#ifdef HEAVY_HDROPT_DEBUG
#define HDR_PREFIX  "HDRoLog/"
    optionLoader &optConfigData = optionLoader::get_instance("");

    char fname[MEDIUMBUF];
    FILE *HDRoLog;

    mkdir(HDR_PREFIX, 0770);
    snprintf(fname, MEDIUMBUF, "%s%s-%s", HDR_PREFIX, inet_ntoa(*((struct in_addr *) &(pkt.ip->daddr))), protD.protoName);

    if ((HDRoLog = fopen(fname, "a+")) == NULL)
        RUNTIME_EXCEPTION("unable to open %s:%s", fopen, strerror(errno));

    fprintf(HDRoLog, "RD %u%u SAPFR{%u%u%u%u%u}\tp#%u id%u\t",
            corruptRequest, corruptDone,
            pkt.tcp->syn, pkt.tcp->ack, pkt.tcp->psh, pkt.tcp->fin, pkt.tcp->rst,
            pkt.SjPacketId, ntohs(pkt.ip->id)
            );

    for (uint8_t i = protD.startOpt; i <= protD.endOpt; ++i)
    {
        if (optTrack[i].size() == false)
        {
            fprintf(HDRoLog, " ~%u", i);
        }
        else
        {
            optionImplement *yep = optConfigData.getSingleOption(i);
            fprintf(HDRoLog, " %s", yep->sjOptName);

            for (vector<option_occurrence>::iterator it = optTrack[i].begin(); it != optTrack[i].end(); ++it)
                fprintf(HDRoLog, ":%u(%u)", it->off, it->len);
        }
    }
    fprintf(HDRoLog, "\n");

    fclose(HDRoLog);
#endif
}

/* all the derived classes implemented in IPTCPoptApply call this constructor */
optionImplement::optionImplement(bool enable, uint8_t sjI, const char * const sjN, uint8_t proto, uint8_t opcode) :
enabled(enable),
sjOptIndex(sjI),
sjOptName(sjN),
optProto(proto),
optValue(opcode),
availableUsage(CORRUPTUNASSIGNED)
{
}

void optionImplement::optionConfigure(corruption_t c)
{

    availableUsage = c;
}

/* this is the utility function used by the single option adder to calculate the best fit size for an option */
uint8_t optionImplement::getBestRandsize(struct optHdrData *oD, uint8_t fixedLen, uint8_t minRblks, uint8_t maxRblks, uint8_t blockSize)
{
    uint8_t minComputed = fixedLen + (minRblks * blockSize);
    uint8_t maxComputed = fixedLen + (maxRblks * blockSize);

    uint8_t checkedAvail = oD->getAvailableOptLen();

    if (checkedAvail == minComputed || checkedAvail == maxComputed)
        return checkedAvail;

    if (checkedAvail < minComputed)
        return 0;

    if (checkedAvail > maxComputed)
        return (((random() % (maxRblks - minRblks + 1)) + minRblks) * blockSize) + fixedLen;

    /* else should try the best filling of memory and the NOP fill after */

    uint8_t blockNumber = (checkedAvail - fixedLen) / blockSize;
    return ((blockNumber * blockSize) + fixedLen);
}
