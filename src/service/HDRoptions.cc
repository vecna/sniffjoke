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

#include "IPTCPopt.h"
#include "IPTCPoptImpl.h"
#include "OptionPool.h"

extern auto_ptr<OptionPool> opt_pool;

/* Now start the implementation of HDRoptions member */
HDRoptions::HDRoptions(injector_t t, Packet &pkt, TTLFocus &ttlfocus) :
type(t),
pkt(pkt),
ttlfocus(ttlfocus),
corruptRequest(false),
corruptDone(false)
{

    /* initialization of header and indexes on specific proto basis */
    switch (type)
    {
    case IPOPTS_INJECTOR:

        protD.protoName = "IP";
        protD.firstOptIndex = FIRST_IPOPT;
        protD.lastOptIndex = LAST_IPOPT;
        protD.NOP_code = IPOPT_NOOP;
        protD.END_code = IPOPT_END;
        protD.hdrAddr = (uint8_t**) & pkt.ip;
        protD.fixedHdrLen = sizeof (struct iphdr);
        protD.optsMaxLen = MAXIPOPTIONS;
        protD.hdrResize = &Packet::iphdrResize;

        oD.actual_opts_len = pkt.iphdrlen - sizeof (struct iphdr);

        for (uint8_t i = protD.firstOptIndex; i <= protD.lastOptIndex; ++i)
        {
            switch (i) /* Specific options configurations goes here */
            {
            case SJ_IPOPT_TIMESTOVERFLOW:
                (reinterpret_cast<Io_TIMESTOVERFLOW *> ((*opt_pool)[i]))->setupTTLFocus(&ttlfocus);
                break;

            default:
                break;
            }
        }

        break;

    case TCPOPTS_INJECTOR:

        protD.protoName = "TCP";
        protD.firstOptIndex = FIRST_TCPOPT;
        protD.lastOptIndex = LAST_TCPOPT;
        protD.NOP_code = TCPOPT_NOP;
        protD.END_code = TCPOPT_EOL;
        protD.hdrAddr = (uint8_t**) & pkt.tcp;
        protD.fixedHdrLen = sizeof (struct tcphdr);
        protD.optsMaxLen = MAXTCPOPTIONS;
        protD.hdrResize = &Packet::tcphdrResize;

        oD.actual_opts_len = pkt.tcphdrlen - sizeof (struct tcphdr);

        for (uint8_t i = protD.firstOptIndex; i <= protD.lastOptIndex; ++i)
        {
            switch (i) /* Specific options configurations goes here */
            {
            default:
                break;
            }
        }

        break;
    }

    oD.optshdr.resize(protD.optsMaxLen, protD.END_code);

    acquirePresentOptions();
}

/*
 *    returns true if injection is possible, false instead;
 *    in addition it registers the presence of some options.
 */
bool HDRoptions::acquirePresentOptions(void)
{
    if (oD.actual_opts_len == 0)
        return true;

    memcpy(&oD.optshdr[0], *protD.hdrAddr + protD.fixedHdrLen, oD.actual_opts_len);

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
        for (vector<IPTCPopt *>::iterator it = opt_pool->begin(); it != opt_pool->end(); ++it)
        {
            IPTCPopt *underVerify = *it;

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
 * 1) check if a requested option(selected by a random or forced by a plugin) is enabled
 * 2) check if the goal is to corrupt or not, and choose the option by the counter data
 */
bool HDRoptions::evaluateInjectCoherence(IPTCPopt *requested, struct optHdrData *oD, uint8_t counterInj)
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
        if (corruptRequest == false && counterInj == 0)
            return true;
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
void HDRoptions::registerOptOccurrence(struct IPTCPopt *oDesc, uint8_t offset, uint8_t len)
{
    const uint8_t sjOndx = oDesc->sjOptIndex;

    if (oDesc->availableUsage == ONESHOT)
        corruptDone = true;

    struct option_occurrence occ;
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

void HDRoptions::copyOpthdr()
{
    memcpy(*protD.hdrAddr + protD.fixedHdrLen, &oD.optshdr[0], oD.actual_opts_len);
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
    ((pkt).*(protD.hdrResize))(protD.fixedHdrLen + oD.actual_opts_len);
    copyOpthdr();

    LOG_PACKET("*- resize %shdr to contain %d options len", protD.protoName, oD.actual_opts_len);
}

void HDRoptions::injector(uint8_t sjOptIndex)
{
    IPTCPopt *requested = (*opt_pool)[sjOptIndex];

    /* if needed by corruption method, make two time the injection, otherwise 1, otherwise 0 */
    for (uint8_t counterInj = 0; evaluateInjectCoherence(requested, &oD, counterInj); ++counterInj)
    {
        const uint8_t writtedLen = requested->optApply(&oD);

        if (writtedLen > 0)
        {
            LOG_PACKET("** %s at the index of %u options length of %u (avail %u)",
                       requested->sjOptName, requested->sjOptIndex, writtedLen, oD.getAvailableOptLen());

            oD.actual_opts_len += writtedLen;
            registerOptOccurrence(requested, oD.actual_opts_len, writtedLen);
        }

        else
        {
            /* to avoid time consuming checks and loops:
             * if there is not enougth space, skip! */
            break;
        }
    }
}

void HDRoptions::randomInjector()
{
    vector<uint8_t> seq;

    for (uint8_t i = protD.firstOptIndex; i <= protD.lastOptIndex; ++i)
        seq.push_back(i);

    random_shuffle(seq.begin(), seq.end());

    for (vector<uint8_t>::iterator it = seq.begin(); it != seq.end(); ++it)
        injector(*it);
}

bool HDRoptions::injectSingleOpt(bool corrupt, bool strip_previous, uint8_t sjOptIndex)
{
    /* this check need to be done only on external public functions */
    if (sjOptIndex < protD.firstOptIndex || sjOptIndex > protD.lastOptIndex)
        RUNTIME_EXCEPTION("invalid use of optcode index: %u");

    LOG_PACKET("*1 %s single opt [%u] option: actual_opt_len(%u) (avail %u) goal %s",
               protD.protoName, sjOptIndex, oD.actual_opts_len, oD.getAvailableOptLen(),
               corruptRequest ? "CORRUPT" : "NOT CORRUPT");

    if (prepareInjection(corrupt, strip_previous))
        injector(sjOptIndex);

    if (!isGoalAchieved())
        return false;

    completeInjection();

    LOG_PACKET("*2 %s single opt [%u] option: actual_opt_len(%u) (avail %u) goal %s ",
               protD.protoName, sjOptIndex, oD.actual_opts_len, oD.getAvailableOptLen(),
               isGoalAchieved() ? "ACHIEVED" : "NOT ACHIEVED");

    return true;
}

bool HDRoptions::injectRandomOpts(bool corrupt, bool strip_previous)
{
    LOG_PACKET("*1 %s rand opts: actual_opt_len(%u) (avail %u) goal %s",
               protD.protoName, oD.actual_opts_len, oD.getAvailableOptLen(),
               corruptRequest ? "CORRUPT" : "NOT CORRUPT");

    if (prepareInjection(corrupt, strip_previous))
        randomInjector();

    if (!isGoalAchieved())
        return false;

    completeInjection();

    LOG_PACKET("*2 %s rand opts: actual_opt_len(%u) (avail %u) goal %s ",
               protD.protoName, oD.actual_opts_len, oD.getAvailableOptLen(),
               isGoalAchieved() ? "ACHIEVED" : "NOT ACHIEVED");

    return true;
}

/* off-topic naming base rule: 
 *
 * sjOptIndex is the uint8_t name of the index, defined in hardcodedDefines.h
 *            sometime, will be shortened with "sjI"
 * optValue is the uint8_t name used for the binary value copyed in the optHdr
 */
bool HDRoptions::removeOption(uint8_t sjOptIndex)
{

    /* this check need to be done only on external public functions */
    if (sjOptIndex < protD.firstOptIndex || sjOptIndex > protD.lastOptIndex)
        RUNTIME_EXCEPTION("invalid use of optcode index: %u");

    /* if an option is request to be deleted, we need to check if it exists! */
    if (optTrack[sjOptIndex].size() == 0)
        return false;

    for (vector<option_occurrence>::iterator it = optTrack[sjOptIndex].begin(); it != optTrack[sjOptIndex].end(); it = optTrack[sjOptIndex].erase(it))
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

    char fname[MEDIUMBUF];

    mkdir(HDR_PREFIX, 0770);
    snprintf(fname, MEDIUMBUF, "%s%s-%s", HDR_PREFIX, inet_ntoa(*((struct in_addr *) &(pkt.ip->daddr))), protD.protoName);

    FILE *HDRoLog = fopen(fname, "a+");
    if (HDRoLog == NULL)
        RUNTIME_EXCEPTION("unable to open %s:%s", fopen, strerror(errno));

    fprintf(HDRoLog, "RD %u%u SAPFR{%u%u%u%u%u}\tp#%u id%u\t",
            corruptRequest, corruptDone,
            pkt.tcp->syn, pkt.tcp->ack, pkt.tcp->psh, pkt.tcp->fin, pkt.tcp->rst,
            pkt.SjPacketId, ntohs(pkt.ip->id)
            );

    for (uint8_t i = protD.firstOptIndex; i <= protD.lastOptIndex; ++i)
    {
        if (optTrack[i].size() == false)
        {
            fprintf(HDRoLog, " ~%u", i);
        }
        else
        {
            IPTCPopt *yep = (*opt_pool)[i];
            fprintf(HDRoLog, " %s", yep->sjOptName);

            for (vector<option_occurrence>::iterator it = optTrack[i].begin(); it != optTrack[i].end(); ++it)
                fprintf(HDRoLog, ":%u(%u)", it->off, it->len);
        }
    }
    fprintf(HDRoLog, "\n");

    fclose(HDRoLog);
#endif
}
