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
    /* this 'swapPtr' is required to solve:
     * warning: dereferencing type-punned pointer will break strict-aliasing rules */
    void *swapPtr;

    /* initialization of header and indexes on specific proto basis */
    switch (type)
    {
    case IPOPTS_INJECTOR:

        protD.protoName = "IP";
        protD.firstOptIndex = FIRST_IPOPT;
        protD.lastOptIndex = LAST_IPOPT;
        protD.NOP_code = IPOPT_NOOP;
        protD.EOL_code = IPOPT_END;
        protD.hdrMinLen = sizeof (struct iphdr);
        protD.optsMaxLen = MAXIPOPTIONS;

        /* protocol dependend pointer */
        protD.hdrResize = &Packet::iphdrResize;
        swapPtr = reinterpret_cast<void *>(&(pkt.ip));
        memcpy( &protD.hdrAddr, &swapPtr, sizeof(void *) );
        protD.hdrLen = (uint8_t*) &pkt.iphdrlen;

        for (uint8_t i = protD.firstOptIndex; i <= protD.lastOptIndex; ++i)
        {
            switch (i) /* Specific IP options configurations goes here */
            {
            case SJ_IPOPT_TIMESTOVERFLOW:
                (reinterpret_cast<Io_TIMESTOVERFLOW *> (opt_pool->get(i)))->setupTTLFocus(&ttlfocus);
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
        protD.EOL_code = TCPOPT_EOL;
        protD.hdrMinLen = sizeof (struct tcphdr);
        protD.optsMaxLen = MAXTCPOPTIONS;

        /* protocol dependend pointer */
        protD.hdrResize = &Packet::tcphdrResize;
        swapPtr = reinterpret_cast<void *>(&(pkt.tcp));
        memcpy( &protD.hdrAddr, &swapPtr, sizeof(void *) );
        protD.hdrLen = (uint8_t*) &pkt.tcphdrlen;

        for (uint8_t i = protD.firstOptIndex; i <= protD.lastOptIndex; ++i)
        {
            switch (i) /* Specific TCP options configurations goes here */
            {
            default:
                break;
            }
        }

        break;
    }

    /* initialization of "option Descriptor" */
    memset( &oD, 0x00, sizeof(oD) );
    oD.actual_opts_len = *protD.hdrLen - protD.hdrMinLen;

    pkt.SELFLOG("IP/TCP HDRoptions: free space %d actual protohdrlen %d mi/MA %d/%d actual len %d avail %d", 
                pkt.freespace(), *protD.hdrLen, protD.hdrMinLen, protD.optsMaxLen, 
                oD.actual_opts_len, oD.getAvailableOptLen() );

    if(oD.actual_opts_len > protD.optsMaxLen)
    {
        RUNTIME_EXCEPTION("Actual options length %d > max supported options length %d", 
                          oD.actual_opts_len, protD.optsMaxLen);
    }

    /* remind: MTU is 80 byte less than the maximum available for don't check freespace */
    oD.optshdr.resize(protD.optsMaxLen, protD.EOL_code);
    if(oD.actual_opts_len > 0)
    {
        for(uint32_t i = 0; i < *protD.hdrLen; i++)
            oD.optshdr.push_back( *(*((uint8_t **)protD.hdrAddr) + protD.hdrMinLen + i) );

        acquirePresentOptions(pkt.SjPacketId);
    }

    LOG_PACKET("? checking space of opts header: %d < %d, resizing from %d to %d", 
               oD.actual_opts_len, protD.optsMaxLen, oD.optshdr.size(), protD.optsMaxLen);
}

void HDRoptions::acquirePresentOptions(uint32_t PktID)
{
    LOG_PACKET("*0 analyzing present %sopts for packet #%u, actual opts %d", protD.protoName, PktID, oD.actual_opts_len);

    uint8_t option_len = 1;

    for (uint8_t i = 0; i < oD.actual_opts_len; i += option_len)
    {
        uint8_t * const option = &oD.optshdr[i];

        if (*option == protD.NOP_code)
        {
            option_len = 1;
            registerOptOccurrence(*option, i, option_len);
            continue;
        }

        if (*option == protD.EOL_code)
        {
            registerOptOccurrence(*option, i, 1);
            break;
        }

        option_len = (uint8_t) oD.optshdr[i + 1];
        if (option_len == 0 || option_len > (oD.actual_opts_len - i))
        {
            RUNTIME_EXCEPTION("INFO: an invalid %sopt: option|%02x option_len|%u residual|%u",
                              protD.protoName, *option, option_len, (oD.actual_opts_len - i));
        }

        registerOptOccurrence(*option, i, option_len);
    }
}

/*
 * this is a core method inside HDRoptions, it:
 * 1) check if a requested option(selected by a random or forced by a plugin) is enabled
 * 2) check if the goal is to corrupt or not, and choose the option by the counter data
 */
bool HDRoptions::evaluateInjectCoherence(uint8_t sjOptIndex)
{
    const IPTCPopt &oDesc = *(opt_pool->get(sjOptIndex));
    const uint8_t opt_occurrs = optTrack[sjOptIndex].size();

    /*
     * 1st global check: can we use this option ?
     * an option could be implemented in IPTCPoptImpl.cc but could be put
     * simply for recognize the option, without injecting them.
     */
    if (oDesc.enabled == false)
        return false;
    /*
     * 2nd global check: at which state of the injection are we?
     * we avoid corrupt options if we have just corrupted the packet
     * and we also alter the probability for the first injection
     * in favour of good injection.
     */
    switch (oDesc.availableUsage)
    {
    case NOT_CORRUPT:
        if (corruptRequest == false && opt_occurrs == 0)
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
            if (opt_occurrs <= 1)
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
 * request a selective deletion)
 */
uint8_t HDRoptions::registerOptOccurrence(uint8_t optValue, uint8_t offset, uint8_t len)
{
    for (uint8_t sjOptIndex = protD.firstOptIndex; sjOptIndex <= protD.lastOptIndex; ++sjOptIndex)
    {
        const IPTCPopt &oDesc = *(opt_pool->get(sjOptIndex));

        if (optValue == oDesc.optValue)
        {
            struct option_occurrence occ;
            occ.off = offset;
            occ.len = len;

            optTrack[sjOptIndex].push_back(occ);

            LOG_PACKET("*+ registering %s at the index of %u options length %u (actual %d avail %u)",
                       oDesc.sjOptName, offset, len, oD.actual_opts_len, oD.getAvailableOptLen() );

            return optTrack[sjOptIndex].size();
        }
    }

    /*
     * analysis: will we make a malformed and stripping an option we don't know ?
     * I belive is better to return false if the code is running here, but I prefer
     * support every IP options available in the optMap[].
     * for this reason, in the beta and < 1.0 release the previous message
     * will be used for debug & progress pourposes.
     */
    RUNTIME_EXCEPTION("INFO: a non trapped %sopt: option|%02x option_len|%u residual|%u",
                      protD.protoName, optValue, len, (oD.actual_opts_len - offset));
}

void HDRoptions::alignOpthdr(void)
{
    uint8_t alignBytes = (oD.actual_opts_len % 4) ? 4 - (oD.actual_opts_len % 4) : 0;
    if (alignBytes)
    {
        oD.actual_opts_len += alignBytes;

        LOG_PACKET("*+ aligned to %u for %u bytes (avail %u)", oD.actual_opts_len, alignBytes, oD.getAvailableOptLen());
    }
}

void HDRoptions::copyOpthdr(void)
{
    memcpy(*((uint8_t **)protD.hdrAddr) + protD.hdrMinLen, &oD.optshdr[0], oD.actual_opts_len);
}

bool HDRoptions::isGoalAchieved(void)
{
    return corruptRequest == corruptDone;
}

bool HDRoptions::prepareInjection(bool corrupt, bool strip_previous)
{
    if (strip_previous)
        stripAllOptions();

    corruptRequest = corrupt;

    return true;
}

void HDRoptions::completeHdrEdit(void)
{
    LOG_PACKET("*- complete %shdr actual %u options len", protD.protoName, oD.actual_opts_len);

    alignOpthdr();
    ((pkt).*(protD.hdrResize))(protD.hdrMinLen + oD.actual_opts_len);
    copyOpthdr();
}

void HDRoptions::injector(uint8_t sjOptIndex)
{
    IPTCPopt &oDesc = *(opt_pool->get(sjOptIndex));

    while (evaluateInjectCoherence(sjOptIndex))
    {
        const uint8_t writtedLen = oDesc.optApply(&oD);

        /* when this happen, is because no space is available, so 
         * break; to avoid useless time consuming loop */
        if (writtedLen == 0) 
            break;

        const uint8_t opt_occurrs = registerOptOccurrence(oDesc.optValue, oD.actual_opts_len, writtedLen);

        oD.actual_opts_len += writtedLen;

        if (oDesc.availableUsage == ONESHOT && opt_occurrs == 1)
            corruptDone = true;

        else if (oDesc.availableUsage == TWOSHOT && opt_occurrs == 2)
            corruptDone = true;
    }
}

void HDRoptions::randomInjector(void)
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
        RUNTIME_EXCEPTION("invalid use of optcode index: %u", sjOptIndex);

    LOG_PACKET("*1 injecting single %sopt [%u]: actual_opt_len(%u) (avail %u) goal %s",
               protD.protoName, sjOptIndex, oD.actual_opts_len, oD.getAvailableOptLen(),
               corruptRequest ? "CORRUPT" : "NOT CORRUPT");

    if (prepareInjection(corrupt, strip_previous))
        injector(sjOptIndex);

    if (!isGoalAchieved())
    {
        LOG_PACKET("*! injecting single %sopt [%u]: actual_opt_len(%u) (avail %u) goal NOT ACHIEVED = discarged options ",
                   protD.protoName, sjOptIndex, oD.actual_opts_len, oD.getAvailableOptLen());

        return false;
    }

    completeHdrEdit();

    LOG_PACKET("*2 injecting single %sopt [%u]: actual_opt_len(%u) (avail %u) goal %s ",
               protD.protoName, sjOptIndex, oD.actual_opts_len, oD.getAvailableOptLen(),
               isGoalAchieved() ? "ACHIEVED" : "NOT ACHIEVED");

    return true;
}

bool HDRoptions::injectRandomOpts(bool corrupt, bool strip_previous)
{
    LOG_PACKET("*1 injecting random %sopts: actual_opt_len(%u) (avail %u) goal %s",
               protD.protoName, oD.actual_opts_len, oD.getAvailableOptLen(),
               corruptRequest ? "CORRUPT" : "NOT CORRUPT");

    if (prepareInjection(corrupt, strip_previous))
        randomInjector();

    if (!isGoalAchieved()) 
    {
        LOG_PACKET("*! injecting random %sopts: actual_opt_len(%u) (avail %u) goal NOT ACHIEVED = discarged options",
                   protD.protoName, oD.actual_opts_len, oD.getAvailableOptLen());

        return false;
    }

    completeHdrEdit();

    LOG_PACKET("*2 injecting random %sopts: actual_opt_len(%u) (avail %u) goal %s ",
               protD.protoName, oD.actual_opts_len, oD.getAvailableOptLen(),
               isGoalAchieved() ? "ACHIEVED" : "NOT ACHIEVED");

    return true;
}

bool HDRoptions::stripOption(uint8_t sjOptIndex)
{
    bool found = false;

    /* this check need to be done only on external public functions */
    if (sjOptIndex < protD.firstOptIndex || sjOptIndex > protD.lastOptIndex)
        RUNTIME_EXCEPTION("invalid use of optcode index: %u", sjOptIndex);

    IPTCPopt &oDesc = *(opt_pool->get(sjOptIndex));

    for (vector<option_occurrence>::iterator it = optTrack[sjOptIndex].begin(); it != optTrack[sjOptIndex].end(); it++)
    {
        vector<unsigned char>::iterator start = oD.optshdr.begin() + it->off;
        vector<unsigned char>::iterator end = start + it->len;
        oD.optshdr.erase(start, end);

        oD.actual_opts_len -= it->len;

        uint16_t maxOptSpace = pkt.freespace() > protD.optsMaxLen ? protD.optsMaxLen : ((pkt.freespace() >> 4) << 4);
        oD.optshdr.resize(maxOptSpace, protD.EOL_code);

        LOG_PACKET("*- stripping single %sopt %s for %u bytes (avail %u)", 
                  protD.protoName, oDesc.sjOptName, it->len, oD.getAvailableOptLen());

        optTrack[sjOptIndex].erase(it);
        completeHdrEdit();

        found = true;
    }

    return found;
}

void HDRoptions::stripAllOptions()
{
    LOG_PACKET("*- stripping all %s options (total of used %u)", protD.protoName, oD.actual_opts_len);

    for (uint32_t sjI = protD.firstOptIndex; sjI <= protD.lastOptIndex; sjI++)
    {
        while(optTrack[sjI].size())
        {
            optTrack[sjI].pop_back();
        }
    }

    uint16_t maxOptSpace = pkt.freespace() > protD.optsMaxLen ? protD.optsMaxLen : ((pkt.freespace() >> 4) << 4);
    oD.optshdr.resize(maxOptSpace, protD.EOL_code);
    oD.actual_opts_len = 0;
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
        RUNTIME_EXCEPTION("unable to open %s:%s", fname, strerror(errno));

    fprintf(HDRoLog, "RD %u%u SAPFR{%u%u%u%u%u}\tpktID %u\tip.id %u\t optL %d",
            corruptRequest, corruptDone,
            pkt.tcp->syn, pkt.tcp->ack, pkt.tcp->psh, pkt.tcp->fin, pkt.tcp->rst,
            pkt.SjPacketId, ntohs(pkt.ip->id), oD.actual_opts_len );

    for (uint8_t i = protD.firstOptIndex; i <= protD.lastOptIndex; ++i)
    {
        if (optTrack[i].size() == false)
        {
            fprintf(HDRoLog, " ~%u", i);
        }
        else
        {
            IPTCPopt *yep = opt_pool->get(i);
            fprintf(HDRoLog, " %s", yep->sjOptName);

            for (vector<option_occurrence>::iterator it = optTrack[i].begin(); it != optTrack[i].end(); ++it)
                fprintf(HDRoLog, ":%u(%u)", it->off, it->len);
        }
    }
    fprintf(HDRoLog, "\n");

    fclose(HDRoLog);
#endif
}
