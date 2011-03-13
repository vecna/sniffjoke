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

#include "HDRoptions.h"
#include "Utils.h"

/*
 * Now start the method indexed by optMap. The only ASSURED FACTS:
 * 1) the actual_opts_len is updated by the HDRoptions method that call
 *    the function
 * 2) the random length will be checked by getBestRandsize().
 */

uint8_t HDRoptions::m_IPOPT_NOOP()
{
    if (available_opts_len < IPOPT_NOOP_SIZE)
        return 0;

    const uint8_t index = actual_opts_len;

    optshdr[index] = IPOPT_NOOP;

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s avail %d",
               "SJ_IPOPT_NOOP", index, IPOPT_NOOP_SIZE,
               optTrack[SJ_IPOPT_NOOP].size() ? "true" : "false",
               available_opts_len - IPOPT_NOOP_SIZE
               );

    registerOptOccurrence(SJ_IPOPT_NOOP, index, IPOPT_NOOP_SIZE);

    return IPOPT_NOOP_SIZE;
}

uint8_t HDRoptions::m_IPOPT_TIMESTAMP()
{
    /*
     * This option it's based on analysis of the linux kernel. (2.6.36)
     *
     * Extract from: net/ipv4/ip_options.c
     *
     *   if (optptr[2] < 5) 
     *       pp_ptr = optptr + 2;
     *       goto error;
     *   
     *
     *   if (optptr[2] <= optlen) 
     *       __be32 *timeptr = NULL;
     *       if (optptr[2]+3 > optptr[1]) 
     *           pp_ptr = optptr + 2;
     *           goto error;
     *
     *       [...]
     *
     *   so here have two conditions we can disattend;
     *   It's possible to create a unique hack that
     *   due tu random() exploit one or the other.
     */

    const uint8_t size_timestamp = getBestRandsize(4, 1, 9, 4);
    const uint8_t timestamps = (size_timestamp - 4) / 4;
    const uint8_t index = actual_opts_len;

    /*
     * it has been tested that some networks (Fastweb) do silently filter packets
     * with this option set for security reasons.
     * so at the time we can't use this as a good for !corrupt packets.
     *
     * some interesting informations regarding this recomendations can also be found at:
     * http://tools.ietf.org/html/draft-gont-opsec-ip-options-filtering-00
     * http://yurisk.info/2010/01/23/ip-options-are-evil
     * http://tinyurl.com/63gs5ce (Juniper configuration)
     * http://technet.microsoft.com/en-us/library/cc302652.aspx
     * microsoft isa as contromisure for CAN-2005-0048 seems to block by default:
     * - Record Route (7)
     * - Time Stamp (68)
     * - Loose Source Route (131)
     * - Strict Source Route (137)
     *
     * the same can be found on CISCO and Juniper (http://www.cisco.com/en/US/docs/ios/12_3t/12_3t4/feature/guide/gtipofil.html)
     *
     * this is a great news for us, and in future we will have to test if a good
     * options could be used to make the network drops it.
     */

    /* getBestRandom return 0 if there is not enought space */
    if (!size_timestamp)
        return 0;

    optshdr[index] = IPOPT_TIMESTAMP;
    optshdr[index + 1] = size_timestamp;

    if (corruptNow)
    {
        /*
         * FIXME: integrating ttl knowledge we can select a precise expiring hop;
         * timestamp range is 1:9;
         * overflow range is of 0:15;
         * so we have (covered_hops = 9 + 15) different possibilities.
         * so we can cover destinations between 1 and 24 hops.
         */
        optshdr[index + 2] = size_timestamp + 1; /* full */
        optshdr[index + 3] = (IPOPT_TS_TSONLY | (15 << 4)); /* next will overflow */
        memset_random(&optshdr[index + 4], timestamps * 4);

        corruptDone = true;
    }
    else
    {
        optshdr[index + 2] = 5; /* empty */
        optshdr[index + 3] = IPOPT_TS_TSONLY;

        /* by rfc preallocated options memory must be 0 */
        memset(&optshdr[index + 4], 0, timestamps * 4);
    }

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s (avail %u)",
               "SJ_IPOPT_TIMESTAMP", index, size_timestamp,
               optTrack[SJ_IPOPT_TIMESTAMP].size() ? "true" : "false",
               available_opts_len, size_timestamp
               );

    registerOptOccurrence(SJ_IPOPT_TIMESTAMP, index, size_timestamp);

    return size_timestamp;
}

uint8_t HDRoptions::m_IPOPT_LSRR()
{
    /* http://tools.ietf.org/html/rfc1812
     *
     * "A router MUST NOT originate a datagram containing multiple
     * source route options.  What a router should do if asked to
     * forward a packet containing multiple source route options is
     * described in Section [5.2.4.1]."
     *
     * From [5.2.4.1]:
     * "It is an error for more than one source route option to appear in a
     * datagram.  If it receives such a datagram, it SHOULD discard the
     * packet and reply with an ICMP Parameter Problem message whose pointer
     * points at the beginning of the second source route option.
     *
     * Extract from: net/ipv4/ip_options.c
     *
     *    case IPOPT_SSRR:
     *    case IPOPT_LSRR:
     *
     *        [...]
     *
     *         / * NB: cf RFC-1812 5.2.4.1 * /
     *         if (opt->srr) {
     *                pp_ptr = optptr;
     *                goto error;
     *         }
     *
     *  so to corrupt we need to inject this option twice.
     *
     *  DOUBTS:
     *    - 1) the packet will be discarded at the first router that correctly implements the rfc.
     *         if all does this this corruption is useles :(
     *    - 2) the filled address are random, so the packet will quite surely dropped at first hop.
     *         or sent onto a random path so probably will not reach the sniffer to.
     *         (useful only dealing with a near sniffer)
     *
     *  using SSRR is also possibile but using with withe packet will be surely trashed by the
     *  first router.
     */

    const uint8_t size_lsrr = getBestRandsize(3, 1, 4, 4);
    const uint8_t index = actual_opts_len;

    /* getBestRandom return 0 if there is not enought space */
    if (!size_lsrr)
        return 0;

    optshdr[index] = IPOPT_LSRR;
    optshdr[index + 1] = size_lsrr;
    optshdr[index + 2] = 4;
    memset_random(&optshdr[index + 3], (size_lsrr - 3));

    corruptDone = true;

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s (avail %u)",
               "SJ_IPOPT_LSRR", index, size_lsrr,
               optTrack[SJ_IPOPT_LSRR].size() ? "true" : "false",
               available_opts_len - size_lsrr
               );

    registerOptOccurrence(SJ_IPOPT_LSRR, index, size_lsrr);

    return size_lsrr;
}

uint8_t HDRoptions::m_IPOPT_RR()
{
    /*
     * This option it's based on analysis of the linux kernel. (2.6.36)
     *
     * Extract from: net/ipv4/ip_options.c
     *
     *   if (optptr[2] < 4)
     *       pp_ptr = optptr + 2;
     *       goto error;
     *
     *   if (optptr[2] <= optlen)
     *       if (optptr[2]+3 > optlen)
     *           pp_ptr = optptr + 2;
     *           goto error;
     *
     *       [...]
     *
     *   so here have two conditions we can disattend;
     *   It's possible to create a unique hack that
     *   due to random() exploits the first or the latter.
     */

    const uint8_t size_rr = getBestRandsize(3, 1, 4, 4);
    const uint8_t index = actual_opts_len;

    /* getBestRandom return 0 if there is not enought space */
    if (!size_rr)
        return 0;

    optshdr[index] = IPOPT_RR;
    optshdr[index + 1] = size_rr;
    optshdr[index + 2] = size_rr + 1; /* full */

    memset_random(&(optshdr)[index + 3], (size_rr - 3));

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s (avail %u)",
               "SJ_IPOPT_RR", index, size_rr,
               optTrack[SJ_IPOPT_RR].size() ? "true" : "false",
               available_opts_len - size_rr
               );

    registerOptOccurrence(SJ_IPOPT_RR, index, size_rr);

    return size_rr;
}

uint8_t HDRoptions::m_IPOPT_RA()
{
#define IPOPT_RA_SIZE 4

    /*
     * by literature it's not clear if this option could
     * corrupt the packet.
     * studing it we have encontered some icmp errors
     * probably related to repeatitions of the option.
     * so we avoid it.
     */
    const uint8_t index = actual_opts_len;

    if (available_opts_len < IPOPT_RA_SIZE)
        return 0;

    optshdr[index] = IPOPT_RA;
    optshdr[index + 1] = IPOPT_RA_SIZE;

    /*
     * the value of the option by rfc 2113 means:
     *   0: Router shall examine packet
     *   1-65535: Reserved
     *
     * the kernel linux does handle only the 0 value.
     * we set this random to see what will happen =)
     */
    memset_random(&optshdr[index + 2], 2);

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s (avail %u)",
               "SJ_IPOPT_RA", index, IPOPT_RA_SIZE,
               optTrack[SJ_IPOPT_RA].size() ? "true" : "false",
               available_opts_len - IPOPT_RA_SIZE
               );

    registerOptOccurrence(SJ_IPOPT_RA, index, IPOPT_RA_SIZE);

    return IPOPT_RA_SIZE;
}

uint8_t HDRoptions::m_IPOPT_CIPSO()
{
    /*
     * http://www.faqs.org/rfcs/rfc2828.html
     *
     * This option it's based on analysis of the linux kernel. (2.6.36)
     *
     * Extract from: net/ipv4/ip_options.c
     *
     *   case IPOPT_CIPSO:
     *       if ((!skb && !capable(CAP_NET_RAW)) || opt->cipso)
     *           pp_ptr = optptr;
     *           goto error;
     *       opt->cipso = optptr - iph;
     *       if (cipso_v4_validate(skb, &optptr))
     *          pp_ptr = optptr;
     *          goto error;
     *       break;
     *
     *   so here have two conditions we can disattend;
     *     - The CIPSO option can be not setted on the socket
     *     - also if CIPSO option is setted the random data would
     *       lead the packet to be discarded.
     */

    const uint8_t index = actual_opts_len;

    /* this option always corrupts the packet */

    if (available_opts_len < IPOPT_CIPSO_SIZE)
        return 0;

    optshdr[index] = IPOPT_CIPSO;
    optshdr[index + 1] = IPOPT_CIPSO_SIZE;
    memset_random(&optshdr[index + 2], 8);

    corruptDone = true;

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s (avail %u)",
               "SJ_IPOPT_CIPSO", index, IPOPT_CIPSO_SIZE,
               optTrack[SJ_IPOPT_CIPSO].size() ? "true" : "false",
               available_opts_len - IPOPT_CIPSO_SIZE
               );

    registerOptOccurrence(SJ_IPOPT_CIPSO, index, IPOPT_CIPSO_SIZE);

    return IPOPT_CIPSO_SIZE;
}

uint8_t HDRoptions::m_IPOPT_SEC()
{
    /*
     * This option it's based on analysis of the linux kernel. (2.6.36)
     *
     * Extract from: net/ipv4/ip_options.c
     *
     *   case IPOPT_SEC:
     *   case IPOPT_SID:
     *   default:
     *       if (!skb && !capable(CAP_NET_RAW)) {
     *           pp_ptr = optptr;
     *           goto error;
     *       }
     *
     * Sidenote:
     *   It's interesting also the default switch case,
     *   but not used in hacks at the moment
     */

#define IPOPT_SEC_SIZE 11

    /*
     * this option always corrupts the packet random data value packet
     */

    const uint8_t index = actual_opts_len;

    if (available_opts_len < IPOPT_SEC_SIZE)
        return 0;

    /* TODO - cohorent data for security OPT */
    /* http://www.faqs.org/rfcs/rfc791.html "Security" */
    optshdr[index] = IPOPT_SEC;
    optshdr[index + 1] = IPOPT_SEC_SIZE;
    memset_random(&optshdr[index + 2], 9);

    corruptDone = true;

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s, (avail %u)",
               "SJ_IPOPT_SEC", index, IPOPT_SEC_SIZE,
               optTrack[SJ_IPOPT_SEC].size() ? "true" : "false",
               available_opts_len - IPOPT_SEC_SIZE
               );

    registerOptOccurrence(SJ_IPOPT_SEC, index, IPOPT_SEC_SIZE);

    return IPOPT_SEC_SIZE;
}

uint8_t HDRoptions::m_IPOPT_SID()
{
    /* this option corrupts the packet if repeated. */

    const uint8_t index = actual_opts_len;

    if (available_opts_len < IPOPT_SID_SIZE)
        return 0;

    optshdr[index] = IPOPT_SID;
    optshdr[index + 1] = IPOPT_SID_SIZE;
    memset_random(&optshdr[index + 2], 2);

    if (optTrack[SJ_IPOPT_SID].size())
        corruptDone = true;

    if (corruptRequest && !corruptDone)
        nextPlannedInj = (!nextPlannedInj) ? &HDRoptions::m_IPOPT_SID : NULL;

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s (avail %u)",
               "SJ_IPOPT_SID", index, IPOPT_SID_SIZE,
               optTrack[SJ_IPOPT_SID].size() ? "true" : "false",
               available_opts_len - IPOPT_SID_SIZE
               );

    registerOptOccurrence(SJ_IPOPT_SID, index, IPOPT_SID_SIZE);

    return IPOPT_SID_SIZE;
}

/*
 * TCP OPTIONS
 */
uint8_t HDRoptions::m_TCPOPT_PAWSCORRUPT()
{
#define TCPOPT_TIMESTAMP_SIZE 10

    const uint8_t index = actual_opts_len;

    if (available_opts_len < TCPOPT_TIMESTAMP_SIZE)
        return 0;

    optshdr[index] = TCPOPT_TIMESTAMP;
    optshdr[index + 1] = TCPOPT_TIMESTAMP_SIZE;
    *(uint32_t *) &optshdr[index + 2] = htonl(sj_clock - 600); /* sj_clock - 10 minutes */
    memset_random(&optshdr[index + 6], 4);

    corruptDone = true;

    LOG_PACKET("** %s at the index of %u total size of %u already present: %s (avail %u)",
               "SJ_TCPOPT_PAWSCORRUPT", index, TCPOPT_TIMESTAMP_SIZE,
               optTrack[SJ_TCPOPT_PAWSCORRUPT].size() ? "true" : "false",
               available_opts_len - TCPOPT_TIMESTAMP_SIZE
               );

    registerOptOccurrence(SJ_IPOPT_TIMESTAMP, index, TCPOPT_TIMESTAMP_SIZE);

    return TCPOPT_TIMESTAMP_SIZE;
}

HDRoptions::option_mapping HDRoptions::optMap[SUPPORTED_OPTIONS] = {
    /* SJ_IPOPT_NOOP */
    { true, NOT_CORRUPT, &HDRoptions::m_IPOPT_NOOP, IPOPT_NOOP, IPPROTO_IP, "IP NOOP"},
    /* SJ_IPOPT_TIMESTAMP */
    { true, ONESHOT /* FIXME: should be BOTH */, &HDRoptions::m_IPOPT_TIMESTAMP, IPOPT_TIMESTAMP, IPPROTO_IP, "IP Timestamp"},
    /* SJ_IPOPT_LSRR */
    { true, ONESHOT, &HDRoptions::m_IPOPT_LSRR, IPOPT_LSRR, IPPROTO_IP, "Loose source routing"},
    /* SJ_IPOPT_RR */
    { true, ONESHOT, &HDRoptions::m_IPOPT_RR, IPOPT_RR, IPPROTO_IP, "Record route"},
    /* SJ_IPOPT_RA */
    { true, NOT_CORRUPT, &HDRoptions::m_IPOPT_RA, IPOPT_RA, IPPROTO_IP, "Router advertising"},
    /* SJ_IPOPT_CIPSO */
    { true, ONESHOT, &HDRoptions::m_IPOPT_CIPSO, IPOPT_CIPSO, IPPROTO_IP, "Cipso"},
    /* SJ_IPOPT_SEC */
    { true, ONESHOT, &HDRoptions::m_IPOPT_SEC, IPOPT_SEC, IPPROTO_IP, "Security"},
    /* SJ_IPOPT_SID_VALID */
    { true, TWOSHOT, &HDRoptions::m_IPOPT_SID, IPOPT_SID, IPPROTO_IP, "Session ID"},
    /* SJ_TCPOPT_PAWSCORRUPT */
    { false, ONESHOT, &HDRoptions::m_TCPOPT_PAWSCORRUPT, RFC_UNEXISTENT_CODE, IPPROTO_TCP, "TCP Timestamp corrupt PAWS"},
    /* SJ_TCPOPT_TIMESTAMP */
    { false, UNASSIGNED_VALUE, NULL, TCPOPT_TIMESTAMP, IPPROTO_TCP, "TCP Timestamp "},
    /* SJ_TCPOPT_TCP */
    { false, UNASSIGNED_VALUE, NULL, TCPOPT_MSS, IPPROTO_TCP, "TCP MSS"},
    /* SJ_TCPOPT_SACK */
    { false, UNASSIGNED_VALUE, NULL, TCPOPT_SACK, IPPROTO_TCP, "TCP SACK"}
};

/* Now start the implementation of HDRoptions member */
HDRoptions::HDRoptions(injector_t t, bool corruptRequest, uint8_t *optionStart, uint8_t protohdrlen, uint8_t target_protolen) :
type(t),
corruptRequest(corruptRequest),
corruptDone(false),
nextPlannedInj(NULL)
{
    /* initialize the option tracking usage to 0 */
    memset((void *) optTrack, 0x00, sizeof (optTrack));

    switch (type)
    {
    case IPOPTS_INJECTOR:

        actual_opts_len = protohdrlen - sizeof (struct iphdr);
        target_opts_len = target_protolen - sizeof (struct iphdr);
        optshdr.resize(target_opts_len, IPOPT_EOL);
        memcpy((void *) &optshdr[0], optionStart, actual_opts_len);

        if (!checkupIPopt())
            throw exception();

        break;

    case TCPOPTS_INJECTOR:

        actual_opts_len = protohdrlen - sizeof (struct tcphdr);
        target_opts_len = target_protolen - sizeof (struct tcphdr);
        optshdr.resize(target_opts_len, TCPOPT_EOL);
        memcpy((void *) &optshdr[0], optionStart, actual_opts_len);

        if (!checkupTCPopt())
            throw exception();

        break;
    }

    available_opts_len = target_opts_len - actual_opts_len;

    LOG_DEBUG("+ loading %s for %s with goal %s total_opt_len|%u  (avail %u)",
              __func__, type == IPOPTS_INJECTOR ? "IP" : "TCP",
              corruptRequest ? "CORRUPT" : "NOT CORRUPT",
              actual_opts_len, target_opts_len, available_opts_len
              );
}

void HDRoptions::setupOption(struct option_discovery * sessionDiscovery)
{
    /* TODO */
}

/*
 *    returns true if injection is possible, false instead;
 *    in addition it registers the presence of some options.
 */
bool HDRoptions::checkupIPopt(void)
{
    for (uint8_t i = 0; i < actual_opts_len;)
    {
        uint8_t * const option = &optshdr[i];

        if (*option == IPOPT_NOOP)
        {
            i++;
            continue;
        }

        if (*option == IPOPT_END)
            break;

        uint8_t option_len = (uint8_t) optshdr[i + 1];
        if (option_len == 0 || option_len > (actual_opts_len - i))
        {
            /*
             * the packet contains invalid options
             * we avoid injection regardless of the corrupt value.
             */
            return false;
        }
        i += option_len;

        bool identified = false;
        for (uint8_t j = 0; j < SUPPORTED_OPTIONS; j++)
        {
            if (optMap[j].applyProto == IPPROTO_IP && *option == optMap[j].optValue)
            {
                identified = true;
                registerOptOccurrence(j, i, option_len);
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
            LOG_PACKET("INFO: a non trapped IP-options: %02x", *option);
        }
    }

    return true;
}

/*  returns true if injection is possible, false instead;
 *  in addition it registers the presence of some options.
 */
bool HDRoptions::checkupTCPopt(void)
{
    for (uint8_t i = 0; i < actual_opts_len;)
    {
        unsigned char* const option = &optshdr[i];

        if (*option == TCPOPT_NOP)
        {
            i++;
            continue;
        }

        if (*option == TCPOPT_EOL)
            break;

        uint8_t option_len = (uint8_t) optshdr[i + 1];
        if (option_len == 0 || option_len > (actual_opts_len - i))
        {
            /* injection regardless of the corrupt value.  */
            return false;
        }
        i += option_len;

        bool identified = false;
        for (uint8_t j = 0; j < SUPPORTED_OPTIONS; j++)
        {
            if (optMap[j].applyProto != IPPROTO_TCP && *option == optMap[j].optValue)
            {
                identified = true;
                registerOptOccurrence(j, i, option_len);
                break;
            }
        }

        if (!identified)
        {
            /* read the same analysis written into checkupIPopt for IP unknow options */
            LOG_PACKET("INFO: a non trapped TCP-options: %02x", *option);
        }
    }

    return true;
}

/* return false if the condition doesn't fit */
bool HDRoptions::checkCondition(uint8_t i)
{
    corruptNow = corruptRequest;

    /*
     * 1st global check: can we use this option ?
     * at the time a global enabled variable is used to permit selective testing
     */
    if (optMap[i].enabled == false)
        return false;

    /*
     * 2nd global check: at which state of the injection are we?
     * we avoid corrupt options if we have just corrupted the packet
     * and we also alter the probability for the first injection
     * in favour of good injection.
     */
    if (corruptNow && (corruptDone || ((actual_opts_len < 4) && RANDOMPERCENT(40))))
        corruptNow = false;

    if (corruptNow)
    {
        /* if we have decided to corrupt we must avoid only NOT_CORRUPT options */
        if (optMap[i].corruptionType != NOT_CORRUPT)
            return true;
    }
    else
    {
        /* if we have decided to no corrupt we must avoid ONESHOT and repeated options */
        if ((optMap[i].corruptionType != ONESHOT) && !optTrack[i].size())
        {
            nextPlannedInj = NULL;
            return true;
        }
    }

    return false;
}

/* this is the utility function used by the single option adder to calculate the best fit size for an option */
uint8_t HDRoptions::getBestRandsize(uint8_t fixedLen, uint8_t minRblks, uint8_t maxRblks, uint8_t blockSize)
{
    uint8_t minComputed = fixedLen + (minRblks * blockSize);
    uint8_t maxComputed = fixedLen + (maxRblks * blockSize);

    if (available_opts_len == minComputed || available_opts_len == maxComputed)
        return available_opts_len;

    if (available_opts_len < minComputed)
        return 0;

    if (available_opts_len > maxComputed)
    {
        return (((random() % (maxRblks - minRblks + 1)) + minRblks) * blockSize) +fixedLen;
    }
    else /* should try the best filling of memory and the NOP fill after */
    {
        uint8_t blockNumber = (available_opts_len - fixedLen) / blockSize;
        return (blockNumber * blockSize) +fixedLen;
    }
}

void HDRoptions::registerOptOccurrence(uint8_t opt, uint8_t off, uint8_t len)
{
    struct option_occurrence occ;
    occ.off = off;
    occ.len = len;
    optTrack[opt].push_back(occ);
}

uint32_t HDRoptions::randomInjector()
{
    uint32_t randomStart, lastOpt, firstOpt, tries;

    if (type == IPOPTS_INJECTOR)
    {
        randomStart = GET_RANDOM_IPOPT;
        lastOpt = LAST_IPOPT_NAME;
        firstOpt = 0;
        tries = LAST_IPOPT_NAME + 1;
    }
    else
    {
        randomStart = GET_RANDOM_TCPOPT;
        lastOpt = LAST_TCPOPT_NAME;
        firstOpt = LAST_IPOPT_NAME + 1;
        tries = LAST_TCPOPT_NAME - LAST_IPOPT_NAME + 1;
    }

    LOG_PACKET("*1 %s option: total_opt_len|%u target_opt_len|%u (avail %u)",
               type == IPOPTS_INJECTOR ? "IP" : "TCP",
               actual_opts_len, target_opts_len, available_opts_len);

    uint32_t i = randomStart;
    while (available_opts_len && --tries)
    {
        /* this loop is intended to be partially random without be too much intensive */
        if (i > lastOpt)
            i = firstOpt;
        else
            i++;

        /* check: this->corruptRequest, this->corruptDone and nextPlannedInj */
        if (!checkCondition(i))
            continue;

        actual_opts_len += (this->*(optMap[i].optApply))();
        available_opts_len = target_opts_len - actual_opts_len;

        /* the planned option is used when a TWOSHOT define the second shot */
        if (nextPlannedInj != NULL)
        {
            uint8_t ret = (this->*nextPlannedInj)();
            if (ret)
            {
                actual_opts_len += ret;
                available_opts_len = target_opts_len - actual_opts_len;
            }
            else
            {
                /* TWOSHOT FAIL: and now ?! no problem!
                 *
                 *      1) an other injection tries will follow;
                 *      2) if all the tries will fail probably a scramble downgrade will
                 *         solve the problem with no inconvenience.
                 */
            }

            nextPlannedInj = NULL;

        }

        /* this will likely never happen if the getBestRandom is used correctly */
        if (actual_opts_len > target_opts_len)
        {
            LOG_PACKET("*** EXCEPTION: %d > %d", actual_opts_len, target_opts_len);
            throw exception();
        }

    }

    LOG_PACKET("*2 %s option: total_opt_len|%u target_opt_len|%u (avail %u) goal|%s ",
               type == IPOPTS_INJECTOR ? "IP" : "TCP",
               actual_opts_len, target_opts_len, available_opts_len,
               isGoalAchieved() ? "ACHIEVED" : "NOT ACHIEVED");

    /* random Injection return the progressing growing of the option header */
    return actual_opts_len;
}

/*
 * this is used if a plugin wants to inject a specific option;
 * in this case the value corruptRequest and corruptDone are ignored
 */
bool HDRoptions::customInjector(uint8_t opt)
{
    if ((this->*(optMap[opt].optApply))())
        return true;

    else
        return false;
}

uint32_t HDRoptions::alignOpthdr(uint8_t alignN)
{

    uint8_t nopcode = (type == IPOPTS_INJECTOR) ? IPOPT_NOOP : TCPOPT_NOP;

    memset(&optshdr[actual_opts_len], nopcode, alignN);

    actual_opts_len += alignN;

    LOG_PACKET("*+ aligned to %u for %d bytes", actual_opts_len, alignN);

    return actual_opts_len;
}

void HDRoptions::copyOpthdr(uint8_t * dst)
{

    memcpy(dst, &optshdr[0], actual_opts_len);
}

bool HDRoptions::removeOption(uint8_t opt)
{
    /* if an option is request to be deleted, we need to check if it exists! */
    if (optTrack[opt].size() == false)
        return false;

    for (vector<option_occurrence>::iterator it = optTrack[opt].begin(); it != optTrack[opt].end(); it = optTrack[opt].erase(it))
    {

        vector<unsigned char>::iterator start = optshdr.begin() + it->off;
        vector<unsigned char>::iterator end = start + it->len;
        optshdr.erase(start, end);

        target_opts_len -= it->len;
        actual_opts_len -= it->len;
    }

    return true;
}

bool HDRoptions::isGoalAchieved()
{
    return corruptRequest == corruptDone;
}

