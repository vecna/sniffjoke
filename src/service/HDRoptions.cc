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
 * seems that some weird ipoptions will cause a packet to be discarged
 * on the route, without ever reach the server. we aim to create 
 * ipoptions accepted by the router, and discarded from the remote host.
 */

#include "HDRoptions.h"
#include "Utils.h"

/* this is the static utility function used by the single option adder */
static uint8_t 
getBestRandsize(uint8_t fixedLen, uint8_t minRblks, uint8_t maxRblks, uint8_t blockSize, uint8_t availableLen)
{
    uint8_t minComputed = fixedLen + (minRblks * blockSize);
    uint8_t maxComputed = fixedLen + (maxRblks * blockSize);

    if( availableLen == minComputed || availableLen == maxComputed )
        return availableLen;

    if( minComputed < availableLen)
        return 0;

    if( availableLen > maxComputed)
    {
        return ((( random() % (maxRblks - minRblks + 1) ) + minRblks ) * blockSize ) + fixedLen;
    }
    else /* should try the best filling of memory and the NOP fill after */
    {
        uint8_t blockNumber = (availableLen - fixedLen) / blockSize;
        return (blockNumber * blockSize) + fixedLen;
    }
}

/*
 * Now start the static method indexed by optMap. The only ASSURED FACTS:
 * 1) "co" is the Calling Object, and the method work in them
 * 2) the "co" contains a vector of byte (optshdr) long target_opts_len byte
 * 3) the co->actual_opts_len is updated by the HDRoptions method that call
 *    the static function
 * 4) the random length will be checked by getBestRandsize() here before.
 */

static uint8_t m_IPOPT_NOOP(HDRoptions *co)
{
    if(co->available_opts_len < 1)
        return 0;

    co->optshdr[co->actual_opts_len] = IPOPT_NOOP;

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %d",
        "SJ_IPOPT_NOOP", co->actual_opts_len, 1, 
        co->optTrack[SJ_IPOPT_NOOP].isPresent ? "true" : "false", co->available_opts_len
    );

    co->optTrack[SJ_IPOPT_NOOP].isPresent = true;
    co->optTrack[SJ_IPOPT_NOOP].optlen = 1;
    co->optTrack[SJ_IPOPT_NOOP].offset = &co->optshdr[co->actual_opts_len];

    return 1;
}

static uint8_t m_IPOPT_TIMESTAMP(HDRoptions *co)
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

    const uint8_t size_timestamp = getBestRandsize(4, 1, 4, 8, co->available_opts_len);
    const uint8_t timestamps = (size_timestamp - 4) / 8;
    const uint8_t index = co->actual_opts_len;

    /* this is a corrupt only option - AT THE MOMENT */

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

    /* getBestRandom return 0 if there are not enought space */
    if (!size_timestamp)
        return 0;

    co->optshdr[index] = IPOPT_TIMESTAMP;
    co->optshdr[index + 1] = size_timestamp;
    co->optshdr[index + 2] = size_timestamp + 1; /* full */

    if (RANDOMPERCENT(50))
        co->optshdr[index + 3] = IPOPT_TS_TSONLY;
    else
        co->optshdr[index + 3] = IPOPT_TS_TSANDADDR;

    if (RANDOMPERCENT(50))
    {
        /* reference code : if (optptr[2] < 5) */
        co->optshdr[index + 2] = random() % 5;
    }
    else
    {
        /* reference code : if (optptr[2] <= optlen) 
                      and : if (optptr[2]+3 > optptr[1])  */
        co->optshdr[index + 2] = co->optshdr[index + 1] - (1 + random() % 2);
    }

    co->optshdr[index + 3] = (uint8_t) random();
    memset_random(&co->optshdr[index + 4], timestamps * 8);

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %u",
        "SJ_IPOPT_TIMESTAMP", index, size_timestamp, 
        co->optTrack[SJ_IPOPT_TIMESTAMP].isPresent ? "true" : "false", co->available_opts_len
    );

    co->optTrack[SJ_IPOPT_TIMESTAMP].isPresent = true;
    co->optTrack[SJ_IPOPT_TIMESTAMP].optlen = size_timestamp;
    co->optTrack[SJ_IPOPT_TIMESTAMP].offset = &co->optshdr[index];

    co->corruptDone = true;

    return size_timestamp;
}

static uint8_t m_IPOPT_LSRR(HDRoptions *co)
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
     * This option it's based on analysis of the linux kernel. (2.6.36)
     *
     * Extract from: net/ipv4/ip_options.c
     *
     *    case IPOPT_SSRR:
     *    case IPOPT_LSRR:
     *
     *        [...]
     *
     *        if (optlen < 3) {
     *                pp_ptr = optptr + 1;
     *                goto error;
     *         }
     *         if (optptr[2] < 4) {
     *                pp_ptr = optptr + 2;
     *                goto error;
     *         }
     *         / * NB: cf RFC-1812 5.2.4.1 * /
     *         if (opt->srr) {
     *                pp_ptr = optptr;
     *                goto error;
     *         }
     *         if (!skb) {
     *                if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
     *                        pp_ptr = optptr + 1;
     *                        goto error;
     *                }
     *                memcpy(&opt->faddr, &optptr[3], 4);
     *                if (optlen > 7)
     *                        memmove(&optptr[3], &optptr[7], optlen-7);
     *         }
     *         opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
     *         opt->srr = optptr - iph;
     *         break;
     *
     *  we want to send LSRR option 2 times.
     *  so we have to respect all checks that lead to an error.
     *  using SSRR is also possibile but the packet will be trashed by the
     *  first router.
     */

    const uint8_t size_lsrr = getBestRandsize(3, 2, 4, 4, co->available_opts_len);
    const uint8_t index = co->actual_opts_len;

    /* getBestRandsize return 0 when the space is too small */
    if (!size_lsrr)
    {
        if(co->nextPlannedInj != NULL)
        {
            /* pain in the ass: there are not space for make
             * the double corruption, we need to opt in a dirty way */
            *(co->optTrack[SJ_IPOPT_LSRR].offset + 1) = 0xff;

            co->corruptDone = true;
            co->nextPlannedInj = NULL;
        }
        return 0;
    }

    co->optshdr[index] = IPOPT_LSRR;
    co->optshdr[index + 1] = size_lsrr;
    co->optshdr[index + 2] = 4;
    memset_random(&co->optshdr[index + 3], (size_lsrr - 3) );

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %u",
        "SJ_IPOPT_LSRR", index, size_lsrr, 
        co->optTrack[SJ_IPOPT_LSRR].isPresent ? "true" : "false", co->available_opts_len
    );

    /* in the TWO STEP injecton only the first is tracked */
    if(!co->optTrack[SJ_IPOPT_LSRR].isPresent)
    {
        co->optTrack[SJ_IPOPT_LSRR].isPresent = true;
        co->optTrack[SJ_IPOPT_LSRR].optlen = size_lsrr;
        co->optTrack[SJ_IPOPT_LSRR].offset = &co->optshdr[index];
    }
    else
    {
        co->optTrack[SJ_IPOPT_LSRR].optlen += size_lsrr;
        co->corruptDone = true;
    }

    co->nextPlannedInj = (!co->nextPlannedInj) ? m_IPOPT_LSRR : NULL;

    return size_lsrr;
}

static uint8_t m_IPOPT_RR(HDRoptions *co)
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

    const uint8_t size_rr = getBestRandsize(3, 1, 4, 4, co->available_opts_len);
    const uint8_t index = co->actual_opts_len;

    /* getBestRandsize return 0 when the space is too small */
    if (!size_rr)
        return 0;

    co->optshdr[index] = IPOPT_RR;
    co->optshdr[index + 1] = size_rr;

    /* good option */

    /*
     * the pointer into the route data indicates the byte which begins the next area
     * to store a route address. The pointer is relative to this option.
     * if the pointer is greater than the length, the recorded route data area is full.
     */
    co->optshdr[index + 2] = size_rr + 1;

#if 0
    /* evil option - I've only the doubt that a packet corrupted in these ways will
     *               be dropped from the routers instead of the remote host */
    if (RANDOMPERCENT(50))
    {
        /* reference code : if (optptr[2] < 5) */
        optptr[2] = random() % 4;
    }
    else
    {
        /* reference code : if (optptr[2] <= optlen) 
                      and : if (optptr[2]+3 > optptr[1]) */
        optptr[2] = optptr[1] - (1 + random() % 2);
    }
#endif

    memset_random(&(co->optshdr)[index + 3], (size_rr - 3) );

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %u",
        "SJ_IPOPT_RR", index, size_rr, 
        co->optTrack[SJ_IPOPT_RR].isPresent ? "true" : "false", co->available_opts_len
    );

    co->optTrack[SJ_IPOPT_RR].isPresent = true;
    co->optTrack[SJ_IPOPT_RR].optlen = size_rr;
    co->optTrack[SJ_IPOPT_RR].offset = &co->optshdr[index];

    return size_rr;
}

static uint8_t m_IPOPT_RA(HDRoptions *co)
{
#define IPOPT_RA_SIZE 4

    /*
     * by literature it's not clear if this option could
     * corrupt the packet.
     * studing it we have encontered some icmp errors
     * probably related to repeatitions of the option.
     * so we avoid it.
     */
    const uint8_t index = co->actual_opts_len;

    if (co->available_opts_len < IPOPT_RA_SIZE)
        return 0;

    co->optshdr[index] = IPOPT_RA;
    co->optshdr[index + 1] = IPOPT_RA_SIZE;

    /*
     * the value of the option by rfc 2113 means:
     *   0: Router shall examine packet
     *   1-65535: Reserved
     *
     * the kernel linux does handle only the 0 value.
     * we set this random to see what will happen =)
     */
    memset_random(&co->optshdr[index + 2], 2);

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %u",
        "SJ_IPOPT_RA", index, IPOPT_RA_SIZE, 
        co->optTrack[SJ_IPOPT_RA].isPresent ? "true" : "false", co->available_opts_len
    );

    co->optTrack[SJ_IPOPT_RA].isPresent = true;
    co->optTrack[SJ_IPOPT_RA].optlen = IPOPT_RA_SIZE;
    co->optTrack[SJ_IPOPT_RA].offset = &co->optshdr[index];

    return IPOPT_RA_SIZE;
}

static uint8_t m_IPOPT_CIPSO(HDRoptions *co)
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

    const uint8_t index = co->actual_opts_len;

    /* this option always corrupts the packet */
    if (co->available_opts_len < IPOPT_CIPSO_SIZE)
        return 0;

    co->optshdr[index] = IPOPT_CIPSO;
    co->optshdr[index + 1] = IPOPT_CIPSO_SIZE;
    memset_random(&co->optshdr[index + 2], 8);

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %u",
        "SJ_IPOPT_CIPSO", index, IPOPT_CIPSO_SIZE, 
        co->optTrack[SJ_IPOPT_CIPSO].isPresent ? "true" : "false", co->available_opts_len
    );

    co->optTrack[SJ_IPOPT_CIPSO].isPresent = true;
    co->optTrack[SJ_IPOPT_CIPSO].optlen = IPOPT_CIPSO_SIZE;
    co->optTrack[SJ_IPOPT_CIPSO].offset = &co->optshdr[index];

    co->corruptDone = true;

    return IPOPT_CIPSO_SIZE;
}

static uint8_t m_IPOPT_SEC(HDRoptions *co)
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

    /* this option always corrupts the packet */
    const uint8_t index = co->actual_opts_len;

    if (co->available_opts_len < IPOPT_SEC_SIZE)
        return 0;

    /* TODO - cohorent data for security OPT */
    /* http://www.faqs.org/rfcs/rfc791.html "Security" */
    co->optshdr[index] = IPOPT_SEC;
    co->optshdr[index + 1] = IPOPT_SEC_SIZE;
    memset_random(&co->optshdr[index + 2], 9);

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s, avail %u",
        "SJ_IPOPT_SEC", index, IPOPT_SEC_SIZE, 
        co->optTrack[SJ_IPOPT_SEC].isPresent ? "true" : "false", co->available_opts_len
    );

    co->optTrack[SJ_IPOPT_SEC].isPresent = true;
    co->optTrack[SJ_IPOPT_SEC].optlen = IPOPT_SEC_SIZE;
    co->optTrack[SJ_IPOPT_SEC].offset = &co->optshdr[index];

    co->corruptDone = true;

    return IPOPT_SEC_SIZE;
}

/* rivedere - il doppio uso esiste nel senso che non deve essere good e corrupt, deve essere
 * TWOSHOT che implicitamente se èsato una volta sola è buona! */
static uint8_t m_IPOPT_SID(HDRoptions *co)
{
    /* this option does corrupt the packet if repeated. */
    const uint8_t index = co->actual_opts_len;

    if (co->available_opts_len < IPOPT_SID_SIZE)
    {
        if(co->nextPlannedInj != NULL)
        {
            /* pain in the ass: there are not space for make
             * the double corruption, we need to opt in a dirty way */
            *(co->optTrack[SJ_IPOPT_SID].offset + 1) = 0xff;
            co->corruptDone = true;

            co->nextPlannedInj = NULL;
        }
        return 0;
    }

    co->optshdr[index] = IPOPT_SID;
    co->optshdr[index + 1] = IPOPT_SID_SIZE;
    memset_random(&co->optshdr[index + 2], 2);

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %u",
        "SJ_IPOPT_SID", index, IPOPT_SID_SIZE, 
        co->optTrack[SJ_IPOPT_SID].isPresent ? "true" : "false", co->available_opts_len
    );

    /* in the TWO STEP injecton only the first is tracked */
    if(!co->optTrack[SJ_IPOPT_SID].isPresent)
    {
        co->optTrack[SJ_IPOPT_SID].isPresent = true;
        co->optTrack[SJ_IPOPT_SID].optlen = IPOPT_SID_SIZE;
        co->optTrack[SJ_IPOPT_SID].offset = &co->optshdr[index];
    }
    else
    {
        co->optTrack[SJ_IPOPT_LSRR].optlen += IPOPT_SID_SIZE;
        co->corruptDone = true;
    }

    co->nextPlannedInj = (!co->nextPlannedInj) ? m_IPOPT_SID : NULL;

    return IPOPT_SID_SIZE;
}

/*
 * TCP OPTIONS 
 */
static uint8_t m_TCPOPT_PAWSCORRUPT(HDRoptions *co)
{
#define TCPOPT_TIMESTAMP_SIZE 10
    /* this option does corrupt the packet if repeated. */
    const uint8_t index = co->actual_opts_len;

    if (co->available_opts_len < TCPOPT_TIMESTAMP_SIZE)
        return 0;

    co->optshdr[index] = TCPOPT_TIMESTAMP;
    co->optshdr[index + 1] = TCPOPT_TIMESTAMP_SIZE;
    *(uint32_t *) &co->optshdr[index + 2] = htonl(sj_clock - 600); /* sj_clock - 10 minutes */
    memset_random(&co->optshdr[index + 6], 4);

    LOG_PACKET("** %s at the index of %u total size of %u: already present: %s avail %u",
        "SJ_TCPOPT_PAWSCORRUPT", index, TCPOPT_TIMESTAMP_SIZE, 
        co->optTrack[SJ_TCPOPT_PAWSCORRUPT].isPresent ? "true" : "false", co->available_opts_len
    );

    co->optTrack[SJ_TCPOPT_PAWSCORRUPT].isPresent = true;
    co->optTrack[SJ_TCPOPT_PAWSCORRUPT].optlen = TCPOPT_TIMESTAMP_SIZE;
    co->optTrack[SJ_TCPOPT_PAWSCORRUPT].offset = &co->optshdr[index];

    co->corruptDone = true;

    return TCPOPT_TIMESTAMP_SIZE;
}

/* ----------------------------------------------------------------
 * this is the struct where all IP/TCP otions need to be configured */
static struct option_mapping optMap[SUPPORTED_OPTIONS] = {
    /* SJ_IPOPT_NOOP */
    { NOT_CORRUPT, m_IPOPT_NOOP, IPOPT_NOOP, IPPROTO_IP, "IP NOOP" },
    /* SJ_IPOPT_TIMESTAMP */
    { ONESHOT, m_IPOPT_TIMESTAMP, IPOPT_TIMESTAMP, IPPROTO_IP, "IP Timestamp" },
    /* SJ_IPOPT_LSRR */
    { TWOSHOT, m_IPOPT_LSRR, IPOPT_LSRR, IPPROTO_IP, "Loose source routing" },
    /* SJ_IPOPT_RR */
    { NOT_CORRUPT, m_IPOPT_RR, IPOPT_RR, IPPROTO_IP, "Record route" },
    /* SJ_IPOPT_RA */
    { NOT_CORRUPT, m_IPOPT_RA, IPOPT_RA, IPPROTO_IP, "Router advertising" },
    /* SJ_IPOPT_CIPSO */
    { ONESHOT, m_IPOPT_CIPSO, IPOPT_CIPSO, IPPROTO_IP, "Cipso" },
    /* SJ_IPOPT_SEC */
    { ONESHOT, m_IPOPT_SEC, IPOPT_SEC, IPPROTO_IP, "Security" },
    /* SJ_IPOPT_SID_VALID */
    { TWOSHOT, m_IPOPT_SID, IPOPT_SID, IPPROTO_IP, "Session ID" },
    /* SJ_TCPOPT_PAWSCORRUPT */
    { ONESHOT, m_TCPOPT_PAWSCORRUPT, RFC_UNEXISTENT_CODE, IPPROTO_TCP, "TCP Timestamp corrupt PAWS" },
    /* SJ_TCPOPT_PAWSCORRUPT */
    { UNASSIGNED_VALUE, NULL, TCPOPT_TIMESTAMP, IPPROTO_TCP, "TCP Timestamp " },
    /* SJ_TCPOPT_PAWSCORRUPT */
    { UNASSIGNED_VALUE, NULL, TCPOPT_MSS, IPPROTO_TCP, "TCP MSS" },
    /* SJ_TCPOPT_PAWSCORRUPT */
    { UNASSIGNED_VALUE, NULL, TCPOPT_SACK, IPPROTO_TCP, "TCP SACK" }
};

/* --------------------------------------------------
 * Now start the implementation of HDRoptions memeber */
HDRoptions::HDRoptions(injector_t t, uint8_t *optionStart, uint8_t protohdrlen, uint8_t target_protolen) :
type(t),
nextPlannedInj(NULL)
{
    /* initialize the option tracking usage to 0 */
    memset( (void *)optTrack, 0x00, sizeof(optTrack) );

    corruptRequest = corruptDone = false;

    switch (type)
    {
    case IPOPTS_INJECTOR:

        actual_opts_len = protohdrlen - sizeof(struct iphdr);
        target_opts_len = target_protolen - sizeof(struct iphdr);
        optshdr = vector<unsigned char>(target_opts_len);

        if (!checkupIPopt())
            throw exception();

        break;
    case TCPOPTS_INJECTOR:

        actual_opts_len = protohdrlen - sizeof(struct tcphdr);
        target_opts_len = target_protolen - sizeof(struct tcphdr);
        optshdr = vector<unsigned char>(target_opts_len);

        if (!checkupTCPopt())
            throw exception();

        break;
    }

    available_opts_len = target_opts_len - actual_opts_len;

    memset( (void *)&optshdr[0], 0x00, target_opts_len);
    memcpy( (void *)&optshdr[0], optionStart, actual_opts_len);

    LOG_DEBUG("+ loading %s for %s total opt len:%u target:%u (avail %u) da %d %d",
        __func__, type == IPOPTS_INJECTOR ? "IP" : "TCP", 
       actual_opts_len, target_opts_len, available_opts_len,
       protohdrlen, target_protolen
    );
}

void HDRoptions::setupOption(struct option_discovery *sessionDiscovery)
{
    /* TODO */
}

/*
 *    returns true if injection is possible, false instead;
 *      in addition it registers the presence of some options.
 */
bool HDRoptions::checkupIPopt(void)
{
    uint8_t i = sizeof (struct iphdr);

    while(i < actual_opts_len)
    {
        uint8_t* const option = &optshdr[i];
        uint8_t option_len;

        if(*option == IPOPT_NOOP)
        {
            i++;
            continue;
        }

        if(*option == IPOPT_END)
            break;
        
        for(uint8_t j = 0; j < SUPPORTED_OPTIONS; j++)
        {
            if (optMap[j].applyProto == IPPROTO_IP && *option == optMap[j].optValue)
            {
                optTrack[j].isPresent = true;
                optTrack[j].offset = option;
                optTrack[j].optlen = (uint8_t) optshdr[i + 1];
                goto ip_opts_len_check;
            }
        }

        LOG_PACKET("INFO: a non trapped IP-options: %02x", *option);
        /* read the same analysis below for TCP unknow options */

ip_opts_len_check:
        option_len = (uint8_t) optshdr[i + 1];
        if (option_len == 0 || option_len > (actual_opts_len - i))
        {
            /*
             * the packet contains invalid options
             * we avoid injection regardless of the corrupt value.
             */
            return false;
        }
        i += option_len;
    }

    return true;
}

/*  returns true if injection is possible, false instead;
 *  in addition it registers the presence of some options.
 */
bool HDRoptions::checkupTCPopt(void)
{
    uint8_t i = sizeof (struct tcphdr);

    while(i < actual_opts_len)
    {
        unsigned char* const option = &optshdr[i];
        uint8_t option_len;

        if(*option == TCPOPT_NOP)
        {
            i++;
            continue;
        }

        if(*option == TCPOPT_EOL)
            break;
        
        for (uint8_t j = 0; j < SUPPORTED_OPTIONS; j++)
        {
            if(optMap[j].applyProto != IPPROTO_TCP && *option == optMap[i].optValue)
            {
                optTrack[j].isPresent = true;
                optTrack[j].offset = option;
                optTrack[j].optlen = (uint8_t) optshdr[i + 1];
                goto tcp_opts_len_check;
            }
        }

        LOG_PACKET("INFO: a non trapped TCP-options: %02x", *option);
        /*
         * analysis: will we make a malformed and stripping an option we don't know ? 
         * I belive is better return false if the code is running here, but I prefer 
         * support every TCP options available in the optMap[]. 
         * for this reason, in the beta and < 1.0 release the previous message 
         * will be used for debug & progress pourposes
         */

tcp_opts_len_check:
        option_len = (uint8_t) optshdr[i + 1];
        if (option_len == 0 || option_len > (actual_opts_len - i))
        {
             /* injection regardless of the corrupt value.  */
            return false;
        }
        i += option_len;
        break;
    }

    return true;
}

/* return false if the condition don't fit */
bool HDRoptions::checkCondition(uint32_t i, uint8_t pregressOpt)
{
    /* 1st section, will be the option USED ? */

    /* 2nd section, which the state of the injection history */
    if(!corruptRequest)
        goto only_good;

    if(corruptRequest && corruptDone)
        goto only_good;

    /* 3rd section, corrupted only check */
    if(pregressOpt < 4 && RANDOMPERCENT(40))
        goto only_good;

    if(optMap[i].corruptionType == TWOSHOT || optMap[i].corruptionType == ONESHOT)
        return true;

    return false;

    /* 4th section, clear the next opt + good packet only */
only_good:
    nextPlannedInj = NULL;

    if(optTrack[i].isPresent)
        return false;

    if(optMap[i].corruptionType == NOT_CORRUPT)
        return true;

    if(optMap[i].corruptionType == TWOSHOT && !optTrack[i].isPresent)
        return false;

    return false;    
}

uint32_t HDRoptions::randomInjector(bool corruptionRequest)
{
    /*
     * Every options must be self-contained because sniffjoke needs to know if
     * it has invalidated the packet or not.
     * So for options that need a COMBO (of one ore two options) the combo must
     * be implemented inside the option call itself;
     * For an example of this see the duplicated RR combo defined insied m_IPOPT_LSRR()
     */
    int32_t randomStart, lastOpt, firstOpt, tries;

    /* save this local requirement in the private object variable */
    corruptRequest = corruptionRequest;

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
        firstOpt = (LAST_IPOPT_NAME + 1);
        tries = LAST_TCPOPT_NAME - LAST_IPOPT_NAME + 1;
    }

    int32_t i = randomStart;

    LOG_PACKET("*1 %s option: target:%s status:%s total opt len:%u target:%u (avail %u)",
               type == IPOPTS_INJECTOR ? "IP" : "TCP", 
               corruptRequest ? "CORRUPT" : "VALID",
               corruptDone ? "CORRUPTED" : "NOT YET CORRUPTED",
               actual_opts_len, target_opts_len, available_opts_len);

    while(available_opts_len && --tries)
    {
        /* this loop is intended to be partially random without be too much intensive */
        if( i > lastOpt )
            i = firstOpt;
        else
            i++;

        /* check: this->corruptRequest, this->corruptDone and nextPlannedInj */
        if(!checkCondition(i, actual_opts_len))
            continue;

        actual_opts_len += optMap[i].optApply(this);

        available_opts_len = (target_opts_len - actual_opts_len);

        /* the planned option is used when a TWO SHOT define the second shot */
        if(nextPlannedInj != NULL) 
            actual_opts_len += nextPlannedInj(this);

        /* this will likely never happen if the getBestRandom is used correctly */
        if(actual_opts_len > target_opts_len)
        {
            LOG_PACKET("*** EXCEPTION: %d > %d", actual_opts_len, target_opts_len);
            throw exception();
        }
 
    } 

    LOG_PACKET("*2 %s option: target:%s status:%s total opt len:%u target:%u (avail %u)",
               type == IPOPTS_INJECTOR ? "IP" : "TCP", 
               corruptRequest ? "CORRUPT" : "VALID",
               corruptDone ? "CORRUPTED" : "NOT YET CORRUPTED",
               actual_opts_len, target_opts_len, available_opts_len);

    /* random Injection return the progressing growing of the option header */
    return actual_opts_len;
}

uint32_t HDRoptions::alignOpthdr(uint32_t alignN)
{
    uint8_t nopcode;

    nopcode = (type == IPOPTS_INJECTOR) ? IPOPT_NOOP : TCPOPT_NOP;

    for(uint32_t i = 0; i < alignN; i++)
        optshdr[actual_opts_len + i] = nopcode;

    actual_opts_len += alignN;

    LOG_PACKET("*+ aligned to %u for %d bytes", actual_opts_len, alignN);

    return actual_opts_len;
}

void HDRoptions::copyOpthdr(uint8_t *dst)
{
    for(uint32_t i = 0; i < actual_opts_len; i++)
        dst[i] = optshdr[i];
}

bool HDRoptions::calledInjector(uint32_t sjOptIndex)
{
    if(optMap[sjOptIndex].optApply(this))
        return true;
    else
        return false;
}

bool HDRoptions::removeOption(uint32_t sjDelOpt)
{
    /* if an option is request to be deleted, check before if exist! */
    if(optTrack[sjDelOpt].isPresent == false)
        return false;

    vector<unsigned char> newhdr(target_opts_len);
    uint32_t i;

    for(i = 0; i < target_opts_len; i++)
    {
        if( (&optshdr[i] >= optTrack[i].offset) && (&optshdr[i] <= optTrack[i].offset + optTrack[i].optlen) )
            continue;

        newhdr.push_back(optshdr[i]);
    }

    optshdr.swap(newhdr);

    target_opts_len -= optTrack[i].optlen;
    actual_opts_len -= optTrack[i].optlen;

    return true;
}

