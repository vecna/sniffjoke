/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *
 *  Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                           evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include "IPTCPoptImpl.h"

/* this file contains the extension of the class optionImplement, every options DETAIL,
 * injection function, is implemented here. 
 *
 * in HDRoptions you will found the code SniffJoke-side for the corret choose
 * between the available options
 */

Io_NOOP::Io_NOOP(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_NOOP, "IPOPT_NOOP", IPPROTO_IP, IPOPT_NOOP)
{
}

uint8_t Io_NOOP::optApply(struct optHdrData *oD)
{
    if (oD->getAvailableOptLen() < IPOPT_NOOP_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = IPOPT_NOOP;

    return IPOPT_NOOP_SIZE;
}

Io_EOL::Io_EOL(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_EOL, "IPOPT_EOL", IPPROTO_IP, IPOPT_EOL)
{
}

uint8_t Io_EOL::optApply(struct optHdrData *oD)
{
    return 0;
}

/*
 * IP TIMESTAMP hacking:
 *
 * The timestamp ip option are used in two ways, Io_TIMESTAMP
 * don't corrupt, the option is configured with empy timestamp space.
 *
 * the next instead, Io_TIMESTOVERFLOW, is under research and
 * the option is configured a precise setting of overflow variable
 * to permit an hack similar to prescription.
 *
 * reference: http://tools.ietf.org/rfc/rfc781.txt
 */

Io_TIMESTAMP::Io_TIMESTAMP(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_TIMESTAMP, "IPOPT_TIMESTAMP", IPPROTO_IP, IPOPT_TIMESTAMP)
{
}

uint8_t Io_TIMESTAMP::optApply(struct optHdrData *oD)
{
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
     */

    const uint8_t size_timestamp = getBestRandsize(oD, 4, 1, 6, 4);
    const uint8_t timestamps = (size_timestamp - 4) / 4;
    const uint8_t index = oD->actual_opts_len;

    /* getBestRandom return 0 if there is not enought space */
    if (!size_timestamp)
        return 0;

    oD->optshdr[index] = IPOPT_TIMESTAMP;
    oD->optshdr[index + 1] = size_timestamp;
    oD->optshdr[index + 2] = 5; /* empty */
    oD->optshdr[index + 3] = IPOPT_TS_TSONLY;

    /* by rfc preallocated options memory must be 0, because is filled by the other */
    memset(&oD->optshdr[index + 4], 0, timestamps * 4);

    return size_timestamp;
}

Io_TIMESTOVERFLOW::Io_TIMESTOVERFLOW(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_TIMESTOVERFLOW, "IPOPT_DUMMY (timestamp overflow)", IPPROTO_IP, DUMMY_OPCODE)
{
}

void Io_TIMESTOVERFLOW::setupTTLFocus(TTLFocus *refttlp)
{
    ttlfocus = refttlp;
}

uint8_t Io_TIMESTOVERFLOW::optApply(struct optHdrData *oD)
{
    return 0;
#if 0
    const uint8_t size_timestamp = getBestRandsize(oD, 4, 9, 9, 4);
    const uint8_t timestamps = (size_timestamp - 4) / 4;
    const uint8_t covered_destinations = timestamps + 15; /* the overflow counter is 4 bits */

    if (ttlfocus->status != TTL_KNOWN || ttlfocus->ttl_estimate > covered_destinations)
        return 0;

    /* getBestRandom return 0 if there is not enought space */
    if (!size_timestamp)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    uint8_t overflow = 0;

    uint8_t last_filled = covered_destinations - ttlfocus->ttl_estimate;

    if (last_filled > timestamps)
    {
        overflow = (last_filled - timestamps);
        last_filled = timestamps;
    }

    oD->optshdr[index] = IPOPT_TIMESTAMP;
    oD->optshdr[index + 1] = size_timestamp;
    oD->optshdr[index + 2] = size_timestamp + 1; /* full */
    oD->optshdr[index + 3] = (IPOPT_TS_TSONLY | (overflow << 4)); /* next will overflow */

    memset(&oD->optshdr[index + 4], 0, timestamps * 4);
    memset_random(&oD->optshdr[index + 4], last_filled * 4);

    return size_timestamp;
#endif
}

Io_LSRR::Io_LSRR(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_LSRR, "IPOPT_LSRR", IPPROTO_IP, IPOPT_LSRR)
{
}

uint8_t Io_LSRR::optApply(struct optHdrData *oD)
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

    const uint8_t size_lsrr = getBestRandsize(oD, 3, 1, 4, 4);

    /* getBestRandom return 0 if there is not enought space */
    if (!size_lsrr)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = IPOPT_LSRR;
    oD->optshdr[index + 1] = size_lsrr;
    oD->optshdr[index + 2] = 4;

    memset_random(&oD->optshdr[index + 3], (size_lsrr - 3));

    return size_lsrr;
}

Io_RR::Io_RR(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_RR, "IPOPT_RR", IPPROTO_IP, IPOPT_RR)
{
}

uint8_t Io_RR::optApply(struct optHdrData *oD)
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
     *   due to random : public optionImplement exploits the first or the latter.
     */

    const uint8_t size_rr = getBestRandsize(oD, 3, 1, 4, 4);

    /* getBestRandom return 0 if there is not enought space */
    if (!size_rr)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = IPOPT_RR;
    oD->optshdr[index + 1] = size_rr;
    oD->optshdr[index + 2] = size_rr + 1; /* full */

    memset_random(&(oD->optshdr)[index + 3], (size_rr - 3));

    return size_rr;
}

Io_RA::Io_RA(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_RA, "IPOPT_RA", IPPROTO_IP, IPOPT_RA)
{
}

uint8_t Io_RA::optApply(struct optHdrData *oD)
{
#define IPOPT_RA_SIZE 4

    /*
     * by literature it's not clear if this option could
     * corrupt the packet.
     * studing it we have encontered some icmp errors
     * probably related to repeatitions of the option.
     * so we avoid it.
     */

    if (oD->getAvailableOptLen() < IPOPT_RA_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = IPOPT_RA;
    oD->optshdr[index + 1] = IPOPT_RA_SIZE;

    /*
     * the value of the option by rfc 2113 means:
     *   0: Router shall examine packet
     *   1-65535: Reserved
     *
     * the kernel linux does handle only the 0 value.
     * we set this random to see what will happen =)
     */
    memset_random(&oD->optshdr[index + 2], 2);

    return IPOPT_RA_SIZE;
}

Io_CIPSO::Io_CIPSO(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_CIPSO, "IPOPT_CIPSO", IPPROTO_IP, IPOPT_CIPSO)
{
}

uint8_t Io_CIPSO::optApply(struct optHdrData *oD)
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

    /* this option always corrupts the packet */
    if (oD->getAvailableOptLen() < IPOPT_CIPSO_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = IPOPT_CIPSO;
    oD->optshdr[index + 1] = IPOPT_CIPSO_SIZE;

    memset_random(&oD->optshdr[index + 2], 8);

    return IPOPT_CIPSO_SIZE;
}

Io_SEC::Io_SEC(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_SEC, "IPOPT_SEC", IPPROTO_IP, IPOPT_SEC)
{
}

uint8_t Io_SEC::optApply(struct optHdrData *oD)
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
     * this option always corrupts the packet due to random data values
     */

    if (oD->getAvailableOptLen() < IPOPT_SEC_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    /* TODO - cohorent data for security OPT */
    /* http://www.faqs.org/rfcs/rfc791.html "Security" */
    oD->optshdr[index] = IPOPT_SEC;
    oD->optshdr[index + 1] = IPOPT_SEC_SIZE;

    memset_random(&oD->optshdr[index + 2], 9);

    return IPOPT_SEC_SIZE;
}

Io_SID::Io_SID(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_IPOPT_SID, "IPOPT_SID", IPPROTO_IP, IPOPT_SID)
{
}

uint8_t Io_SID::optApply(struct optHdrData *oD)
{
    /* this option corrupts the packet if repeated. */

    if (oD->getAvailableOptLen() < IPOPT_SID_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = IPOPT_SID;
    oD->optshdr[index + 1] = IPOPT_SID_SIZE;
    memset_random(&oD->optshdr[index + 2], 2);

    return IPOPT_SID_SIZE;
}

/*
 * TCP OPTIONS
 */

To_NOP::To_NOP(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_NOP, "TCPOPT_NOP", IPPROTO_TCP, TCPOPT_NOP)
{
}

uint8_t To_NOP::optApply(struct optHdrData *oD)
{
    if (oD->getAvailableOptLen() < TCPOPT_NOP_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = TCPOPT_NOP;

    return TCPOPT_NOP_SIZE;
}

To_EOL::To_EOL(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_EOL, "TCPOPT_EOL", IPPROTO_TCP, TCPOPT_EOL)
{
}

uint8_t To_EOL::optApply(struct optHdrData *oD)
{
    return 0;
}

To_MD5SIG::To_MD5SIG(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_MD5SIG, "TCPOPT_MD5SIG", IPPROTO_TCP, TCPOPT_MD5SIG)
{
}

/* 
 * http://tools.ietf.org/html/rfc2385 
 * http://frankstocktonart.blogspot.com/2011/04/eisner-nomination.html
 *
 * fyo: MD5 in BGP is not used, and this technology show more reialiability in the
 * https://secure.wikimedia.org/wikipedia/en/wiki/Generalized_TTL_security_mechanism
 * eyes of the tiger.
 *
 * MD5 need to be enabled remotely by a setsockopt. in a more easy way for enabling this
 * signature, TCPOPT_MD5SIG will became the first dianically checked TCP options in Sj
 *
 */
uint8_t To_MD5SIG::optApply(struct optHdrData *oD)
{
    if (oD->getAvailableOptLen() < TCPOPT_MD5SIG_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = TCPOPT_MD5SIG;
    oD->optshdr[index + 1] = TCPOPT_MD5SIG_SIZE;
    memset_random(&oD->optshdr[index + 2], TCPOPT_MD5SIG_SIZE - 2);

    return TCPOPT_MD5SIG_SIZE;
}

To_PAWSCORRUPT::To_PAWSCORRUPT(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_PAWSCORRUPT, "TCPOPT_DUMMY (PAWS)", IPPROTO_TCP, DUMMY_OPCODE)
{
}

uint8_t To_PAWSCORRUPT::optApply(struct optHdrData *oD)
{
    return 0;

#define TCPOPT_TIMESTAMP_SIZE 10
#if 0
    if (oD->getAvailableOptLen() < TCPOPT_TIMESTAMP_SIZE)
        return 0;

    const uint8_t index = oD->actual_opts_len;

    oD->optshdr[index] = TCPOPT_TIMESTAMP;
    oD->optshdr[index + 1] = TCPOPT_TIMESTAMP_SIZE;
    *((uint32_t *) & oD->optshdr[index + 2]) = htonl(sj_clock - 600); /* sj_clock - 10 minutes */
    memset_random(&oD->optshdr[index + 6], 4);

    return TCPOPT_TIMESTAMP_SIZE;
#endif
}

To_TIMESTAMP::To_TIMESTAMP(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_TIMESTAMP, "TCPOPT_TIMESTAMP", IPPROTO_TCP, TCPOPT_TIMESTAMP)
{
}

uint8_t To_TIMESTAMP::optApply(struct optHdrData *oD)
{
    return 0;
}

To_MSS::To_MSS(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_MSS, "TCPOPT_MAXSEG", IPPROTO_TCP, TCPOPT_MAXSEG)
{
}

uint8_t To_MSS::optApply(struct optHdrData *oD)
{
    return 0;
}

To_SACK::To_SACK(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_SACK, "TCPOPT_SACK", IPPROTO_TCP, TCPOPT_SACK)
{
}

uint8_t To_SACK::optApply(struct optHdrData *oD)
{
    return 0;
}

To_SACKPERM::To_SACKPERM(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_SACKPERM, "TCPOPT_SACK_PERMITTED", IPPROTO_TCP, TCPOPT_SACK_PERMITTED)
{
}

uint8_t To_SACKPERM::optApply(struct optHdrData *oD)
{
    return 0;
}

To_WINDOW::To_WINDOW(bool enable) :
IPTCPopt::IPTCPopt(enable, SJ_TCPOPT_WINDOW, "TCPOPT_WINDOW", IPPROTO_TCP, TCPOPT_WINDOW)
{
}

uint8_t To_WINDOW::optApply(struct optHdrData *oD)
{
    return 0;
}

