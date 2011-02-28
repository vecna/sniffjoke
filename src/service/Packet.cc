/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010 vecna <vecna@delirandom.net>
 *                      evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include "Packet.h"
#include "HDRoptions.h"

#define MAXIPHEADER 60 /* included ip options */
#define MAXTCPHEADER 60 /* included tcp options */
#define MINIPOPTION 4 /* excluded NOP/EOL */
#define MINTCPOPTION 4 /* excluded NOP/EOL */
#define MAXIPINJITERATIONS 5 /* max number of injected ip options / retries */
#define MAXTCPINJITERATIONS 5 /* max number of injected tcp options / retries */

Packet::Packet(const unsigned char* buff, uint16_t size) :
queue(QUEUEUNASSIGNED),
prev(NULL),
next(NULL),
evilbit(MORALITYUNASSIGNED),
source(SOURCEUNASSIGNED),
proto(PROTOUNASSIGNED),
position(POSITIONUNASSIGNED),
wtf(JUDGEUNASSIGNED),
pbuf(size),
fragment(false)
{
    memcpy(&(pbuf[0]), buff, size);
    updatePacketMetadata();
}

Packet::Packet(const Packet& pkt) :
queue(QUEUEUNASSIGNED),
prev(NULL),
next(NULL),
evilbit(pkt.evilbit),
source(LOCAL),
proto(pkt.proto),
position(pkt.position),
wtf(pkt.wtf),
pbuf(pkt.pbuf),
fragment(false)
{
    updatePacketMetadata();
}

void Packet::mark(source_t source, evilbit_t morality)
{
    this->source = source;
    this->evilbit = morality;
}

void Packet::mark(source_t source, judge_t wtf, evilbit_t morality)
{
    this->wtf = wtf;
    mark(source, morality);
}

void Packet::updatePacketMetadata()
{
    uint16_t pktlen = pbuf.size();

    /* start initial metadata reset */

    ip = NULL;
    iphdrlen = 0;
    ippayload = NULL;
    ippayloadlen = 0;

    /* unions initialization; one for all */
    tcp = NULL;         /* udp, icmp */
    tcphdrlen = 0;      /* udphdrlen, icmphdrlen */
    tcppayload = NULL;  /* udppayload, icmppayload */
    tcppayloadlen = 0;  /* udppayloadlen, icmppayloadlen */

    /* end initial metadata reset */

    /* start ip update */
    if (pktlen < sizeof (struct iphdr))
        RUNTIME_EXCEPTION("pktlen < sizeof(struct iphdr)");

    ip = (struct iphdr *) &(pbuf[0]);
    iphdrlen = ip->ihl * 4;
    ippayloadlen = pbuf.size() - iphdrlen;
    if (ippayloadlen)
        ippayload = (unsigned char *) ip + iphdrlen;

    if (pktlen < iphdrlen)
        RUNTIME_EXCEPTION("pktlen < iphdrlen");


    if (pktlen < ntohs(ip->tot_len))
        RUNTIME_EXCEPTION("pktlen < ntohs(ip->tot_len)");
    /* end ip update */

    switch (ip->protocol)
    {
    case IPPROTO_TCP:
        proto = TCP;
        break;
    case IPPROTO_UDP:
        proto = UDP;
        break;
    case IPPROTO_ICMP:
        proto = ICMP;
        break;
    default:
        proto = OTHER_IP;
        break;
    }

    /*
     * if the packet it's a fragment sniffjoke does treat it
     * as a pure ip packet.
     */
    if (ip->frag_off & htons(0x3FFF))
    {
        fragment = true;
        return;
    }

    switch (ip->protocol)
    {
    case IPPROTO_TCP:
        /* start tcp update */
        if (pktlen < iphdrlen + sizeof (struct tcphdr))
            RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct tcphdr)");

        tcp = (struct tcphdr *) ((unsigned char *) (ip) + iphdrlen);
        tcphdrlen = tcp->doff * 4;

        if (pktlen < iphdrlen + tcphdrlen)
            RUNTIME_EXCEPTION("pktlen < iphdrlen + tcphdrlen");

        tcppayloadlen = pktlen - iphdrlen - tcphdrlen;
        if (tcppayloadlen)
            tcppayload = (unsigned char *) tcp + tcphdrlen;
        /* end tcp update */
        break;
    case IPPROTO_UDP:
        /* start tcp update */
        if (pktlen < iphdrlen + sizeof (struct udphdr))
            RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct udphdr)");

        udp = (struct udphdr *) ((unsigned char *) (ip) + iphdrlen);
        udphdrlen = sizeof (struct udphdr);

        if (pktlen < iphdrlen + udphdrlen)
            RUNTIME_EXCEPTION("pktlen < iphdrlen + udphdrlen");

        udppayloadlen = pktlen - iphdrlen - udphdrlen;
        if (udppayloadlen)
            udppayload = (unsigned char *) tcp + udphdrlen;
        /* end tcp update */
        break;
    case IPPROTO_ICMP:
        /* start icmp update */
        if (pktlen < iphdrlen + sizeof (struct icmphdr))
            RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct icmphdr)");

        icmp = (struct icmphdr *) ((unsigned char *) (ip) + iphdrlen);
        icmphdrlen = sizeof (struct icmphdr);

        if (pktlen < iphdrlen + icmphdrlen)
            RUNTIME_EXCEPTION("pktlen < iphdrlen + icmphdrlen");

        icmppayloadlen = 0;
        /* end icmp update */

        break;
    }
}

uint32_t Packet::computeHalfSum(const void* data, uint16_t len)
{
    const uint16_t *usdata = (uint16_t *) data;
    const uint16_t *end = (uint16_t *) data + (len / sizeof (uint16_t));
    uint32_t sum = 0;

    while (usdata != end)
        sum += *usdata++;

    if (len % 2)
        sum += *(uint8_t *) usdata;

    return sum;
}

uint16_t Packet::computeSum(uint32_t sum)
{
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

void Packet::fixIpSum(void)
{
    uint32_t sum;

    ip->check = 0;
    sum = computeHalfSum((const void *) ip, iphdrlen);
    ip->check = computeSum(sum);
}

void Packet::fixIpTcpSum(void)
{
    fixIpSum();

    uint32_t sum;
    const uint16_t l4len = ntohs(ip->tot_len) - iphdrlen;

    tcp->check = 0;
    sum = computeHalfSum((const void *) &ip->saddr, 8);
    sum += htons(IPPROTO_TCP + l4len);
    sum += computeHalfSum((const void *) tcp, l4len);
    tcp->check = computeSum(sum);
}

void Packet::fixSum(void)
{
    if (fragment != false || proto != TCP)
        fixIpSum();
    else
        fixIpTcpSum();
}

void Packet::corruptSum(void)
{
    if (fragment == false && proto == TCP)
        tcp->check += 0xd34d;
    else
        ip->check += 0xd34d;
}

bool Packet::selfIntegrityCheck(const char *pluginName)
{
    if (wtf == JUDGEUNASSIGNED)
    {
        LOG_ALL("in %s not set \"wtf\" field (what the fuck Sj has to do with this packet?)", pluginName);
        goto errorinfo;
    }

    if (proto == PROTOUNASSIGNED)
    {
        LOG_ALL("in %s not set \"proto\" field, required", pluginName);
        goto errorinfo;
    }

    if (position == POSITIONUNASSIGNED)
    {
        LOG_ALL("in %s not set \"position\" field, required", pluginName);
        goto errorinfo;
    }

    return true;

errorinfo:
    LOG_DEBUG("documentation about plugins development: http://www.sniffjoke.net/delirandom/plugins");
    return false;
}

void Packet::iphdrResize(uint8_t size)
{
    if (size == iphdrlen)
        return;

    const uint16_t pktlen = pbuf.size();

    /*
     * safety checks delegated to the function caller:
     *   size : must be multiple of 4;
     *   size : must be >= sizeof(struct iphdr));
     *   size : must be <= MAXIPHEADER;
     *   pktlen - iphdrlen + size : must be <= MTU.
     */

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    ip->ihl = size / 4;
    if (size % 4) exit(1);

    vector<unsigned char>::iterator it = pbuf.begin();

    if (iphdrlen < size)
    {
        ip->tot_len = htons(pktlen + (size - iphdrlen));
        pbuf.insert(it + iphdrlen, size - iphdrlen, IPOPT_NOOP);
    }
    else
    { /* iphdrlen > size */
        ip->tot_len = htons(pktlen - (iphdrlen - size));
        pbuf.erase(it + size, it + iphdrlen);
    }

    updatePacketMetadata();
}

void Packet::tcphdrResize(uint8_t size)
{
    if (fragment == true)
        RUNTIME_EXCEPTION("it's not possible to call this function on a ip fragment");

    if (size == tcphdrlen)
        return;

    const uint16_t pktlen = pbuf.size();

    /*
     * safety checks delegated to the function caller:
     *   - size : must be multiple of 4;
     *   - size : must be >= sizeof(struct tcphdr));
     *   - size : must be <= MAXTCPHEADER;
     *   - pktlen - tcphdrlen + size : must be <= MTU.
     */

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    tcp->doff = size / 4;

    vector<unsigned char>::iterator it = pbuf.begin() + iphdrlen;

    if (tcphdrlen < size)
    {
        ip->tot_len = htons(pktlen + (size - tcphdrlen));
        pbuf.insert(it + tcphdrlen, size - tcphdrlen, TCPOPT_NOP);
    }
    else
    { /* tcphdrlen > size */
        ip->tot_len = htons(pktlen - (tcphdrlen - size));
        pbuf.erase(it + size, it + tcphdrlen);
    }

    updatePacketMetadata();
}

void Packet::ippayloadResize(uint16_t size)
{
    if (size == ippayloadlen)
        return;

    const uint16_t pktlen = pbuf.size();

    /* begin safety checks */
    if (pktlen - ippayloadlen + size > MTU)
        RUNTIME_EXCEPTION("");
    /* end safety checks */

    const uint16_t new_total_len = pktlen - ippayloadlen + size;

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    ip->tot_len = htons(new_total_len);

    pbuf.resize(new_total_len);

    updatePacketMetadata();
}

void Packet::tcppayloadResize(uint16_t size)
{
    if (size == tcppayloadlen)
        return;

    const uint16_t pktlen = pbuf.size();

    /* begin safety checks */
    if (pktlen - tcppayloadlen + size > MTU)
        RUNTIME_EXCEPTION("");
    /* end safety checks */

    const uint16_t new_total_len = pktlen - tcppayloadlen + size;

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    ip->tot_len = htons(new_total_len);

    pbuf.resize(new_total_len);

    updatePacketMetadata();
}

void Packet::ippayloadRandomFill()
{
    const uint16_t diff = pbuf.size() - iphdrlen;
    memset_random(ippayload, diff);
}

void Packet::tcppayloadRandomFill()
{
    const uint16_t diff = pbuf.size() - (iphdrlen + tcphdrlen);
    memset_random(tcppayload, diff);
}

bool Packet::injectIPOpts(bool corrupt, bool strip_previous)
{

    bool injected = false;

    const uint16_t pktlen = pbuf.size();

    uint8_t actual_iphdrlen = iphdrlen;

    uint8_t target_iphdrlen = 0;

    uint16_t freespace = MTU - pktlen;

    SELFLOG("before ip injection [strip %u] iphdrlen %u ippayloadlen %u pktlen %u", strip_previous, iphdrlen, ippayloadlen, pbuf.size());

    if (strip_previous)
    {
        freespace += (iphdrlen - (sizeof (struct iphdr)));

        actual_iphdrlen = sizeof (struct iphdr);
        target_iphdrlen = sizeof (struct iphdr) + (random() % (MAXIPHEADER - sizeof (struct iphdr) + 1));
    }
    else if (MAXIPHEADER - iphdrlen >= MINIPOPTION)
    {
        target_iphdrlen = iphdrlen + random() % (MAXIPHEADER - iphdrlen + 1);
    }

    // iphdrlen must be a multiple of 4, we decrement by the modulus keeping count of MTU
    freespace -= freespace % 4;
    target_iphdrlen -= target_iphdrlen % 4;

    if (freespace == 0)
        return false;

    if (freespace < target_iphdrlen)
        target_iphdrlen = actual_iphdrlen + freespace;

    if (target_iphdrlen != iphdrlen)
        iphdrResize(target_iphdrlen);

    try
    {
        HDRoptions IPInjector(IPOPTS_INJECTOR, corrupt, (unsigned char *) ip + sizeof (struct iphdr), actual_iphdrlen, target_iphdrlen);
        uint8_t tries = MAXIPINJITERATIONS;

        do
        {
            injected |= IPInjector.randomInjector();

        }
        while ((target_iphdrlen != actual_iphdrlen) && --tries);
    }
    catch (exception &e)
    {
        SELFLOG("ip injection is not possibile");
    }

    if (target_iphdrlen != actual_iphdrlen)
    {
        /* iphdrlen must be a multiple of 4, this last check is to permit IPInjector.randomInjector()
           to inject options not aligned to 4 */
        actual_iphdrlen += (actual_iphdrlen % 4) ? (4 - actual_iphdrlen % 4) : 0;
        iphdrResize(actual_iphdrlen);
    }

    SELFLOG("after ip injection [strip %u] iphdrlen %u ippayloadlen %u pktlen %u", strip_previous, iphdrlen, ippayloadlen, pbuf.size());

    return injected;
}

bool Packet::injectTCPOpts(bool corrupt, bool strip_previous)
{
    bool injected = false;

    const uint16_t pktlen = pbuf.size();

    uint8_t actual_tcphdrlen = tcphdrlen;

    uint8_t target_tcphdrlen = 0;

    uint16_t freespace = MTU - pktlen;

    SELFLOG("before tcp injection [strip %u] iphdrlen %u tcphdrlen %u ippayload %u pktlen %u", strip_previous, iphdrlen, tcphdrlen, tcppayloadlen, pbuf.size());

    if (strip_previous)
    {
        freespace += (tcphdrlen - (sizeof (struct tcphdr)));

        actual_tcphdrlen = sizeof (struct tcphdr);
        target_tcphdrlen = sizeof (struct tcphdr) + (random() % (MAXTCPHEADER - sizeof (struct tcphdr) + 1));
    }
    else if (MAXTCPHEADER - tcphdrlen >= MINTCPOPTION)
    {
        target_tcphdrlen = tcphdrlen + (random() % (MAXTCPHEADER - tcphdrlen + 1));
    }

    // tcphdrlen must be a multiple of 4, we decrement by the modulus keeping count of MTU
    freespace -= freespace % 4;
    target_tcphdrlen -= target_tcphdrlen % 4;

    if (freespace == 0)
        return false;

    if (freespace < target_tcphdrlen)
        target_tcphdrlen = actual_tcphdrlen + freespace;

    if (target_tcphdrlen != tcphdrlen)
        tcphdrResize(target_tcphdrlen);

    try
    {
        HDRoptions TCPInjector(TCPOPTS_INJECTOR, corrupt, (unsigned char *) tcp + sizeof (struct tcphdr), actual_tcphdrlen, target_tcphdrlen);
        uint8_t tries = MAXTCPINJITERATIONS;

        do
        {
            injected |= TCPInjector.randomInjector();

        }
        while ((target_tcphdrlen != actual_tcphdrlen) && --tries);

    }
    catch (exception &e)
    {
        SELFLOG("tcp injection is not possibile");
    }

    if (target_tcphdrlen != actual_tcphdrlen)
    {
        /* tcphdrlen must be a multiple of 4, this last check is to permit IPInjector.randomInjector()
           to inject options not aligned to 4 */
        actual_tcphdrlen += (actual_tcphdrlen % 4) ? (4 - actual_tcphdrlen % 4) : 0;
        tcphdrResize(actual_tcphdrlen);
    }

    SELFLOG("after tcp injection [strip %u] iphdrlen %u tcphdrlen %u ippayload %u pktlen %u", strip_previous, iphdrlen, tcphdrlen, tcppayloadlen, pbuf.size());

    return injected;
}

void Packet::selflog(const char *func, const char *format, ...) const
{
    if (debug.level() == SUPPRESS_LEVEL)
        return;

    char loginfo[LARGEBUF] = {0};
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(loginfo, sizeof (loginfo), format, arguments);
    va_end(arguments);

    const char *evilstr, *wtfstr, *sourcestr, *p;
    char protoinfo[MEDIUMBUF] = {0}, saddr[MEDIUMBUF] = {0}, daddr[MEDIUMBUF] = {0};

    p = inet_ntoa(*((struct in_addr *) &(ip->saddr)));
    strncpy(saddr, p, sizeof (saddr));

    p = inet_ntoa(*((struct in_addr *) &(ip->daddr)));
    strncpy(daddr, p, sizeof (daddr));

    switch (evilbit)
    {
    case GOOD: evilstr = "good";
        break;
    case EVIL: evilstr = "evil";
        break;
    default: case MORALITYUNASSIGNED: evilstr = "UNASSIGNED-e";
        break;

    }

    switch (wtf)
    {
    case PRESCRIPTION: wtfstr = "ttlexpire";
        break;
    case INNOCENT: wtfstr = "innocent";
        break;
    case GUILTY: wtfstr = "badcksum";
        break;
    case MALFORMED: wtfstr = "malformed";
        break;
    default: case JUDGEUNASSIGNED: wtfstr = "UNASSIGNED-wtf";
        break;
    }

    switch (source)
    {
    case TUNNEL: sourcestr = "tunnel";
        break;
    case LOCAL: sourcestr = "local";
        break;
    case NETWORK: sourcestr = "network";
        break;
    case TTLBFORCE: sourcestr = "ttl bruteforce";
        break;
    default: case SOURCEUNASSIGNED: sourcestr = "UNASSIGNED-src";
        break;
    }

    if (fragment)
    {
        LOG_PACKET("%s: (E|%s) (WTF|%s) (src|%s) %s->%s FRAGMENT (%u) ttl %u [%s]",
                   func, evilstr, wtfstr, sourcestr,
                   saddr, daddr, ntohs(ip->frag_off),
                   ip->ttl, loginfo
                   );
    }
    else
    {
        switch (proto)
        {
        case TCP:
            snprintf(protoinfo, sizeof (protoinfo), "TCP sp %u dp %u SAFR{%d%d%d%d} len %u(%u) seq %x ack_seq %x",
                     ntohs(tcp->source), ntohs(tcp->dest), tcp->syn, tcp->ack, tcp->fin,
                     tcp->rst, (unsigned int) pbuf.size(), (unsigned int) (pbuf.size() - iphdrlen - tcphdrlen),
                     ntohl(tcp->seq), ntohl(tcp->ack_seq)
                     );
            break;
        case UDP:
            snprintf(protoinfo, sizeof (protoinfo), "UDP sp %u dp %u len %u(%u)",
                     ntohs(udp->source), ntohs(udp->dest),
                     (unsigned int) pbuf.size(), (unsigned int) (pbuf.size() - iphdrlen - udphdrlen)
                     );
            break;
        case ICMP:
            snprintf(protoinfo, sizeof (protoinfo), "ICMP type %d code %d len %u(%u)",
                     icmp->type, icmp->code,
                     (unsigned int) pbuf.size(), (unsigned int) (pbuf.size() - iphdrlen - sizeof (struct icmphdr))
                     );
            break;
        case OTHER_IP:
            snprintf(protoinfo, sizeof (protoinfo), "other proto: %d", ip->protocol);
            break;
        case PROTOUNASSIGNED:
            snprintf(protoinfo, sizeof (protoinfo), "protocol unassigned! value %d", ip->protocol);
            break;
        default:
            RUNTIME_EXCEPTION("BUG: invalid and impossibile");
            break;
        }

        LOG_PACKET("%s: E|%s WTF|%s src %s|%s->%s proto [%s] ttl %d %s",
                   func, evilstr, wtfstr, sourcestr, saddr, daddr, protoinfo, ip->ttl, loginfo);
    }
}
