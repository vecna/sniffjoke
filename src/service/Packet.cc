/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2010, 2011 vecna <vecna@delirandom.net>
 *                            evilaliv3 <giovanni.pellerano@evilaliv3.org>
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

#include "hardcodedDefines.h"
/* defined at the bottom of hardcodedDefines.h */
#ifdef HEAVY_PACKET_DEBUG
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "Packet.h"
#include "HDRoptions.h"
#include "UserConf.h"

extern auto_ptr<UserConf> userconf;

uint32_t Packet::SjPacketIdCounter;

Packet::Packet(const unsigned char* buff, uint16_t size) :
prev(NULL),
next(NULL),
queue(QUEUEUNASSIGNED),
SjPacketId(++SjPacketIdCounter),
source(SOURCEUNASSIGNED),
proto(PROTOUNASSIGNED),
position(POSITIONUNASSIGNED),
wtf(JUDGEUNASSIGNED),
choosableScramble(0),
chainflag(HACKUNASSIGNED),
fragment(false),
fragFakeMTU(0),
pbuf(size)
{
    memcpy(&(pbuf[0]), buff, size);
    updatePacketMetadata(0, 0);
}

Packet::Packet(const Packet& pkt) :
prev(NULL),
next(NULL),
queue(QUEUEUNASSIGNED),
SjPacketId(++SjPacketIdCounter),
source(SOURCEUNASSIGNED),
proto(PROTOUNASSIGNED),
position(POSITIONUNASSIGNED),
wtf(JUDGEUNASSIGNED),
choosableScramble(0),
chainflag(pkt.chainflag),
fragment(false),
fragFakeMTU(0),
pbuf(pkt.pbuf)
{
    updatePacketMetadata(0, 0);
    this->SELFLOG("newly generated packet from: sjI#%d", pkt.SjPacketId);
}

Packet::Packet(const Packet& pkt, uint16_t ipdataoff, uint16_t fragdatalen, uint16_t fakeMTU) :
prev(NULL),
next(NULL),
queue(QUEUEUNASSIGNED),
SjPacketId(++SjPacketIdCounter),
source(SOURCEUNASSIGNED),
proto(PROTOUNASSIGNED),
position(POSITIONUNASSIGNED),
wtf(JUDGEUNASSIGNED),
choosableScramble(0),
chainflag(pkt.chainflag),
fragment(true),
fragFakeMTU(fakeMTU),
pbuf(fragdatalen + sizeof(struct iphdr))
{
    /* copy of the IP header */
    memcpy(&(pbuf[0]), &(pkt.pbuf[0]), sizeof(struct iphdr));

    /* and of the selected IP payload */
    memcpy(&(pbuf[sizeof(struct iphdr)]), &(pkt.pbuf[pkt.iphdrlen + ipdataoff]), fragdatalen);

    if ( (fragdatalen + sizeof(struct iphdr)) > fakeMTU )
    {
        RUNTIME_EXCEPTION("creation of a fragment of (%d + %d ) with fake MTU of %d", 
                          fragdatalen, sizeof(struct iphdr), fakeMTU);
    }

    /* 
     * now the packet has only the iphdr, without option and the ip payload, 
     * 12 bytes options are assured between pbuf.size() and fakeMTU, if required a resize
     */
    updatePacketMetadata(sizeof(struct iphdr), fragdatalen);

    this->SELFLOG("newly generated fragment (dataoff %d fraglen %d fakeMTU %d) source: sjI#%d", 
                ipdataoff, fragdatalen, fakeMTU, pkt.SjPacketId);
}

uint32_t Packet::maxMTU(void)
{
    /* when a fragment is created, also a fake MTU is passed as value */
    if(fragment)
        return fragFakeMTU;
    else
        return userconf->runcfg.net_iface_mtu;
}

uint32_t Packet::freespace(void)
{
    return maxMTU() - pbuf.size();
}

/* the arguments are usually (0, 0): except in fragment creation: in this case,
 * the iphdr is stripped of the options and thus became iphdr, and tot_len is
 * resized by the construct in memcpy, therfore the new value is forced here */
void Packet::updatePacketMetadata(uint16_t forceHDRsize, uint16_t forceTOTsize)
{
    const uint16_t pktlen = pbuf.size();

    /* start initial metadata reset */

    ip = NULL;
    iphdrlen = 0;
    ippayload = NULL;
    ippayloadlen = 0;

    /* unions initialization;
     * one for all because variables are all pointers or uint32_t */
    tcp = NULL; /* udp, icmp */
    tcphdrlen = 0; /* udphdrlen, icmphdrlen */
    tcppayload = NULL; /* udppayload, icmppayload */
    tcppayloadlen = 0; /* udppayloadlen, icmppayloadlen */

    /* end initial metadata reset */

    /* start IP update */
    if (pktlen < sizeof (struct iphdr))
        RUNTIME_EXCEPTION("pktlen < sizeof(struct iphdr)");

    ip = (struct iphdr *) &(pbuf[0]);

    if (!forceHDRsize)
    {
        iphdrlen = ip->ihl * 4;
    }
    else
    {
        iphdrlen = forceHDRsize;
        ip->ihl = (forceHDRsize / 4);
    }

    ippayloadlen = pbuf.size() - iphdrlen;
    if (ippayloadlen)
        ippayload = (unsigned char *) ip + iphdrlen;

    if (pktlen < iphdrlen)
        RUNTIME_EXCEPTION("pktlen < iphdrlen");

    if (forceTOTsize)
        ip->tot_len = htons(forceTOTsize + sizeof(struct iphdr));
    /* end IP update */

    if (fragment)
    {
        /* note: the frag_off and the flags at the moment is managed by the 
         * calling functions, not by Packet. This will be not clean, but for 
         * permit a selfcontained management, is required a passage of various 
         * data (more fragment, the effective offset) and in fact these info 
         * are decided by the calling member. */
        proto = OTHER_IP;
        return;
    }

    switch (ip->protocol)
    {
    case IPPROTO_TCP:
        proto = TCP;
        /* start tcp update */
        if (pktlen < iphdrlen + sizeof (struct tcphdr))
            RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct tcphdr)");

        tcp = (struct tcphdr *) (ippayload);
        tcphdrlen = tcp->doff * 4;

        if (pktlen < iphdrlen + tcphdrlen)
            RUNTIME_EXCEPTION("pktlen < iphdrlen + tcphdrlen");

        if (!(tcphdrlen >= sizeof(struct tcphdr) && tcphdrlen <= sizeof(struct tcphdr) + MAXTCPOPTIONS))
        {
            RUNTIME_EXCEPTION("invalid tcphdrlen %d (min %d max %d)",
                    tcphdrlen, sizeof(struct tcphdr), sizeof(struct tcphdr) + MAXTCPOPTIONS);
        }

        tcppayloadlen = pktlen - iphdrlen - tcphdrlen;
        if (tcppayloadlen)
            tcppayload = (unsigned char *) tcp + tcphdrlen;
        /* end tcp update */
        break;
    case IPPROTO_UDP:
        proto = UDP;
        /* start udp update */
        if (pktlen < iphdrlen + sizeof (struct udphdr))
            RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct udphdr)");

        udp = (struct udphdr *) (ippayload);
        udphdrlen = sizeof (struct udphdr);

        if (pktlen < iphdrlen + udphdrlen)
            RUNTIME_EXCEPTION("pktlen < iphdrlen + udphdrlen");

        if (pktlen < iphdrlen + ntohs(udp->len))
            RUNTIME_EXCEPTION("pktlen != iphdrlen + ntohs(udp->len)");

        udppayloadlen = pktlen - iphdrlen - udphdrlen;
        if (udppayloadlen)
            udppayload = (unsigned char *) tcp + udphdrlen;
        /* end udp update */
        break;
    case IPPROTO_ICMP:
        proto = ICMP;
        /* start icmp update */
        if (pktlen < iphdrlen + sizeof (struct icmphdr))
            RUNTIME_EXCEPTION("pktlen < iphdrlen + sizeof(struct icmphdr)");

        icmp = (struct icmphdr *) (ippayload);
        icmphdrlen = sizeof (struct icmphdr);

        if (pktlen < iphdrlen + icmphdrlen)
            RUNTIME_EXCEPTION("pktlen != iphdrlen + icmphdrlen");

        icmppayloadlen = pktlen - iphdrlen - icmphdrlen;
        if (icmppayloadlen)
            icmppayload = (unsigned char *) icmp + icmphdrlen;
        /* end icmp update */
        break;
    default:
        proto = OTHER_IP;
    }
}

uint32_t Packet::computeHalfSum(const unsigned char* data, uint16_t len)
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

void Packet::fixIPSum(void)
{
    ip->check = 0;

    uint32_t sum = computeHalfSum((const unsigned char *) ip, iphdrlen);

    ip->check = computeSum(sum);
}

void Packet::fixIPTCPSum(void)
{
    fixIPSum();

    tcp->check = 0;

    uint32_t sum = computeHalfSum((const unsigned char *) &ip->saddr, 8);
    sum += htons(IPPROTO_TCP + ippayloadlen);
    sum += computeHalfSum((const unsigned char *) tcp, ippayloadlen);

    tcp->check = computeSum(sum);
}

void Packet::fixIPUDPSum(void)
{
    fixIPSum();

    udp->check = 0;

    uint32_t sum = computeHalfSum((const unsigned char *) &ip->saddr, 8);
    sum += htons(IPPROTO_UDP + ippayloadlen);
    sum += computeHalfSum((const unsigned char *) udp, ippayloadlen);

    udp->check = computeSum(sum);
}

void Packet::fixSum(void)
{
    if (fragment == false)
    {
        switch (proto)
        {
        case TCP:
            fixIPTCPSum();
            break;
        case UDP:
            fixIPUDPSum();
            break;
        default:
            fixIPSum();
        }
    }
    else
    {
        fixIPSum();
    }
}

void Packet::corruptSum(void)
{
    if (fragment == false)
    {
        switch (proto)
        {
        case TCP:
            tcp->check += 0xd34d;
            break;
        case UDP:
            udp->check += 0xd34d;
            break;
        default:
            ip->check += 0xd34d;
        }
    }
    else
    {
        ip->check += 0xd34d;
    }
}

bool Packet::selfIntegrityCheck(const char *pluginName)
{
    if (wtf == JUDGEUNASSIGNED)
    {
        LOG_ALL("in %s not set \"wtf\" field (what the fuck Sj has to do with this packet?)", pluginName);
        goto errorinfo;
    }

    if (choosableScramble == 0)
    {
        LOG_ALL("in %s not set \"choosableScramble\" field (what the fuck Sj can to do with this packet?)", pluginName);
        goto errorinfo;
    }

    if (proto == PROTOUNASSIGNED)
    {
        LOG_ALL("in %s not set \"proto\" field, required %u", pluginName, pbuf.size());
        goto errorinfo;
    }

    if (position == POSITIONUNASSIGNED)
    {
        LOG_ALL("in %s not set \"position\" field, required", pluginName);
        goto errorinfo;
    }

    if (chainflag == HACKUNASSIGNED)
    {
        LOG_ALL("in %s not set \"chainflag\" field, required", pluginName);
        goto errorinfo;
    }

    return true;
errorinfo:
    LOG_VERBOSE("Invalid packet generation from a plugin: not a strong problem, but must be handled. remind");
    return false;
}

void Packet::randomizeID(void)
{
    ip->id = htons(ntohs(ip->id) - 10 + (random() % 20));
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
     *   pktlen - iphdrlen + size : must be <= maxMTU().
     */

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    ip->ihl = size / 4;

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

    updatePacketMetadata(0, 0);
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
     *   - pktlen - tcphdrlen + size : must be <= maxMTU().
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

    updatePacketMetadata(0, 0);
}

void Packet::ippayloadResize(uint16_t size)
{
    if (size == ippayloadlen)
        return;

    const uint16_t pktlen = pbuf.size();

    /* begin safety checks */
    if (pktlen - ippayloadlen + size > (int16_t) maxMTU())
        RUNTIME_EXCEPTION("pktlen - ippayloadlen + (new) size > MTU");
    /* end safety checks */

    const uint16_t new_total_len = pktlen - ippayloadlen + size;

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    ip->tot_len = htons(new_total_len);

    pbuf.resize(new_total_len);

    updatePacketMetadata(0, 0);
}

void Packet::tcppayloadResize(uint16_t size)
{
    if (size == tcppayloadlen)
        return;

    const uint16_t pktlen = pbuf.size();

    /* begin safety checks */
    if (pktlen - tcppayloadlen + size > (int16_t) maxMTU())
        RUNTIME_EXCEPTION("pktlen - tcppayloadlen + (new) size > MTU");
    /* end safety checks */

    const uint16_t new_total_len = pktlen - tcppayloadlen + size;

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    ip->tot_len = htons(new_total_len);

    pbuf.resize(new_total_len);

    updatePacketMetadata(0, 0);
}

void Packet::udppayloadResize(uint16_t size)
{
    if (size == udppayloadlen)
        return;

    const uint16_t pktlen = pbuf.size();

    /* begin safety checks */
    if (pktlen - udppayloadlen + size > (int16_t) maxMTU())
        RUNTIME_EXCEPTION("pktlen - udppayload + (new) size > MTU");
    /* end safety checks */

    const uint16_t new_total_len = pktlen - udppayloadlen + size;

    /* its important to update values into hdr before vector insert call because it can cause relocation */
    ip->tot_len = htons(new_total_len);

    /* in udp we have also to correct the len field */
    udp->len = htons(udphdrlen + size);

    pbuf.resize(new_total_len);

    updatePacketMetadata(0, 0);
}

void Packet::ippayloadRandomFill(void)
{
    memset_random(ippayload, pbuf.size() - iphdrlen);
}

void Packet::tcppayloadRandomFill(void)
{
    memset_random(tcppayload, pbuf.size() - (iphdrlen + tcphdrlen));
}

void Packet::udppayloadRandomFill(void)
{
    memset_random(udppayload, pbuf.size() - (iphdrlen + udphdrlen));
}

void Packet::payloadRandomFill(void)
{
    if (fragment == false)
    {
        switch (proto)
        {
        case TCP:
            tcppayloadRandomFill();
            break;
        case UDP:
            udppayloadRandomFill();
            break;
        default:
            ippayloadRandomFill();
            break;
        }
    }
    else
    {
        ippayloadRandomFill();
    }
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

    const char *p;
    char protoinfo[MEDIUMBUF] = {0}, saddr[MEDIUMBUF] = {0}, daddr[MEDIUMBUF] = {0};

    p = inet_ntoa(*((struct in_addr *) &(ip->saddr)));
    strncpy(saddr, p, sizeof (saddr));

    p = inet_ntoa(*((struct in_addr *) &(ip->daddr)));
    strncpy(daddr, p, sizeof (daddr));

    const char *sourcestr = getSourceStr(source);
    const char *wtfstr = getWtfStr(wtf);
    const char *chainstr = getChainStr(chainflag);

    if (!fragment)
    {
        switch (proto)
        {
        case TCP:
            snprintf(protoinfo, sizeof (protoinfo), "TCP %u:%u SAFR{%u%u%u%u} L %u = %u+%u+%u",
                     ntohs(tcp->source), ntohs(tcp->dest), tcp->syn, tcp->ack, tcp->fin, tcp->rst,
                     (unsigned int) pbuf.size(), (htons(ip->tot_len) - ippayloadlen),
                     (tcp->doff * 4), htons(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4)
                     );
            break;
        case UDP:
            snprintf(protoinfo, sizeof (protoinfo), "UDP %u->%u len|%u(%u)",
                     ntohs(udp->source), ntohs(udp->dest),
                     (unsigned int) pbuf.size(), (unsigned int) (pbuf.size() - iphdrlen - udphdrlen)
                     );
            break;
        case ICMP:
            snprintf(protoinfo, sizeof (protoinfo), "ICMP type|%d code|%d len|%u(%u)",
                     icmp->type, icmp->code,
                     (unsigned int) pbuf.size(), (unsigned int) (pbuf.size() - iphdrlen - sizeof (struct icmphdr))
                     );
            break;
        case OTHER_IP:
            snprintf(protoinfo, sizeof (protoinfo), "other proto: %d", ip->protocol);
            break;
        default:
            RUNTIME_EXCEPTION("FATAL CODE [CYN1C]: please send a notification to the developers (%u)", proto);
            break;
        }

        LOG_PACKET("%s: i%u s'%s w'%s c'%s %s->%s [%s] ttl:%u %s",
                   func, SjPacketId, sourcestr, wtfstr, chainstr,
                   saddr, daddr, protoinfo, ip->ttl, loginfo);
    }
    else
    {
        LOG_PACKET("%s: i%u s'%s w'%s c'%s %s->%s FRAG:%u '%s' ttl:%u %s",
                   func, SjPacketId, sourcestr, wtfstr, chainstr,
                   saddr, daddr, ntohs(ip->frag_off & IP_OFFMASK),
                   ntohs(ip->frag_off & IP_MF) ? "MF" : "!MF",
                   ip->ttl, loginfo);
    }
}

Packet::~Packet()
{
#ifdef HEAVY_PACKET_DEBUG
#define PACKETLOG_PREFIX_TCP   "TCPpktLog/"
#define PACKETLOG_PREFIX_UDP   "UDPpktLog/"

    const char *protoprefix = NULL;
    uint16_t sport = 0;
    uint16_t dport = 0;

    switch (proto)
    {
    case TCP:
        protoprefix = PACKETLOG_PREFIX_TCP;
        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);
        break;
    case UDP:
        protoprefix = PACKETLOG_PREFIX_UDP;
        sport = ntohs(udp->source);
        dport = ntohs(udp->dest);
        break;
    case ICMP:
    case OTHER_IP:
        return;
    case PROTOUNASSIGNED:
        RUNTIME_EXCEPTION("FATAL CODE [L3B0WSK1]: please send a notification to the developers (%u)", proto);
    }

    mkdir(protoprefix, 0770);

    char fname[MEDIUMBUF];
    snprintf(fname, MEDIUMBUF, "%s%s", protoprefix, inet_ntoa(*((struct in_addr *) &ip->daddr)));

    FILE *packetLog = fopen(fname, "a+");
    if (packetLog == NULL)
        RUNTIME_EXCEPTION("unable to open %s:%s", fopen, strerror(errno));

    fprintf(packetLog, "%d\t%d:%d%s%d\tchain %s, position %d, judge [%s], queue %d, from [%s]\n",
            SjPacketId, sport, dport,
            fragment ? "\tfrag " : "\t", (unsigned int) pbuf.size(), getChainStr(chainflag),
            position, getWtfStr(wtf), queue, getSourceStr(source));

    fclose(packetLog);
#endif
}

const char * Packet::getWtfStr(judge_t wtf) const
{
    switch (wtf)
    {
    case PRESCRIPTION:
        return "ttlexpire";
    case INNOCENT:
        return "innocent";
    case GUILTY:
        return "badcksum";
    case MALFORMED:
        return "malformed";
    case JUDGEUNASSIGNED:
        return "U";
    default:
        RUNTIME_EXCEPTION("FATAL CODE [3V0LUT10N4RYSL33PER]: please send a notification to the developers");
    }
}

const char * Packet::getSourceStr(source_t source) const
{
    switch (source)
    {
    case TUNNEL:
        return "tunnel";
    case NETWORK:
        return "network";
    case PLUGIN:
        return "hackinject";
    case TRACEROUTE:
        return "tracert";
    case SOURCEUNASSIGNED:
        return "U";
    default:
        RUNTIME_EXCEPTION("FATAL CODE [S1KT4MBUR0]: please send a notification to the developers");
    }
}

const char * Packet::getChainStr(chaining_t chainflag) const
{
    switch (chainflag)
    {
    case FINALHACK:
        return "final";
    case REHACKABLE:
        return "reHackable";
    case HACKUNASSIGNED:
        return "U";
    default:
        RUNTIME_EXCEPTION("FATAL CODE [P4ND3LD14V0L0]: please send a notification to the developers");
    }
}
