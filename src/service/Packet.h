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

#ifndef SJ_PACKET_H
#define SJ_PACKET_H

#include "Utils.h"
#include "ScrambleMask.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/* IT'S FUNDAMENTAL TO HAVE ALL ENUMS VALUES AS POWERS OF TWO TO PERMIT OR MASKS */

/* queue_t is a a reflection variable used by packet to know in what queue it's inserted */
enum queue_t
{
    QUEUEUNASSIGNED = 0, YOUNG = 1, KEEP = 2, HACK = 4, SEND = 8
};

/* if the packet is injected by sniffjoke is marked with the evilbit,
 * GOOD if is a natural packet, EVIL if is an injected one, NEUTRAL if the scramble
 * has generated a packet which morality will be defined by the plugins */
enum evilbit_t
{
    MORALITYUNASSIGNED = 0, GOOD = 1, EVIL = 2, NEUTRAL = 4
};

/* the source_t is the nature of the packet, ANY_SOURCE is used at catch-all */
enum source_t
{
    SOURCEUNASSIGNED = 0, TUNNEL = 1, NETWORK = 2, PLUGIN = 4, SCRAMBLE = 8
};

/* an enum for the proto. ANY_PROTO is the catch-all used when the queue(s) are queryed */
enum proto_t
{
    PROTOUNASSIGNED = 0, TCP = 1, UDP = 2, ICMP = 4, OTHER_IP = 8
};

/* Every sniffjoke packet is based on be discarged from the remote host and accepted from
 * the sniffer, in order to obtain the sniffer tracking poisoning, those marker mean if the
 * packet need to be plain and correct (INNOCENT) or be CORRUPTED. when a packet is INNOCENT,
 * mean that that remote host will accept it in the kernel level, when is CORRUPTNEED is a marker
 * useful for the scramble engine, to understand that the packet has to be modify in order to be
 * discarged, not accepted, or never reach the remote server application. CORRUPTDONE is useful
 * to mark a packet that require to be corrupted, and in fact happen. */
enum judge_t
{
    JUDGEUNASSIGNED = 0, INNOCENT = 1, CORRUPTNEED = 2, CORRUPTDONE = 4
};

/* a sniffjoke packet should be send before the original packet or after the original packet */
enum position_t
{
    POSITIONUNASSIGNED = 0, ANY_POSITION = 1, ANTICIPATION = 2, POSTICIPATION = 4
};

/* a packet will be rehacked or will not, these value are used in chaining mode */
enum chaining_t
{
    HACKUNASSIGNED = 0, FINALHACK = 1, REHACKABLE = 2
};

class Packet
{
private:
    friend class PacketQueue;
    static uint32_t SjPacketIdCounter;

    Packet *prev;
    Packet *next;

    /* reflection variable used on queue change */
    queue_t queue;

public:
    uint32_t SjPacketId;

    /* variable to keep track of packet creation origins */
    source_t source;

    /* proto variable, redundant but useful because defined to permit OR masks */
    proto_t proto;

    /* morality of the packet: the goal and the nature */
    evilbit_t morality;

    /* status variable to force relative position of a packet with
       respect to an other. */
    position_t position;

    /* define the actual goal for the scrambles */
    judge_t wtf;

    /* specify which kind of scramble will be apply or has been apply */
    scrambleMask usedScramble;

    /* status variable for chained hack inherited on Packet(const Packet &).
       significative only if source == PLUGIN  */
    chaining_t chainflag;

    bool fragment;
    uint16_t fragFakeMTU;

    struct iphdr *ip;
    uint8_t iphdrlen; /* [20 - 60] bytes */
    unsigned char *ippayload;
    uint16_t ippayloadlen; /* [0 - 65515] bytes */

    union
    {
        struct tcphdr *tcp;
        struct udphdr *udp;
        struct icmphdr *icmp;
    };

    union
    {
        uint8_t tcphdrlen; /* [20 - 60] bytes */
        uint8_t udphdrlen; /* fixed: 8 bytes*/
        uint8_t icmphdrlen; /* fixed: 8 bytes*/
    };

    union
    {
        unsigned char *tcppayload;
        unsigned char *udppayload;
        unsigned char *icmppayload;
    };

    union
    {
        uint16_t tcppayloadlen; /* [0 - 65515] bytes */
        uint16_t udppayloadlen; /* [0 - 65527] bytes */
        uint16_t icmppayloadlen; /* [0 - 65527] bytes */
    };

    vector<unsigned char> pbuf;

    /* pkt creation from readed buffer */
    Packet(const unsigned char *, uint16_t);
    /* pkt creation from exisiting Packet object */
    Packet(const Packet &);
    /* pkt fragment creation from an existing packet */
    Packet(const Packet &, uint16_t, uint16_t, uint16_t);

    ~Packet();

    uint32_t maxMTU(void);
    uint32_t freespace(void);

    void updatePacketMetadata(uint16_t, uint16_t);

    /* IP/TCP checksum functions */
    uint32_t computeHalfSum(const unsigned char*, uint16_t);
    uint16_t computeSum(uint32_t);
    void fixIPSum(void);
    void fixIPTCPSum(void);
    void fixIPUDPSum(void);
    void fixSum(void);
    void corruptSum(void);

    /* autochecking */
    bool selfIntegrityCheck(const char *);

    /* functions required in TCP/IP packets forging */
    void randomizeID(void);
    void iphdrResize(uint8_t);
    void tcphdrResize(uint8_t);
    void ippayloadResize(uint16_t);
    void tcppayloadResize(uint16_t);
    void udppayloadResize(uint16_t);
    void ippayloadRandomFill(void);
    void tcppayloadRandomFill(void);
    void udppayloadRandomFill(void);
    void payloadRandomFill(void);

    /* utilities */
    void selflog(const char *, const char *, ...) const;
    const char *getWtfStr(judge_t) const;
    const char *getSourceStr(source_t) const;
    const char *getChainStr(chaining_t) const;
};

#endif /* SJ_PACKET_H */
