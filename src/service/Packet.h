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

#ifndef SJ_PACKET_H
#define SJ_PACKET_H

#include "Utils.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

using namespace std;

/* IT'S FUNDAMENTAL TO HAVE ALL ENUMS VALUES AS POWERS OF TWO TO PERMIT OR MASKS */

/* queue_t is a a reflection variable used by packet to know in what queue it's inserted */
enum queue_t
{
    QUEUEUNASSIGNED = 0, YOUNG = 1, KEEP = 2, HACK = 4, SEND = 8
};

/* if the packet is inject from sniffjoke is marked with the evilbit */
enum evilbit_t
{
    MORALITYUNASSIGNED = 0, GOOD = 1, EVIL = 2
};

/* the source_t is the nature of the packet, ANY_SOURCE is used at catch-all */
enum source_t
{
    SOURCEUNASSIGNED = 0, TUNNEL = 1, NETWORK = 2, LOCAL = 4, TTLBFORCE = 8
};

/* Every sniffjoke packet is based on be discarged from the remote host and accepted from
 * the sniffer, in order to obtain the sniffer tracking poisoning, those marker mean if the
 * packet need to be plain and correct (INNOCENT) to expire prematurely (PRESCRIPTION) to be 
 * consider bad and discarged (GUILTY, corrupt the TCP checksum), MALFORMED (weird ip options)
 * or a random choose of those */
enum judge_t
{
    JUDGEUNASSIGNED = 0, INNOCENT = 1, PRESCRIPTION = 2, GUILTY = 4, MALFORMED = 8
};

/* an enum for the proto. ANY_PROTO is the catch-all used when the queue(s) are queryed */
enum proto_t
{
    PROTOUNASSIGNED = 0, TCP = 1, UDP = 2, ICMP = 4, OTHER_IP = 8
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
    static uint32_t SjPacketIdCounter;

    queue_t queue;
    Packet *prev;
    Packet *next;
    friend class PacketQueue;

public:
    uint32_t SjPacketId;
    evilbit_t evilbit;
    source_t source;
    proto_t proto;
    position_t position;

    /* this is what the hack has decided to do,
     * had choosed between the Hack.avaialableScramble */
    judge_t wtf;
    /* this is what's the packet will accept if the 'wtf'
     * will not be used, (rarely will happen) */
    uint8_t choosableScramble;

    /* a Packet created from a Packet inheriet the chainflag */
    chaining_t chainflag;

    vector<unsigned char> pbuf;

    struct iphdr *ip;
    uint8_t iphdrlen; /* [20 - 60] bytes */
    unsigned char *ippayload;
    uint16_t ippayloadlen; /* [0 - 65515] bytes */

    bool fragment;

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
        unsigned char *icmppayload; /* always NULL */
    };

    union
    {
        uint16_t tcppayloadlen; /* [0 - 65515] bytes */
        uint16_t udppayloadlen; /* [0 - 65527] bytes */
        uint16_t icmppayloadlen; /* always 0 */
    };

    Packet(const unsigned char *, uint16_t);
    Packet(const Packet &);

    void updatePacketMetadata(void);

    void mark(source_t, evilbit_t);
    void mark(source_t, evilbit_t, judge_t);

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

    /* MALFORMED hacks and distortion of INNOCENT packets */
    bool injectIPOpts(bool, bool);
    bool injectTCPOpts(bool, bool);

    /* utilities */
    void selflog(const char *, const char *, ...) const;
};

/* definition for service Aggressiviy, or-red in a 16 bit field 
 * the Frequency meaning is explained in http://www.delirandom.net/sniffjoke/plugin 
 * they are put here because Packet.h is included in UserConf.h via SessionTrack.h
 * and are used in TCPTrack.cc too. whenever the parsing methodology implemented in 
 * UserConf about the tcp-port files change, those define should be revised */
#define AGG_NONE            1
#define AGG_N_NONE          "NONE"
#define AGG_VERYRARE        2
#define AGG_N_VERYRARE      "VERYRARE"
#define AGG_RARE            4
#define AGG_N_RARE          "RARE"
#define AGG_COMMON          8
#define AGG_N_COMMON        "COMMON"
#define AGG_HEAVY           16 
#define AGG_N_HEAVY         "HEAVY"
#define AGG_ALWAYS          32
#define AGG_N_ALWAYS        "ALWAYS"
#define AGG_PACKETS10PEEK   64
#define AGG_N_PACKETS10PEEK "PEEK10PKT"
#define AGG_PACKETS30PEEK   128
#define AGG_N_PACKETS30PEEK "PEEK30PKT"
#define AGG_TIMEBASED5S     256
#define AGG_N_TIMEBASED5S   "EVERY5SECONDS"
#define AGG_TIMEBASED20S    512
#define AGG_N_TIMEBASED20S  "EVERY20SECONDS"
#define AGG_STARTPEEK       1024
#define AGG_N_STARTPEEK     "PEEKATSTART"
#define AGG_LONGPEEK        2048
#define AGG_N_LONGPEEK      "LONGPEEK"


#endif /* SJ_PACKET_H */
