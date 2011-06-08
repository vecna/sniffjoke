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

#include "SniffJokeCli.h"
#include "service/internalProtocol.h"
#include "service/PortConf.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

SniffJokeCli::SniffJokeCli(const char* serveraddr, uint16_t serverport, uint32_t ms_timeout) :
serveraddr(serveraddr),
serverport(serverport),
ms_timeout(ms_timeout)
{
}

int32_t SniffJokeCli::send_command(const char *cmdstring)
{
    int sock;
    struct sockaddr_in service_sin; /* address of service */
    struct sockaddr_in from; /* address used for receiving data */
    int rlen, flagblock;

    /* Create a UNIX datagram socket for client */
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        fprintf(stderr, "FATAL: unable to open UDP socket for connect to SniffJoke service: %s", strerror(errno));
        return SJ_ERROR;
    }

    memset(&service_sin, 0x00, sizeof (service_sin));
    service_sin.sin_family = AF_INET;
    service_sin.sin_port = htons(serverport);

    if (!inet_aton(serveraddr, &service_sin.sin_addr))
    {
        fprintf(stderr, "FATAL: unable to accept hostname (%s): only IP address allow", serveraddr);
        return SJ_ERROR;
    }

    if (sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *) &service_sin, sizeof (service_sin)) == -1)
    {
        fprintf(stderr, "FATAL: unable to send message [%s] via %s:%d: %s",
                cmdstring, serveraddr, serverport, strerror(errno));
        return SJ_ERROR;
    }

    /* because we loop over the socket file description, is required a non blocking mode */
    flagblock = fcntl(sock, F_GETFL);
    if (fcntl(sock, F_SETFL, flagblock | O_NONBLOCK) == -1)
    {
        fprintf(stderr, "FATAL: unable to set non blocking mode in listening socket: %s", strerror(errno));
        fprintf(stderr, "anyway: the command has been sent to sniffjoke service, without error in sending");
        return SJ_ERROR;
    }

    /* poll is required for timeout pourpose checking, because only one file desciption is used */
    struct pollfd fd;
    fd.events = POLLIN;
    fd.fd = sock;

    int nfds = poll(&fd, 1, ms_timeout);

    if (nfds == 1)
    {
        /* the same size declared in io_buf SniffJoke.cc service */
        uint8_t received_data[HUGEBUF * 4] = {0};
        uint8_t received_buf[LARGEBUF] = {0};
        uint32_t progressive_recvl = 0;
        int fromlen = sizeof (struct sockaddr_in);

        do
        {
            memset(received_buf, 0x00, LARGEBUF);
            rlen = (recvfrom(sock, received_buf, LARGEBUF, MSG_WAITALL, (sockaddr*) & from, (socklen_t *) & fromlen));

            if (rlen == -1)
            {
                if (errno != EAGAIN)
                {
                    printf("unable to receive from local socket: %s\n", strerror(errno));
                    return SJ_ERROR;
                }
                break;
            }
            memcpy(&received_data[progressive_recvl], received_buf, rlen);
            progressive_recvl += rlen;
        }
        while (rlen > 0);

        if (!(parse_SjinternalProto(received_data, progressive_recvl)))
        {
            fprintf(stderr, "error in parsing received message\n");
            return SJ_ERROR;
        }
    }
    else
    {
        printf("connection timeout: SniffJoke is not running, or --timeout too low\n");
        return SJ_ERROR;
    }

    close(sock);
    return SJ_OK;
}

#define SPACESIZE   20

uint32_t SniffJokeCli::fillingSpaces(uint16_t p)
{
    char testingline[MEDIUMBUF] = {0};
    sprintf(testingline, "%d", p);

    return (SPACESIZE - strlen(testingline));
}

uint32_t SniffJokeCli::fillingSpace(uint16_t s, uint16_t e)
{
    char testingline[MEDIUMBUF] = {0};
    sprintf(testingline, "%d:%d", s, e);

    return (SPACESIZE - strlen(testingline));
}

void SniffJokeCli::resolveWeight(char *buf, size_t len, uint32_t weight)
{
    const struct mapTheKeys *mtk;
    uint32_t writtedLen = 0;

    memset(buf, 0x00, len);

    /* this is taken from portConfParsing.cc */
    const struct mapTheKeys mappedKeywords[] = {
        { AGG_RARE, AGG_N_RARE},
        { AGG_VERYRARE, AGG_N_VERYRARE},
        { AGG_COMMON, AGG_N_COMMON},
        { AGG_ALWAYS, AGG_N_ALWAYS},
        { AGG_PACKETS10PEEK, AGG_N_PACKETS10PEEK},
        { AGG_PACKETS30PEEK, AGG_N_PACKETS30PEEK},
        { AGG_TIMEBASED5S, AGG_N_TIMEBASED5S},
        { AGG_TIMEBASED20S, AGG_N_TIMEBASED20S},
        { AGG_STARTPEEK, AGG_N_STARTPEEK},
        { AGG_LONGPEEK, AGG_N_LONGPEEK},
        { AGG_NONE, AGG_N_NONE},
        { AGG_HEAVY, AGG_N_HEAVY},
        { 0, NULL}
    };

    for (mtk = &mappedKeywords[0]; mtk->value; mtk++)
    {
        if (weight & mtk->value)
        {
            if (writtedLen)
            {
                buf[writtedLen] = ',';
                writtedLen++;
            }

            snprintf(&buf[writtedLen], (len - writtedLen - 1), "%s", mtk->keyword);
            writtedLen = strlen(buf);
        }
    }
}

/* TODO in the stable release: implement a sort of cryptography, resolving issue of authentication */
bool SniffJokeCli::parse_SjinternalProto(uint8_t *recvd, uint32_t rcvdlen)
{
    struct command_ret blockInfo;

    /* first sanity check */
    if ((uint32_t) rcvdlen < sizeof (blockInfo))
        return false;

    memcpy(&blockInfo, (void *) recvd, sizeof (blockInfo));

    /* global transfert sanity check */
    if (blockInfo.cmd_len != (uint32_t) rcvdlen)
    {
        printf("invalid lenght (received %d, declared %d)\n", rcvdlen, blockInfo.cmd_len);
        return false;
    }

    switch (blockInfo.cmd_type)
    {
    case START_COMMAND_TYPE:
        printf("received (%d bytes) confirm of START command\n", rcvdlen);
        return printSJStat(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case STOP_COMMAND_TYPE:
        printf("received (%d bytes) confirm of STOP command\n", rcvdlen);
        return printSJStat(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case QUIT_COMMAND_TYPE:
        printf("received (%d bytes) confirm of QUIT command\n", rcvdlen);
        return printSJStat(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case STAT_COMMAND_TYPE:
        printf("received (%d bytes) confirm of STAT command\n", rcvdlen);
        return printSJStat(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case INFO_COMMAND_TYPE:
        printf("received (%d bytes) confirm of INFO command\n", rcvdlen);
        return printSJSessionInfo(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case LOGLEVEL_COMMAND_TYPE:
        printf("received (%d bytes) confirm of LOGLEVEL command\n", rcvdlen);
        return printSJStat(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case SAVECONF_COMMAND_TYPE:
        printf("received (%d bytes) confirm of SAVECONF command\n", rcvdlen);
        return printSJStat(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case SETPORT_COMMAND_TYPE:
        printf("received (%d bytes) SET PORT is read only at the moment!\n", rcvdlen);
        return printSJPort(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case SHOWPORT_COMMAND_TYPE:
        printf("received (%d bytes) confirm of SHOW PORT command\n", rcvdlen);
        return printSJPort(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case TTLMAP_COMMAND_TYPE:
        printf("received (%d bytes) confirm of TTL MAP command\n", rcvdlen);
        return printSJTTL(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    case COMMAND_ERROR_MSG:
        printf("received (%d bytes) error in command sent\n", rcvdlen);
        return printSJError(&recvd[sizeof (blockInfo)], rcvdlen - sizeof (blockInfo));
    default:
        printf("invalid command type %d ?\n", blockInfo.cmd_type);
    }
    return false;
}

/* this parse and print the data block exposed in SJ-PROTOCOL.txt:
                +--------+--------+---------+
                |  len 1 | who 1  | data 1  |
                +--------+--------+---------+
                ...
                +--------+--------+---------+
                |  len N | who N  | data N  |
                +--------+--------+---------+
 */
bool SniffJokeCli::printSJStat(const uint8_t *statblock, uint32_t blocklen)
{
    uint32_t parsedlen = 0;
    struct single_block *singleData;

    while (parsedlen < blocklen)
    {
        singleData = (struct single_block *) &statblock[parsedlen];
        void *pointed_data = (void *) &statblock[parsedlen + sizeof (struct single_block) ];

        /* this are the possibile used storave variables */
        bool boolvar = false;
        uint16_t intvar = 0;
        char charvar[MEDIUMBUF];
        memset(charvar, 0x00, MEDIUMBUF);
        /* starting the parsing of the blocks */

        switch (singleData->WHO)
        {
        case STAT_ACTIVE:
            boolvar = (bool)(*(uint8_t *) pointed_data);
            printf("SniffJoke\t\t%s\n", boolvar ? "running" : "not running");
            break;
        case STAT_LOCAT:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("location name:\t\t%s\n", charvar);
            break;
        case STAT_MACGW:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("gateway hw address:\t%s\n", charvar);
            break;
        case STAT_GWADDR:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("gateway IP address:\t%s\n", charvar);
            break;
        case STAT_NETIFACENAME:
            /* WARNING - REMIND: this name "hijacked interface" is grepped in sniffjoke-autotest */
            memcpy(&charvar, pointed_data, singleData->len);
            printf("hijacked interface:\t%s\n", charvar);
            break;
        case STAT_NETIFACEIP:
            /* WARNING: the following name, "hijacked interface etc..." MUST NOT COLLIDE with the grep */
            memcpy(&charvar, pointed_data, singleData->len);
            printf("hijacked local IPaddr:\t%s\n", charvar);
            break;
        case STAT_NETIFACEMTU:
            /* YEP, here too */
            memcpy(&intvar, pointed_data, singleData->len);
            printf("hijacked MTU interface:\t%d\n", intvar);
            break;
        case STAT_TUNIFACENAME:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("tunnel interface:\t%s\n", charvar);
            break;
        case STAT_TUNIFACEIP:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("tunnel local IPaddr:\t%s\n", charvar);
            break;
        case STAT_TUNIFACEMTU:
            memcpy(&intvar, pointed_data, singleData->len);
            printf("tunnel MTU interface:\t%d\n", intvar);
            break;
        case STAT_DEBUGL:
            memcpy(&intvar, pointed_data, singleData->len);
            printf("debug level:\t\t%d\n", intvar);
            break;
        case STAT_BINDA:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("admin address:\t\t%s\n", charvar);
            break;
        case STAT_BINDP:
            memcpy(&intvar, pointed_data, singleData->len);
            printf("admin UDP port:\t\t%d\n", intvar);
            break;
        case STAT_USER:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("running user:\t\t%s\n", charvar);
            break;
        case STAT_GROUP:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("running group:\t\t%s\n", charvar);
            break;
        case STAT_CHAINING:
            boolvar = (bool)(*(uint8_t *) pointed_data);
            printf("hack chaining:\t\t%s\n", boolvar ? "enabled" : "disabled");
            break;
        case STAT_NO_TCP:
            boolvar = (bool)(*(uint8_t *) pointed_data);
            printf("tcp mangling:\t\t%s\n", boolvar ? "disabled" : "enabled");
            break;
        case STAT_NO_UDP:
            boolvar = (bool)(*(uint8_t *) pointed_data);
            printf("udp mangling:\t\t%s\n", boolvar ? "disabled" : "enabled");
            break;
        case STAT_WHITELIST:
            boolvar = (bool)(*(uint8_t *) pointed_data);
            printf("whitelist mode:\t\t%s\n", boolvar ? "enabled" : "disabled");
            break;
        case STAT_BLACKLIST:
            boolvar = (bool)(*(uint8_t *) pointed_data);
            printf("blacklist mode:\t\t%s\n", boolvar ? "enabled" : "disabled");
            break;
        case STAT_ONLYP:
            memcpy(&charvar, pointed_data, singleData->len);
            printf("single plugin:\t\t%s\n", charvar);
            break;
        default:
            break;
        }
        parsedlen += (singleData->len + sizeof (struct single_block));
    }
    return true;
}

bool SniffJokeCli::printSJSessionInfo(const uint8_t *received, uint32_t rcvdlen)
{
    struct sex_record *sr;
    uint32_t cnt = 1, i = 0;

    while (i < rcvdlen)
    {
        sr = (struct sex_record *) &received[i];
        printf(" %02d) %s %u -> %s:%u #%d (injected %d)\n",
               cnt, sr->proto == IPPROTO_TCP ? "TCP" : "UDP", ntohs(sr->sport),
               inet_ntoa(*((struct in_addr *) &(sr->daddr))),
               ntohs(sr->dport), sr->packet_number, sr->injected_pktnumber
               );
        cnt++;
        i += sizeof (struct sex_record);
    }

    if (!i)
    {
        printf("no sessions appear tracked at the moment\n");
    }

    return true;
}

bool SniffJokeCli::printSJTTL(const uint8_t *received, uint32_t rcvdlen)
{
    struct ttl_record *tr;
    uint32_t cnt = 1, i = 0;

    struct tm *tm;
    char access[SMALLBUF] = {0};
    char nextprobe[SMALLBUF] = {0};

    while (i < rcvdlen)
    {
        tr = (struct ttl_record *) &received[i];

        tm = localtime(&tr->access);
        strftime(access, SMALLBUF, "%d %H:%M:%S", tm);

        tm = localtime(&tr->nextprobe);
        strftime(nextprobe, SMALLBUF, "%d %H:%M:%S", tm);

        printf(" %02d) %s [%s %s] sent #%d recv #%d incoming TTL (%d) ext hop dist %d\n",
               cnt,
               inet_ntoa(*((struct in_addr *) &(tr->daddr))),
               access, nextprobe,
               tr->sentprobe, tr->receivedprobe, tr->synackval, tr->ttlestimate
               );
        cnt++;
        i += sizeof (struct ttl_record);
    }

    if (!i)
    {
        printf("no hosts appear hop-mapped at the moment\n");
    }

    return true;
}

bool SniffJokeCli::printSJPort(const uint8_t *statblock, uint32_t blocklen)
{
    char resolvedInfo[MEDIUMBUF];

    /* the first goal is to detect the de-facto default in your conf */
    uint16_t mostValue = AGG_NONE;
    uint16_t checkingValue = AGG_NONE;
    uint16_t occurrence = 0;

    do
    {
        uint16_t checking_occ = 0;

        for (uint32_t parsedlen = 0; parsedlen < blocklen; parsedlen += sizeof (struct port_info))
        {
            struct port_info *pInfo = (struct port_info *) &statblock[parsedlen];

            if (checkingValue == pInfo->weight)
                checking_occ++;
        }

        if (checking_occ > occurrence)
        {
            mostValue = checkingValue;
            occurrence = checking_occ;
        }

        checkingValue *= 2;
    }
    while (checkingValue <= AGG_LONGPEEK);

    for (uint32_t parsedlen = 0; parsedlen < blocklen; parsedlen += sizeof (struct port_info))
    {
        struct port_info *pInfo = (struct port_info *) &statblock[parsedlen];

        if (pInfo->weight == mostValue)
            continue;

        resolveWeight(resolvedInfo, sizeof (resolvedInfo), pInfo->weight);

        if (pInfo->start == pInfo->end)
        {
            printf("%d%*s%s\n", pInfo->start, fillingSpaces(pInfo->start), " ", resolvedInfo);
        }
        else
        {
            printf("%d:%d%*s%s\n", pInfo->start, pInfo->end, fillingSpace(pInfo->start, pInfo->end), " ", resolvedInfo);
        }
    }

    resolveWeight(resolvedInfo, sizeof (resolvedInfo), mostValue);
    printf("omitted rule from the list is %s and apply to all ports not present on the list\n", resolvedInfo);
    return true;
}

bool SniffJokeCli::printSJError(const uint8_t *statblock, uint32_t blocklen)
{
    printf("error - not implemented the parsing of an error - ATM\n");

    return true;
}
