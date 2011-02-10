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

#include "service/Utils.h"
#include "SniffJokeCli.h"
#include "service/internalProtocol.h"
#include "service/portConfParsing.h"

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

#include <cstdlib>

SniffJokeCli::SniffJokeCli(char* serveraddr, uint16_t serverport, uint32_t ms_timeout) :
	serveraddr(serveraddr),
	serverport(serverport),
	ms_timeout(ms_timeout)
{
}

void SniffJokeCli::send_command(const char *cmdstring)
{
	int sock;
	struct sockaddr_in service_sin;	/* address of service */
	struct sockaddr_in from;	/* address used for receiving data */
	int rlen, flagblock;

	/* Create a UNIX datagram socket for client */
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		fprintf(stderr, "FATAL: unable to open UDP socket for connect to SniffJoke service: %s", strerror(errno));
		return;
	}

	memset(&service_sin, 0x00, sizeof(service_sin));
	service_sin.sin_family = AF_INET;
	service_sin.sin_port = htons(serverport);

	if (!inet_aton(serveraddr, &service_sin.sin_addr)) {
		fprintf(stderr, "Unable to accept hostname (%s): only IP address allow", serveraddr);
		return;
	}

	if (sendto(sock, cmdstring, strlen(cmdstring), 0, (const struct sockaddr *)&service_sin, sizeof(service_sin)) == -1) 
	{
		fprintf(stderr, 
			"FATAL: unable to send message [%s] via %s:%d: %s", 
			cmdstring, serveraddr, serverport, strerror(errno));
		return;
	}

    /* because we loop over the socket file description, is required a non blocking mode */
    flagblock = fcntl(sock, F_GETFL);
    if (fcntl(sock, F_SETFL, flagblock | O_NONBLOCK) == -1) {
		fprintf(stderr, "FATAL: unable to set non blocking mode in listening socket: %s", strerror(errno));
        fprintf(stderr, "anyway: the command has been sent to sniffjoke service, without error in sending");
		return;
    }


    /* poll is required for timeout pourpose checking, because only one file desciption is used */
    struct pollfd fd;
    fd.events = POLLIN;
    fd.fd = sock;

	int nfds = poll(&fd, 1, ms_timeout);

	if(nfds == 1) 
	{
		uint8_t received_data[HUGEBUF];
        uint8_t received_buf[LARGEBUF];
        uint32_t progressive_recvl = 0;
		memset(received_data, 0x00, HUGEBUF);
		int fromlen = sizeof(struct sockaddr_in);

        do {
            memset(received_buf, 0x00, LARGEBUF);
		    rlen = (recvfrom(sock, received_buf, LARGEBUF, MSG_WAITALL, (sockaddr*)&from, (socklen_t *)&fromlen));

            if(rlen == -1) 
            {
                if( errno != EAGAIN) 
                {
                    printf("unable to receive from local socket: %s\n", strerror(errno));
                    return;
                }
                break;
		    }
            memcpy(&received_data[progressive_recvl], received_buf, rlen);
            progressive_recvl += rlen;
        }
        while(rlen > 0);

	    if(!(parse_SjinternalProto(received_data, progressive_recvl))) {
			fprintf(stderr, "error in parsing received message\n");
		}
	} else {
		printf("Connection timeout: SniffJoke is not running, or --timeout too low\n");
	}

	close(sock);
}

/* TODO in the stable release: implement a sort of cryptography, resolving issue of authentication */
bool SniffJokeCli::parse_SjinternalProto(uint8_t *recvd, int32_t rcvdlen)
{
	struct command_ret blockInfo;

	/* first sanity check */
	if( (uint32_t)rcvdlen < sizeof(blockInfo) )
		return false;

	memcpy(&blockInfo, (void *)recvd, sizeof(blockInfo));

	/* global transfert sanity check */
	if(blockInfo.cmd_len !=  (uint32_t)rcvdlen) 
    {
        printf("invalid lenght (received %d, declared %d)\n", rcvdlen, blockInfo.cmd_len);
		return false;
    }

	switch(blockInfo.cmd_type) 
	{
		case START_COMMAND_TYPE:
            printf("received (%d bytes) confirm of START command\n", rcvdlen);
			return printSJStat(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case STOP_COMMAND_TYPE:
            printf("received (%d bytes) confirm of STOP command\n", rcvdlen);
			return printSJStat(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case QUIT_COMMAND_TYPE:
            printf("received (%d bytes) confirm of QUIT command\n", rcvdlen);
			return printSJStat(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case STAT_COMMAND_TYPE:
            printf("received (%d bytes) confirm of STAT command\n", rcvdlen);
			return printSJStat(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case INFO_COMMAND_TYPE:
            printf("received (%d bytes) confirm of INFO command\n", rcvdlen);
			return printSJSessionInfo(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case LOGLEVEL_COMMAND_TYPE:
            printf("received (%d bytes) confirm of LOGLEVEL command\n", rcvdlen);
			return printSJStat(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case SAVECONF_COMMAND_TYPE:
            printf("received (%d bytes) confirm of SAVECONF command\n", rcvdlen);
			return printSJStat(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case SETPORT_COMMAND_TYPE:
            printf("received (%d bytes) confirm of SET PORT command\n", rcvdlen);
			return printSJPort(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case SHOWPORT_COMMAND_TYPE:
            printf("received (%d bytes) confirm of SHOW PORT command\n", rcvdlen);
			return printSJPort(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case COMMAND_ERROR_MSG:
            printf("received (%d bytes) error in command sent\n", rcvdlen);
			return printSJError(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
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
bool SniffJokeCli::printSJStat(uint8_t *statblock, int32_t blocklen)
{
	int32_t parsedlen = 0;
    struct single_block *singleData;

	while( parsedlen < blocklen ) 
	{
        singleData = (struct single_block *)&statblock[parsedlen];
		void *pointed_data = (void *)&statblock[parsedlen + sizeof(struct single_block)];

        /* this are the possibile used storave variables */
		bool boolvar = false;
		uint16_t intvar = 0;
		char charvar[MEDIUMBUF];
		memset(charvar, 0x00, MEDIUMBUF);
        /* starting the parsing of the blocks */

		switch(singleData->WHO)
		{
			case STAT_ACTIVE:
				boolvar = (bool)(*(uint8_t *)pointed_data);
				printf("SniffJoke\t\t%s\n", boolvar ? "running" : "not running");
				break;
			case STAT_MACGW:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("gateway hw address:\t%s\n", charvar);
				break;
			case STAT_GWADDR:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("gateway IP address:\t%s\n", charvar);
				break;
			case STAT_IFACE:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("hijacked interface:\t%s\n", charvar);
				break;
			case STAT_LOIP:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("Sj's tunnel IP address:\t%s\n", charvar);
				break;
			case STAT_TUNN:
				memcpy(&intvar, pointed_data, singleData->len);
				printf("tunnel iface number:\t%d\n", intvar);
				break;
			case STAT_DEBUGL:
				memcpy(&intvar, pointed_data, singleData->len);
				printf("debug level:\t\t%d\n", intvar);
				break;
			case STAT_LOGFN:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("log filename:\t%s\n", charvar);
				break;
			case STAT_CHROOT:
            /* not useful ATM */ 
				memcpy(&charvar, pointed_data, singleData->len);
				printf("base directory:\t\t%s\n", charvar);
				break;
            /* not more present in the sj_config */
			case STAT_ENABLR:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("enabler file:\t%s\n", charvar);
				break;
			case STAT_LOCAT:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("location name:\t\t%s\n", charvar);
				break;
			case STAT_ONLYP:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("single plugin:\t\t%s\n", charvar);
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
				printf("dedicated user:\t\t%s\n", charvar);
				break;
			case STAT_GROUP:
				memcpy(&charvar, pointed_data, singleData->len);
				printf("dedicated group:\t%s\n", charvar);
				break;
			default:
				break;
		}
		parsedlen += (singleData->len + sizeof(struct single_block));
	}
	return true;
}

bool SniffJokeCli::printSJSessionInfo(uint8_t *received, uint32_t rcvdlen)
{
    struct sex_record *sr;
    uint32_t cnt = 1, i = 0;

    while(i < rcvdlen)
    {
        sr = (struct sex_record *)&received[i];
        printf(" %02d) %u -> %s:%u #%d (injected %d)\n", 
            cnt, ntohs(sr->sport), 
            inet_ntoa(*((struct in_addr *) &(sr->daddr))), 
            ntohs(sr->dport), sr->packet_number, sr->injected_pktnumber
        );
        cnt++;
        i += sizeof(struct sex_record);
    }

    if(!i)
    {
        printf("none Session appears to be tracked at the moment\n");
    }

    return true;
}

#define SPACESIZE   20
char *SniffJokeCli::fillWithSpace(uint16_t p)
{
    static char spaces[MEDIUMBUF];
    char testingline[MEDIUMBUF];

    memset(testingline, 0x00, MEDIUMBUF);
    memset(spaces, 0x00, MEDIUMBUF);

    sprintf(testingline, "%d", p);

    for(uint32_t i = strlen(testingline); i < SPACESIZE; i++)
        spaces[ i - strlen(testingline) ] = ' ';

    return &spaces[0];
}

char *SniffJokeCli::fillWithSpace(uint16_t s, uint16_t e)
{
    static char spaces[MEDIUMBUF];
    char testingline[MEDIUMBUF];

    memset(testingline, 0x00, MEDIUMBUF);
    memset(spaces, 0x00, MEDIUMBUF);

    sprintf(testingline, "%d:%d", s, e);

    for(uint32_t i = strlen(testingline); i < SPACESIZE; i++)
        spaces[ i - strlen(testingline) ] = ' ';

    return &spaces[0];
}

char *SniffJokeCli::resolve_weight(uint32_t weight)
{
    static char resolvedInfo[MEDIUMBUF];
    const struct mapTheKeys *mtk;
    uint32_t writtedLen = 0;

    memset(&resolvedInfo, 0x00, MEDIUMBUF);

    /* this is taken from portConfParsing.cc */
    const struct mapTheKeys mappedKeywords[] = {
        { AGG_RARE, AGG_N_RARE },
        { AGG_COMMON, AGG_N_COMMON },
        { AGG_ALWAYS, AGG_N_ALWAYS },
        { AGG_PACKETS10PEEK, AGG_N_PACKETS10PEEK },
        { AGG_PACKETS30PEEK, AGG_N_PACKETS30PEEK },
        { AGG_TIMEBASED5S, AGG_N_TIMEBASED5S },
        { AGG_TIMEBASED20S, AGG_N_TIMEBASED20S },
        { AGG_STARTPEEK, AGG_N_STARTPEEK },
        { AGG_LONGPEEK, AGG_N_LONGPEEK },
        { FREQ_NONE, FREQ_N_NONE },
        { FREQ_LIGHT, FREQ_N_LIGHT },
        { FREQ_NORMAL, FREQ_N_NORMAL },
        { FREQ_HEAVY, FREQ_N_HEAVY },
        { 0, NULL }
    };

    for(mtk = &mappedKeywords[0]; mtk->value; mtk++)
    {
        if(weight & mtk->value) 
        {
            if(writtedLen)
            {
                resolvedInfo[writtedLen] = ',';
                writtedLen++;
            }

            snprintf(&resolvedInfo[writtedLen], (MEDIUMBUF - writtedLen -1), "%s", mtk->keyword);
            writtedLen = strlen(resolvedInfo);
        }
    }

    return &resolvedInfo[0];
}

bool SniffJokeCli::printSJPort(uint8_t *statblock, int32_t blocklen)
{
	int32_t parsedlen = 0;

	while( parsedlen < blocklen ) 
	{
        struct port_info *pInfo = (struct port_info *)&statblock[parsedlen];

        if(pInfo->start == pInfo->end)
        {
            printf("%d%s%s\n", pInfo->start, fillWithSpace(pInfo->start), resolve_weight(pInfo->weight));
        }
        else
        {
            printf("%d:%d%s%s\n", pInfo->start, pInfo->end, fillWithSpace(pInfo->start, pInfo->end), resolve_weight(pInfo->weight));
        }

        parsedlen += sizeof(struct port_info);
    }

	return true;
}

bool SniffJokeCli::printSJError(uint8_t *statblock, int32_t blocklen)
{
	printf("error - not implemented the parsing of an error - ATM\n");

	return true;
}
