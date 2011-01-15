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
	int rlen;

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

        struct pollfd fd;
        fd.events = POLLIN;
        fd.fd = sock;

	int nfds = poll(&fd, 1, ms_timeout);

	if(nfds == 1) 
	{
		uint8_t rcv_buf[HUGEBUF];
		memset(rcv_buf, 0x00, sizeof(rcv_buf));
		int fromlen = sizeof(struct sockaddr_in);

		/* TODO: make a loop until the size don't become -1 */
		if ((rlen = (recvfrom(sock, rcv_buf, sizeof(rcv_buf), MSG_WAITALL, (sockaddr*)&from, (socklen_t *)&fromlen))) == -1) {
			printf("unable to receive from local socket: %s\n", strerror(errno));
		}

		if (rlen == 0) {
			fprintf(stderr, 
				"[%s] command produces no answer. Verify sniffjoke is running and your command line\n",
				cmdstring);
		}
		else {
			if(!(parse_SjinternalProto(rcv_buf, rlen))) {
				fprintf(stderr, "error in parsing received message\n");
			}
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
	if(blockInfo.len !=  (uint32_t)rcvdlen)
		return false;

	switch(blockInfo.command_type) 
	{
		case START_COMMAND_TYPE:
		case STOP_COMMAND_TYPE:
		case QUIT_COMMAND_TYPE:
		case STAT_COMMAND_TYPE:
		case INFO_COMMAND_TYPE: /* tmp, INFO need to be other */
		case LOGLEVEL_COMMAND_TYPE:
			return printSJStat(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case DUMP_COMMAND_TYPE:
			printf("not more supported! delete in the next repository sync");
			return false;
		case SETPORT_COMMAND_TYPE:
		case SHOWPORT_COMMAND_TYPE:
			return printSJPort(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		case COMMAND_ERROR_MSG:
			return printSJError(&recvd[sizeof(blockInfo)], rcvdlen - sizeof(blockInfo));
		default:
			printf("invalid command type %d ?\n", blockInfo.command_type);
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
	struct command_ret *cast_cmdr;
	int32_t parsedlen = 0;

	while( parsedlen < blocklen ) 
	{
		/* struct command_ret { uint32_t len; uint8_t command_type } */
	 	cast_cmdr = (struct command_ret *)&statblock[parsedlen];
		void *p = (void *)&statblock[parsedlen + 2];

		/* init to 0 the buffer to use for I/O */
		bool boolvar = false;
		char charvar[MEDIUMBUF];
		uint16_t intvar = 0;
		memset(charvar, 0x00, MEDIUMBUF);

		switch(cast_cmdr->command_type)
		{
			case STAT_ACTIVE:
				boolvar = (bool)(*(uint8_t *)p);
				printf("SniffJoke %s\n", boolvar ? "running" : "not running");
				break;
			case STAT_MACGW:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("gw mac address:\t%s\n", charvar);
				break;
			case STAT_GWADDR:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("gw IP address:\t%s\n", charvar);
				break;
			case STAT_IFACE:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("hijacked interface:\t%s\n", charvar);
				break;
			case STAT_LOIP:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("gw fake IP used:\t%s\n", charvar);
				break;
			case STAT_TUNN:
				intvar = *(uint16_t *)p;
				printf("tunnel interface number:\t%d\n", intvar);
				break;
			case STAT_DEBUGL:
				intvar = *(uint16_t *)p;
				printf("debug level:\t%d\n", intvar);
				break;
			case STAT_LOGFN:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("log filename:\t%s\n", charvar);
				break;
			case STAT_CHROOT:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("chroot dir:\t%s\n", charvar);
				break;
			case STAT_ENABLR:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("enabler file:\t%s\n", charvar);
				break;
			case STAT_LOCAT:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("location name:\t%s\n", charvar);
				break;
			case STAT_ONLYP:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("single plugin:\t%s\n", charvar);
				break;
			case STAT_BINDA:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("admin address:\t%s\n", charvar);
				break;
			case STAT_BINDP:
				intvar = *(uint16_t *)p;
				printf("admin UDP port:\t%d\n", intvar);
				break;
			case STAT_USER:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("dedicated user:\t%s\n", charvar);
				break;
			case STAT_GROUP:
				memcpy(&charvar, p, cast_cmdr->len);
				printf("dedicated group:\t%s\n", charvar);
				break;
			default:
				break;
		}
		parsedlen += (cast_cmdr->len + 2);
	}
	return true;
}

bool SniffJokeCli::printSJPort(uint8_t *statblock, int32_t blocklen)
{
	printf("y\n");
	return true;
}

bool SniffJokeCli::printSJError(uint8_t *statblock, int32_t blocklen)
{
	printf("x\n");
	return true;
}

/*
      switch(what) {
                case HEAVY: what_weightness = "heavy"; break;
                case NORMAL: what_weightness = "normal"; break;
                case LIGHT: what_weightness = "light"; break;
                case NONE: what_weightness = "no hacking"; break;
                default:
                        debug.log(ALL_LEVEL, "%s: invalid strength code for TCP ports");
                        debug.log(ALL_LEVEL, "BAD ERROR: %s", io_buf);
                        return;
        }
}

bool UserConf::parse_port_weight(char *weightstr, Strength *value)
{
        struct parsedata {
                const char *keyword;
                const int keylen;
                Strength equiv;
        };

#define keywordToParse  4

        struct parsedata wParse[] = {
                { "none",       strlen("none"),         NONE },
                { "light",      strlen("light"),        LIGHT },
                { "normal",     strlen("normal"),       NORMAL },
                { "heavy",      strlen("heavy"),        HEAVY }
        };

        for(uint8_t i = 0; i < keywordToParse; ++i) {
                if (!strncasecmp(weightstr, wParse[i].keyword, wParse[i].keylen)) {
                        *value = wParse[i].equiv;
                        return true;
                }
        }

        return false;
}
*/
