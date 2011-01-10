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

#include "SniffJokeCli.h"

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
	char rcv_buf[4096];
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
		memset(rcv_buf, 0x00, sizeof(rcv_buf));
		int fromlen = sizeof(struct sockaddr_in);

		if ((rlen = (recvfrom(sock, rcv_buf, sizeof(rcv_buf), MSG_WAITALL, (sockaddr*)&from, (socklen_t *)&fromlen))) == -1) {
			printf("unable to receive from local socket: %s\n", strerror(errno));
		}

		if (rlen == 0) {
			fprintf(stderr, 
				"[%s] command produces no answer. Verify sniffjoke is running and your command line\n",
				cmdstring);
		}
		else {
			parse_SjinternalProto(rcv_buf, rlen);
		}
	} else {
		printf("Connection timeout: SniffJoke is not running, or --timeout too low\n");
	}

	close(sock);
}
void SniffJokeCli::parse_SjinternalProto(char *rcv, uint32_t rlen)
{
	int i;
	for(i = 0; i < rlen; i++)
		printf("%02x ", rcv[i]);
}

#if 0
parse_SjinternalProto {

     snprintf(io_buf, sizeof(io_buf), 
                "\nsniffjoke status:\t\t%s\n" \
                "gateway mac address:\t\t%s\n" \
                "gateway ip address:\t\t%s\n" \
                "local interface:\t\t%s\n" \
                "local ip address:\t\t%s\n" \
                "dynamic tunnel interface:\ttun%d\n" \
                "log level:\t\t\t%d at file %s\n" \
                "chroot directory:\t\t%s\n",
        runconfig.active == true ? "ACTIVE" : "PASSIVE",
        runconfig.gw_mac_str, runconfig.gw_ip_addr,
        runconfig.interface, runconfig.local_ip_addr, runconfig.tun_number,
        runconfig.debug_level, runconfig.logfname, runconfig.chroot_dir)

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
#endif
