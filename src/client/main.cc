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

#include <cstdlib>
#include <cstring>

#include <getopt.h>
#include <stdint.h>

using namespace std;

static void sjcli_version(const char *pname)
{
    printf("%s: %s\n", pname, SJCTL_VERSION);
}

#define SNIFFJOKECLI_HELP_FORMAT \
	"Usage: %s [OPTIONS]... [COMMANDS]...\n"\
	" --address <ip>[:port]\tspecify administration IP address [default: %s:%d]\n"\
	" --version\t\tshow sniffjoke version\n"\
	" --timeout\t\tset milliseconds timeout when contacting SniffJoke service [default: %d]\n"\
	" --help\t\t\tshow this help\n\n"\
	"when sniffjoke is running, you should send commands with a command line argument:\n"\
	" start\t\t\tstart sniffjoke hijacking/injection\n"\
	" stop\t\t\tpause sniffjoke\n"\
	" quit\t\t\tquit sniffjoke\n"\
	" saveconf\t\tdump configuration file\n"\
	" stat\t\t\tget statistics about sniffjoke configuration and network\n"\
	" info\t\t\tget statistics about sniffjoke active sessions\n"\
	" ttlmap\t\t\tshow the mapped hop count for destination\n"\
	" showport\t\tshow the running port-aggressivity configuration\n"\
	" set start:end value\tset the injection's strogness over selected port [not supported!]\n"\
    "\t\tneed to be set in port-aggressivity.conf\n"\
	" debug\t\t\t[%d-%d] change the log debug level\n\n"\
	"\t\t\thttp://www.delirandom.net/sniffjoke\n"

static void sjcli_help(const char *pname)
{
    printf(SNIFFJOKECLI_HELP_FORMAT,
           pname,
           DEFAULT_ADMIN_ADDRESS, DEFAULT_ADMIN_PORT,
           SJCTL_DEFAULT_TIMEOUT,
           SUPPRESS_LEVEL, PACKET_LEVEL
           );
}

/* return false on error in parsing or when command is not present */
static bool parse_command(char **av, uint32_t ac, struct command *sjcmdlist, char *retcmd)
{
    for (uint32_t i = 0; i < ac; ++i)
    {
        struct command *ptr;
        for (ptr = &sjcmdlist[0]; ptr->cmd != NULL; ++ptr)
        {
            if (!strcmp(ptr->cmd, av[i]))
            {
                size_t usedlen = 0;
                snprintf(retcmd, 256, "%s", ptr->cmd);
                if (ptr->related_args + i > ac)
                    return false;
                while (--(ptr->related_args))
                {
                    usedlen = strlen(retcmd);
                    snprintf(&retcmd[usedlen], 256 - usedlen, " %s", av[++i]);
                }
                return true;
            }
        }
    }
    return false;
}

int main(int argc, char **argv)
{

    struct sjcli_cmdline_opts
    {
        char admin_address[256];
        uint16_t admin_port;
        uint32_t ms_timeout;
        char cmd_buffer[256];
    } useropt;

    memset(&useropt, 0x00, sizeof (useropt));
    /* setting the default defined in SniffJokeCli.h */
    snprintf(useropt.admin_address, sizeof (useropt.admin_address), DEFAULT_ADMIN_ADDRESS);
    useropt.admin_port = DEFAULT_ADMIN_PORT;
    useropt.ms_timeout = SJCTL_DEFAULT_TIMEOUT;

    struct command sjcli_command[] = {
        { "start", 1},
        { "stop", 1},
        { "quit", 1},
        { "saveconf", 1},
        { "info", 1},
        { "ttlmap", 1},
        { "stat", 1},
        { "showport", 1},
        { "set", 3},
        { "clear", 1},
        { "debug", 2},
        { NULL, 0}
    };

    if (!parse_command(argv, argc, sjcli_command, useropt.cmd_buffer))
    {
        sjcli_help(argv[0]);
        return -1;
    }

    struct option sjcli_option[] = {
        { "address", required_argument, NULL, 'a'},
        { "timeout", required_argument, NULL, 't'},
        { "version", no_argument, NULL, 'v'},
        { "help", no_argument, NULL, 'h'},
        { NULL, 0, NULL, 0}
    };

    int charopt;
    while ((charopt = getopt_long(argc, argv, "c:a:t:vh", sjcli_option, NULL)) != -1)
    {
        switch (charopt)
        {
        case 'c':
            snprintf(useropt.cmd_buffer, sizeof (useropt.cmd_buffer), "%s", optarg);
            break;
        case 'a':
            snprintf(useropt.admin_address, sizeof (useropt.admin_address), "%s", optarg);
            char* port;
            if ((port = strchr(useropt.admin_address, ':')) != NULL)
            {
                *port = 0x00;
                int checked_port = atoi(++port);

                if (checked_port > 65535 || checked_port < 0)
                    goto sniffjokecli_help;

                useropt.admin_port = (uint16_t) checked_port;
            }
            break;
        case 't':
            useropt.ms_timeout = atoi(optarg);
            break;
        case 'v':
            sjcli_version(argv[0]);
            return 0;
sniffjokecli_help:
        case 'h':
        default:
            sjcli_help(argv[0]);
            return -1;

            argc -= optind;
            argv += optind;
        }
    }

    SniffJokeCli cli(useropt.admin_address, useropt.admin_port, useropt.ms_timeout);
    return cli.send_command(useropt.cmd_buffer);
}
