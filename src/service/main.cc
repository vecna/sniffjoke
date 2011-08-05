/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011, 2010 vecna <vecna@delirandom.net>
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

#include "Utils.h"
#include "UserConf.h"
#include "SniffJoke.h"

#include <getopt.h>
#include <stdint.h>

/* defined here, is needed by SniffJoke.cc */
void sigtrap(int signal)
{
    event_loopbreak();
}

static void sj_version(const char *pname)
{
    printf("%s %s\n", SW_NAME, SW_VERSION);
}

#define SNIFFJOKE_HELP_FORMAT \
    "Usage: %s [OPTION]... :\n"\
    " --location <name>\tspecify the network environment (suggested) [default: %s]\n"\
    " --dir <name>\t\tspecify the base directory where the location reside [default: %s]\n"\
    "\t\t\t[using both location and dir defaults, the configuration status will not be saved]\n"\
    " --no-tcp\t\tdisable tcp mangling [default: %s]\n"\
    " --no-udp\t\tdisable udp mangling [default: %s]\n"\
    " --whitelist\t\tinject evasion packets only in the specified ip addresses\n"\
    " --blacklist\t\tinject evasion packet in all session excluding the blacklisted ip address\n"\
    " --start\t\tif present, evasion i'ts activated immediatly [default: %s]\n"\
    " --chain\t\tenable chained hacking, powerful and entropic effects [default: %s]\n"\
    " --dump-packets\tdump all traffic data\n"\
    " --debug <level %d-%d>\tset verbosity level [default: %d]\n"\
    "\t\t\t%d: suppress log, %d: common, %d: verbose, %d: debug, %d: session %d: packets\n"\
    " --foreground\t\trunning in foreground [default:background]\n"\
    " --admin <ip>[:port]\tspecify administration IP address/port [default: %s:%d]\n"\
    " --janus <ip>[:in:out]\tspecify janus IP address/ports [default: %s:%d:%d]\n"\
    " --force\t\tforce restart (usable when another sniffjoke service is running)\n"\
    " --version\t\tshow sniffjoke version\n"\
   " --help\t\t\tshow this help\n\n"\
    "\t\t\thttp://www.delirandom.net/sniffjoke\n"

static void sj_help(const char *pname)
{
    printf(SNIFFJOKE_HELP_FORMAT,
           pname,
           DEFAULT_LOCATION,
           WORK_DIR,
           DEFAULT_NO_TCP ? "tcp not mangled" : "tcp mangled",
           DEFAULT_NO_UDP ? "udp not mangled" : "udp mangled",
           DEFAULT_START_STOPPED ? "present" : "not present",
           DEFAULT_CHAINING ? "enabled" : "disabled",
           SUPPRESS_LEVEL, PACKET_LEVEL, DEFAULT_DEBUG_LEVEL,
           SUPPRESS_LEVEL, ALL_LEVEL, VERBOSE_LEVEL, DEBUG_LEVEL, SESSION_LEVEL, PACKET_LEVEL,
           DEFAULT_ADMIN_ADDRESS, DEFAULT_ADMIN_PORT,
           DEFAULT_JANUS_ADDRESS, DEFAULT_JANUS_PORTIN, DEFAULT_JANUS_PORTOUT
           );
}

int main(int argc, char **argv)
{
    /*
     * set the default values in the configuration struct
     */
    struct sj_cmdline_opts useropt;
    memset(&useropt, 0x00, sizeof (useropt));

    /* ordered initialization of all boolean/uint values to the default */
    useropt.admin_port = DEFAULT_ADMIN_PORT;
    useropt.janus_portin = DEFAULT_JANUS_PORTIN;
    useropt.janus_portout = DEFAULT_JANUS_PORTOUT;
    useropt.chaining = DEFAULT_CHAINING;
    useropt.no_tcp = DEFAULT_NO_TCP;
    useropt.no_udp = DEFAULT_NO_UDP;
    useropt.use_whitelist = DEFAULT_USE_WHITELIST;
    useropt.use_blacklist = DEFAULT_USE_BLACKLIST;
    useropt.active = DEFAULT_START_STOPPED;
    useropt.go_foreground = DEFAULT_GO_FOREGROUND;
    useropt.force_restart = DEFAULT_FORCE_RESTART;
    useropt.dump_packets = DEFAULT_DUMP_PACKETS;
    useropt.debug_level = DEFAULT_DEBUG_LEVEL;
    useropt.max_ttl_probe = DEFAULT_MAX_TTLPROBE;

    /*
     * no explicit inizialization needed for string values;
     * all will be checked with string[0] != 0
     */

    struct option sj_option[] = {
        { "dir", required_argument, NULL, 'i'},
        { "location", required_argument, NULL, 'o'},
        { "admin", required_argument, NULL, 'a'},
        { "janus", required_argument, NULL, 'j'},
        { "chain", no_argument, NULL, 'c'},
        { "no-tcp", no_argument, NULL, 't'},
        { "no-udp", no_argument, NULL, 'l'},
        { "whitelist", no_argument, NULL, 'w'},
        { "blacklist", no_argument, NULL, 'b'},
        { "start", no_argument, NULL, 's'},
        { "foreground", no_argument, NULL, 'x'},
        { "force", no_argument, NULL, 'r'},
        { "dump-packets", no_argument, NULL, 'u'},
        { "debug", required_argument, NULL, 'd'},
        { "only-plugin", required_argument, NULL, 'p'}, /* not documented in --help */
        { "max-ttl-probe", required_argument, NULL, 'm'}, /* not documented too */
        { "version", no_argument, NULL, 'v'},
        { "help", no_argument, NULL, 'h'},
        { NULL, 0, NULL, 0}
    };

    int charopt;
    uint8_t i;
    char *port;
    uint16_t checked_port[2] = {0};
    while ((charopt = getopt_long(argc, argv, "i:o:a:j:ctlwbsxrd:up:m:vh", sj_option, NULL)) != -1)
    {
        switch (charopt)
        {
        case 'i':
            snprintf(useropt.basedir, sizeof (useropt.basedir) - 1, "%s", optarg);
            if (useropt.basedir[strlen(useropt.basedir) - 1] != '/')
                useropt.basedir[strlen(useropt.basedir)] = '/';
            break;
        case 'o':
            snprintf(useropt.location, sizeof (useropt.location), "%s", optarg);
            break;
        case 'a':
            snprintf(useropt.admin_address, sizeof (useropt.admin_address), "%s", optarg);
            if ((port = strchr(useropt.admin_address, ':')) != NULL)
            {
                *port = 0x00;
                checked_port[0] = atoi(++port);

                if (checked_port[0] >= PORTSNUMBER || checked_port[0] < 0)
                    goto sniffjoke_help;

                useropt.admin_port = checked_port[0];
            }
            break;
        case 'j':
            snprintf(useropt.janus_address, sizeof (useropt.janus_address), "%s", optarg);
            port = strtok(useropt.janus_address, ":");
            for(i = 0; i < 2; ++i)
            {
                if ((port = strtok(NULL, ":")) != NULL)
                {
                    checked_port[i] = atoi(port);

                    if ((checked_port[i] >= PORTSNUMBER || checked_port[i] < 0))
                        goto sniffjoke_help;
                } else break;
            }
            if(i == 2)
            {
                useropt.janus_portin = checked_port[0];
                useropt.janus_portout = checked_port[1];
            }
            break;
        case 'c':
            useropt.chaining = true;
            break;
        case 't':
            useropt.no_tcp = true;
            break;
        case 'l':
            useropt.no_udp = true;
            break;
        case 'w':
            useropt.use_whitelist = true;
            break;
        case 'b':
            useropt.use_blacklist = true;
            break;
        case 's':
            useropt.active = true;
            break;
        case 'x':
            useropt.go_foreground = true;
            break;
        case 'r':
            useropt.force_restart = true;
            break;
        case 'u':
            useropt.dump_packets = true;
            break;
        case 'd':
            useropt.debug_level = atoi(optarg);
            if (useropt.debug_level > TESTING_LEVEL)
                goto sniffjoke_help;
            break;
        case 'p':
            snprintf(useropt.onlyplugin, sizeof (useropt.onlyplugin), "%s", optarg);
            break;
        case 'm':
            useropt.max_ttl_probe = atoi(optarg);
            break;
        case 'v':
            sj_version(argv[0]);
            return 0;
sniffjoke_help:
        case 'h':
        default:
            sj_help(argv[0]);
            return -1;

            argc -= optind;
            argv += optind;
        }
    }

    try
    {
        SniffJoke sniffjoke(useropt);
        sniffjoke.run();

    }
    catch (runtime_error &exception)
    {
        LOG_ALL("[runtime exception] going shutdown: %s", exception.what());
        return 0;
    }
}
