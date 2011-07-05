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

static auto_ptr<SniffJoke> sniffjoke;

/* defined here, is needed by SniffJoke.cc */
void sigtrap(int signal)
{
    sniffjoke->alive = false;
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
    " --user <username>\tdowngrade priviledge to the specified user [default: %s]\n"\
    " --group <groupname>\tdowngrade priviledge to the specified group [default: %s]\n"\
    " --no-tcp\t\tdisable tcp mangling [default: %s]\n"\
    " --no-udp\t\tdisable udp mangling [default: %s]\n"\
    " --whitelist\t\tinject evasion packets only in the specified ip addresses\n"\
    " --blacklist\t\tinject evasion packet in all session excluding the blacklisted ip address\n"\
    " --start\t\tif present, evasion i'ts activated immediatly [default: %s]\n"\
    " --chain\t\tenable chained hacking, powerful and entropic effects [default: %s]\n"\
    " --debug <level %d-%d>\tset verbosity level [default: %d]\n"\
    "\t\t\t%d: suppress log, %d: common, %d: verbose, %d: debug, %d: session %d: packets\n"\
    " --foreground\t\trunning in foreground [default:background]\n"\
    " --admin <ip>[:port]\tspecify administration IP address [default: %s:%d]\n"\
    " --force\t\tforce restart (usable when another sniffjoke service is running)\n"\
    " --gw-mac-addr\t\tspecify default gateway mac address [default: is autodetected]\n"\
    " --version\t\tshow sniffjoke version\n"\
    " --help\t\t\tshow this help\n\n"\
    "\t\t\thttp://www.delirandom.net/sniffjoke\n"

static void sj_help(const char *pname)
{
    printf(SNIFFJOKE_HELP_FORMAT,
           pname,
           DEFAULT_LOCATION,
           WORK_DIR,
           DEFAULT_USER, DEFAULT_GROUP,
           DEFAULT_NO_TCP ? "tcp not mangled" : "tcp mangled",
           DEFAULT_NO_UDP ? "udp not mangled" : "udp mangled",
           DEFAULT_START_STOPPED ? "present" : "not present",
           DEFAULT_CHAINING ? "enabled" : "disabled",
           SUPPRESS_LEVEL, PACKET_LEVEL, DEFAULT_DEBUG_LEVEL,
           SUPPRESS_LEVEL, ALL_LEVEL, VERBOSE_LEVEL, DEBUG_LEVEL, SESSION_LEVEL, PACKET_LEVEL,
           DEFAULT_ADMIN_ADDRESS, DEFAULT_ADMIN_PORT
           );
}

int main(int argc, char **argv)
{

    if (getuid() || geteuid())
    {
        printf("SniffJoke is too dangerous to be run by an humble user; go to fetch daddy root, now!\n");
        exit(1);
    }

    /*
     * set the default values in the configuration struct
     */
    struct sj_cmdline_opts useropt;
    memset(&useropt, 0x00, sizeof (useropt));

    /* ordered initialization of all boolean/uint values to the default */
    useropt.admin_port = DEFAULT_ADMIN_PORT;
    useropt.chaining = DEFAULT_CHAINING;
    useropt.no_tcp = DEFAULT_NO_TCP;
    useropt.no_udp = DEFAULT_NO_UDP;
    useropt.use_whitelist = DEFAULT_USE_WHITELIST;
    useropt.use_blacklist = DEFAULT_USE_BLACKLIST;
    useropt.active = DEFAULT_START_STOPPED;
    useropt.go_foreground = DEFAULT_GO_FOREGROUND;
    useropt.debug_level = DEFAULT_DEBUG_LEVEL;
    useropt.max_ttl_probe = DEFAULT_MAX_TTLPROBE;
    useropt.force_restart = false;

    /*
     * no explicit inizialization needed for string values;
     * all will be checked with string[0] != 0
     */

    struct option sj_option[] = {
        { "dir", required_argument, NULL, 'i'},
        { "location", required_argument, NULL, 'o'},
        { "user", required_argument, NULL, 'u'},
        { "group", required_argument, NULL, 'g'},
        { "admin", required_argument, NULL, 'a'},
        { "chain", no_argument, NULL, 'c'},
        { "no-tcp", no_argument, NULL, 't'},
        { "no-udp", no_argument, NULL, 'l'},
        { "whitelist", no_argument, NULL, 'w'},
        { "blacklist", no_argument, NULL, 'b'},
        { "start", no_argument, NULL, 's'},
        { "foreground", no_argument, NULL, 'x'},
        { "force", no_argument, NULL, 'r'},
        { "debug", required_argument, NULL, 'd'},
        { "only-plugin", required_argument, NULL, 'p'}, /* not documented in --help */
        { "max-ttl-probe", required_argument, NULL, 'm'}, /* not documented too */
        { "gw-mac-addr", required_argument, NULL, 'e'},
        { "version", no_argument, NULL, 'v'},
        { "help", no_argument, NULL, 'h'},
        { NULL, 0, NULL, 0}
    };

    int charopt;
    while ((charopt = getopt_long(argc, argv, "i:o:u:g:a:ctlwbsxrd:p:m:vh", sj_option, NULL)) != -1)
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
        case 'u':
            snprintf(useropt.user, sizeof (useropt.user), "%s", optarg);
            break;
        case 'g':
            snprintf(useropt.group, sizeof (useropt.group), "%s", optarg);
            break;
        case 'a':
            snprintf(useropt.admin_address, sizeof (useropt.admin_address), "%s", optarg);
            char* port;
            if ((port = strchr(useropt.admin_address, ':')) != NULL)
            {
                *port = 0x00;
                int checked_port = atoi(++port);

                if (checked_port >= PORTSNUMBER || checked_port < 0)
                    goto sniffjoke_help;

                useropt.admin_port = (uint16_t) checked_port;
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
        case 'd':
            useropt.debug_level = atoi(optarg);
            if (useropt.debug_level > TESTING_LEVEL)
                goto sniffjoke_help;
            break;
        case 'p':
            snprintf(useropt.onlyplugin, sizeof (useropt.onlyplugin), "%s", optarg);
            break;
        case 'e':
            snprintf(useropt.gw_mac_str, sizeof (useropt.gw_mac_str), "%s", optarg);
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

    init_random();

    try
    {
        sniffjoke = auto_ptr<SniffJoke > (new SniffJoke(useropt));
        sniffjoke->run();

    }
    catch (runtime_error &exception)
    {
        LOG_ALL("[runtime exception] going shutdown: %s", exception.what());

        sniffjoke.reset();
        return 0;
    }
}
