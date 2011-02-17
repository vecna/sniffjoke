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

#include "hardcodedDefines.h"

#include "Utils.h"
#include "UserConf.h"
#include "SniffJoke.h"

#include <stdexcept>

#include <getopt.h>
#include <stdint.h>

using namespace std;

Debug debug;
time_t sj_clock;

static auto_ptr<SniffJoke> sniffjoke;

runtime_error runtime_exception(const char* func, const char* file, int32_t line, const char* format, ...)
{
    char error[LARGEBUF];
    char complete_error[LARGEBUF];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(error, sizeof (error), format, arguments);
    snprintf(complete_error, sizeof (complete_error), "%s:%d %s() [ %s ]", file, line, func, error);
    va_end(arguments);

    stringstream stream;
    stream << complete_error;
    return std::runtime_error(stream.str());
}

void init_random()
{
    /* random pool initialization */
    srandom(time(NULL));
    for (uint8_t i = 0; i < ((uint8_t) random() % 10); ++i)
        srandom(random());
}

void* memset_random(void *s, size_t n)
{
    /*
     * highly optimized memset_random
     *
     * long int random(void).
     *
     * long int is variable on different architectures;
     * for example on linux 64 bit is 8 chars long,
     * so do a while using single chars its an inefficient choice.
     *
     */

    if (debug.level() == TESTING_LEVEL)
    {
        memset(s, '6', n);
        return s;
    }

    size_t longint = n / sizeof (long int);
    size_t finalbytes = n % sizeof (long int);
    unsigned char *cp = (unsigned char*) s;

    while (longint-- > 0)
    {
        *((long int*) cp) = random();
        cp += sizeof (long int);
    }

    while (finalbytes-- > 0)
    {
        *cp = (unsigned char) random();
        ++cp;
    }

    return s;
}

void sigtrap(int signal)
{
    sniffjoke->alive = false;
}

static void sj_version(const char *pname)
{
    printf("%s %s\n", SW_NAME, SW_VERSION);
}

#define SNIFFJOKE_HELP_FORMAT \
    "%s [command] or %s --options:\n"\
    " --location <name>\tspecify the network environment (suggested) [default: %s]\n"\
    " --dir <name>\t\tspecify the base directory where the location reside [default: %s]\n"\
    "\t\t[using both location and dir defaults, the configuration status will not be saved]\n"\
    " --user <username>\tdowngrade priviledge to the specified user [default: %s]\n"\
    " --group <groupname>\tdowngrade priviledge to the specified group [default: %s]\n"\
    " --whitelist\tinject evasion packets only in the specified ip addresses\n"\
    " --blacklist\tinject evasion packet in all session excluding the blacklisted ip address\n"\
    " --start\t\tif present, evasion i'ts activated immediatly [default: %s]\n"\
    " --debug <level %d-%d>\tset up verbosoty level [default: %d]\n"\
    "\t\t\t%d: suppress log, %d: common, %d: verbose, %d: debug, %d: session %d: packets\n"\
    " --foreground\t\trunning in foreground [default:background]\n"\
    " --admin <ip>[:port]\tspecify administration IP address [default: %s:%d]\n"\
    " --force\t\tforce restart (usable when another sniffjoke service is running)\n"\
    " --version\t\tshow sniffjoke version\n"\
    " --help\t\t\tshow this help\n\n"\
    "\t\t\thttp://www.delirandom.net/sniffjoke\n"

static void sj_help(const char *pname)
{
    printf(SNIFFJOKE_HELP_FORMAT,
           pname, pname,
           DEFAULT_LOCATION,
           WORK_DIR,
           DROP_USER, DROP_GROUP,
           DEFAULT_START_STOPPED ? "present" : "not present",
           SUPPRESS_LEVEL, PACKET_LEVEL, DEFAULT_DEBUG_LEVEL,
           SUPPRESS_LEVEL, ALL_LEVEL, VERBOSE_LEVEL, DEBUG_LEVEL, SESSION_LEVEL,PACKET_LEVEL,
           DEFAULT_ADMIN_ADDRESS, DEFAULT_ADMIN_PORT
           );
}

int main(int argc, char **argv)
{
    /*
     * set the default values in the configuration struct
     * we have only constant length char[] and booleans
     */
    struct sj_cmdline_opts useropt;
    memset(&useropt, 0x00, sizeof (useropt));

    struct option sj_option[] = {
        { "dir", required_argument, NULL, 'i'},
        { "location", required_argument, NULL, 'o'},
        { "user", required_argument, NULL, 'u'},
        { "group", required_argument, NULL, 'g'},
        { "start", no_argument, NULL, 's'},
        { "foreground", no_argument, NULL, 'x'},
        { "force", no_argument, NULL, 'r'},
        { "whitelist", no_argument, NULL, 'w'},
        { "blacklist", no_argument, NULL, 'b'},
        { "admin", required_argument, NULL, 'a'},
        { "only-plugin", required_argument, NULL, 'p'}, /* not documented in --help */
        { "max-ttl-probe", required_argument, NULL, 'm'}, /* not documented too */
        { "debug", required_argument, NULL, 'd'},
        { "version", no_argument, NULL, 'v'},
        { "help", no_argument, NULL, 'h'},
        { NULL, 0, NULL, 0}
    };

    int charopt;
    while ((charopt = getopt_long(argc, argv, "i:o:u:g:sxrwba:p:m:d:vh", sj_option, NULL)) != -1)
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
        case 'm':
            useropt.max_ttl_probe = atoi(optarg);
            break;
        case 'g':
            snprintf(useropt.group, sizeof (useropt.group), "%s", optarg);
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
        case 'a':
            snprintf(useropt.admin_address, sizeof (useropt.admin_address), "%s", optarg);
            char* port;
            if ((port = strchr(useropt.admin_address, ':')) != NULL)
            {
                *port = 0x00;
                int checked_port = atoi(++port);

                if (checked_port > PORTNUMBER || checked_port < 0)
                    goto sniffjoke_help;

                useropt.admin_port = (uint16_t) checked_port;
            }
            break;
        case 'p':
            snprintf(useropt.onlyplugin, sizeof (useropt.onlyplugin), "%s", optarg);
            break;
        case 'd':
            useropt.debug_level = atoi(optarg);
            if (useropt.debug_level < SUPPRESS_LEVEL || useropt.debug_level > TESTING_LEVEL)
                goto sniffjoke_help;
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
