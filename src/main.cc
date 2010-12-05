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

#include "hardcoded-defines.h"

#include "Utils.h"
#include "UserConf.h"
#include "SniffJoke.h"

#include <stdexcept>
#include <csignal>
#include <memory>
#include <getopt.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace std;

Debug debug;

timespec sj_clock;

static struct sj_cmdline_opts useropt;
static auto_ptr<SniffJoke> sniffjoke;

#define SNIFFJOKE_HELP_FORMAT \
	"%s [command] or %s --options:\n"\
	" --config <filename>\tconfig file [default: %s%s]\n"\
	" --enabler <filename>\tplugins enabler file [default: %s]\n"\
	" --user <username>\tdowngrade priviledge to the specified user [default: %s]\n"\
	" --group <groupname>\tdowngrade priviledge to the specified group [default: %s]\n"\
	" --chroot-dir <dir>\truns chroted into the specified dir [default: %s]\n"\
	" --logfile <file>\tset a logfile, [default: %s%s]\n"\
	" --debug <level 1-6>\tset up verbosoty level [default: %d]\n"\
	"\t\t\t1: suppress log, 2: common, 3: verbose, 4: debug, 5: session 6: packets\n"\
	" --foreground\t\trunning in foreground [default:background]\n"\
	" --admin <IPv4>[:port]\tspecify administration IP address [default: 127.0.0.1:%d]\n"\
	" --force\t\tforce restart if sniffjoke service\n"\
	" --version\t\tshow sniffjoke version\n"\
	" --help\t\t\tshow this help (special --help hacking)\n\n"\
	"testing options (not saved in configuration file):\n"\
	" --only-plugin <plugin.so>\tspecify the single plugin to use\n"\
	" --scramble <Y|N><Y|N><Y|N>\tselect scrambling techniques (order: TTL, checksum, IPmalform)\n\n"\
	"while sniffjoke is running, you should send one of those commands as command line argument:\n"\
	" start\t\t\tstart sniffjoke hijacking/injection\n"\
	" stop\t\t\tstop sniffjoke (but remain tunnel interface active)\n"\
	" quit\t\t\tstop sniffjoke, save config, abort the service\n"\
	" saveconf\t\tdump config file\n"\
	" stat\t\t\tget statistics about sniffjoke configuration and network\n"\
	" info\t\t\tget massive info about sniffjoke internet stats\n"\
	" showport\t\tshow TCP ports strongness of injection\n"\
	" set start end value\tset per tcp ports the strongness of injection\n"\
	" \t\t\tthe values are: <heavy|normal|light|none>\n"\
	" \t\t\texample: sniffjoke set 22 80 heavy\n"\
	" clear\t\t\talias to \"set 1 65535 none\"\n"\
	" loglevel\t\t[1-6] change the loglevel\n\n"\
	"\t\t\thttp://www.delirandom.net/sniffjoke\n"

static void sj_help(const char *pname, const char optchroot[MEDIUMBUF], const char *defaultbd)
{
	const char *basedir = optchroot[0] ? &optchroot[0] : defaultbd;

	printf(SNIFFJOKE_HELP_FORMAT, 
		pname, pname,
		basedir, CONF_FILE,
		PLUGINSENABLER,
		DROP_USER, DROP_GROUP, 
		basedir,
		basedir, LOGFILE,
		DEFAULT_DEBUG_LEVEL, DEFAULT_UDP_ADMIN_PORT
	);
}

static void sj_version(const char *pname)
{
	printf("%s %s\n", SW_NAME, SW_VERSION);
}

runtime_error sj_runtime_exception(const char* func, const char* file, long line, const char* msg)
{
	stringstream stream;
	stream << "[EXCEPTION] "<< file << "(" << line << ") function: " << func << "()";
	if(msg != NULL)
		stream << " : " << msg;
	return std::runtime_error(stream.str());
}

void init_random()
{
	/* random pool initialization */
	srandom(time(NULL));
	for (uint8_t i = 0; i < ((uint8_t)random() % 10); ++i) 
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

	size_t longint = n / sizeof(long int);
	size_t finalbytes = n % sizeof(long int);
	unsigned char *cp = (unsigned char*)s;

	while (longint-- > 0) {
		*((long int*)cp) = random();
		cp += sizeof(long int);
	}
	
	while (finalbytes-- > 0) {
		*cp = (unsigned char)random();
		++cp;
	}

	return s;
}

void updateSchedule(struct timespec &schedule, time_t sec, long ns)
{
#define NSEC_PER_SEC 1000000000
	schedule.tv_sec += sec;
	if(ns) {
		uint32_t temp = schedule.tv_nsec + ns;
		schedule.tv_sec += temp / NSEC_PER_SEC;
		schedule.tv_nsec = temp % NSEC_PER_SEC;
	}
}

bool isSchedulePassed(const struct timespec& schedule)
{
    if(sj_clock.tv_sec > schedule.tv_sec)
        return true;

    else if((sj_clock.tv_sec == schedule.tv_sec) && (sj_clock.tv_nsec > schedule.tv_nsec)) {
        return true;
    }
        
    return false;
}

void sigtrap(int signal)
{
	sniffjoke->alive = false;
	
}

static bool client_command_found(char **av, uint32_t ac, struct command *sjcmdlist, char *retcmd) 
{
	for(uint32_t i = 0; i < ac; ++i) 
	{
		struct command *ptr;
		for(ptr = &sjcmdlist[0]; ptr->cmd != NULL; ++ptr) 
		{
			if(!strcmp(ptr->cmd, av[i])) 
			{
				size_t usedlen = 0;
				snprintf(retcmd, MEDIUMBUF, "%s", ptr->cmd);
				if(ptr->related_args + i > ac) {
					sj_help(av[0], CHROOT_DIR, CHROOT_DIR);
					exit(-1);
				}
				while(--(ptr->related_args)) {
					usedlen = strlen(retcmd);
					snprintf(&retcmd[usedlen], MEDIUMBUF - usedlen, " %s", av[++i]);
				}
				return true;
			}
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	clock_gettime(CLOCK_REALTIME, &sj_clock);
	
	/* 
	 * set the default values in the configuration struct
	 * we have only constant length char[] and booleans
	 */
	memset(&useropt, 0x00, sizeof(useropt));
	
	struct option sj_option[] =
	{
		{ "config", required_argument, NULL, 'f' },
		{ "enabler", required_argument, NULL, 'e' },
		{ "user", required_argument, NULL, 'u' },
		{ "group", required_argument, NULL, 'g' },
		{ "chroot-dir", required_argument, NULL, 'c' },
		{ "debug", required_argument, NULL, 'd' },
		{ "logfile", required_argument, NULL, 'l' },
		{ "admin", required_argument, NULL, 'a' },		
		{ "foreground", no_argument, NULL, 'x' },
		{ "force", no_argument, NULL, 'r' },
		{ "version", no_argument, NULL, 'v' },
		{ "only-plugin", required_argument, NULL, 'p' },
		{ "scramble", required_argument, NULL, 's' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	struct command sj_command[] =
	{
		{ "start",    1 },
		{ "stop",     1 },
		{ "stat",     1 },
		{ "clear",    1 },
		{ "showport", 1 },
		{ "quit",     1 },
		{ "info",     1 },
		{ "saveconf", 1 },
		{ "loglevel", 2 }, 	/* the loglevel */
		{ "set",      4 }, 	/* set start_port end_port value */
		{ NULL,       0	}
	};

	useropt.process_type = SJ_CLIENT_PROC;

	/* check for client commands */
	if(!client_command_found(argv, argc, sj_command, useropt.cmd_buffer))
		useropt.process_type = SJ_SERVER_PROC;

	int charopt;
	while ((charopt = getopt_long(argc, argv, "f:e:u:g:c:d:l:a:xrvp:s:h", sj_option, NULL)) != -1) {
		switch(charopt) {
			case 'f':
				snprintf(useropt.cfgfname, sizeof(useropt.cfgfname), "%s", optarg);
				break;
			case 'e':
				snprintf(useropt.enabler, sizeof(useropt.enabler), "%s", optarg);
				break;
			case 'u':
				snprintf(useropt.user, sizeof(useropt.user), "%s", optarg);
				break;
			case 'g':
				snprintf(useropt.group, sizeof(useropt.group), "%s", optarg);
				break;
			case 'c':
				snprintf(useropt.chroot_dir, sizeof(useropt.chroot_dir) -1, "%s", optarg);
				/* this fix it's useful if the useropt path lacks the ending slash */
				if(useropt.chroot_dir[strlen(useropt.chroot_dir) -1] != '/')
					useropt.chroot_dir[strlen(useropt.chroot_dir)] = '/';
				break;
			case 'd':
				useropt.debug_level = atoi(optarg);
				if(useropt.debug_level < 1 || useropt.debug_level > 6)
					goto sniffjoke_help;
				break;
			case 'l':
				snprintf(useropt.logfname, sizeof(useropt.logfname), "%s", optarg);
				snprintf(useropt.logfname_packets, sizeof(useropt.logfname_packets), "%s%s", optarg, SUFFIX_LF_PACKETS);
				snprintf(useropt.logfname_sessions, sizeof(useropt.logfname_sessions), "%s%s", optarg, SUFFIX_LF_SESSIONS);
				break;
			case 'a':
				snprintf(useropt.admin_address, sizeof(useropt.admin_address), "%s", optarg);
				char* port;
				if((port = strchr(useropt.admin_address, ':')) != NULL) {
					*port = 0x00;
					int checked_port = atoi(++port);

					if(checked_port > PORTNUMBER || checked_port < 0)
						goto sniffjoke_help;

					useropt.admin_port = (uint16_t)checked_port;
				}
				break;
			case 'x':
				useropt.go_foreground = true;
				break;
			case 'r':
				useropt.force_restart = true;
				break;
			case 'v':
				sj_version(argv[0]);
				return 0;
			case 'p':
				snprintf(useropt.onlyplugin, sizeof(useropt.onlyplugin), "%s", optarg);
				break;
			case 's':
				if((strlen(optarg) != 3)
				|| YNcheck(optarg[0]) || YNcheck(optarg[1]) || YNcheck(optarg[2]))
					goto sniffjoke_help;

				snprintf(useropt.scramble, sizeof(useropt.scramble), "%s", optarg);
				break;
sniffjoke_help:
			case 'h':
			default:
				sj_help(argv[0], useropt.chroot_dir, CHROOT_DIR);
				return -1;

			argc -= optind;
			argv += optind;
		}
	}
	
	/* someone has made a "sniffjoke typo" */
	if(useropt.process_type == SJ_SERVER_PROC && argc > 1 && argv[1][0] != '-') {
		sj_help(argv[0], useropt.chroot_dir, CHROOT_DIR);
		return -1;
	}

	init_random();

	try {
		sniffjoke = auto_ptr<SniffJoke> (new SniffJoke(useropt));
		sniffjoke->run();
	
	} catch (runtime_error &exception) {
		debug.log(ALL_LEVEL, "Runtime exception, going shutdown: %s", exception.what());
		
		sniffjoke.reset();
		return 0;
	}
}
