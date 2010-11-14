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

static struct sj_cmdline_opts useropt;

static auto_ptr<SniffJoke> sniffjoke;

#define SNIFFJOKE_HELP_FORMAT \
	"%s [command] or %s --options:\n"\
	" --debug [level 1-6]\tset up verbosoty level [default: %d]\n"\
	"\t\t\t1: suppress log, 2: common, 3: verbose, 4: debug, 5: session 6: packets\n"\
	" --logfile [file]\tset a logfile, [default: %s%s]\n"\
	" --user [username]\tdowngrade priviledge to the specified user [default: %s]\n"\
	" --group [groupname]\tdowngrade priviledge to the specified group [default: %s]\n"\
	" --chroot-dir [dir]\truns chroted into the specified dir [default: %s]\n"\
	" --force\t\tforce restart if sniffjoke service\n"\
	" --foreground\t\trunning in foreground [default:background]\n"\
	" --config [filename]\tconfig file [default: %s%s]\n"\
	" --enabler [filename]\tplugins enabler file [default: %s]\n"\
	" --version\t\tshow sniffjoke version\n"\
	" --help\t\t\tshow this help (special --help hacking)\n\n"\
	"while sniffjoke is running, you should send one of those commands as command line argument:\n"\
	" start\t\t\tstart sniffjoke hijacking/injection\n"\
	" stop\t\t\tstop sniffjoke (but remain tunnel interface active)\n"\
	" quit\t\t\tstop sniffjoke, save config, abort the service\n"\
	" saveconfig\t\tdump config file\n\n"\
	" stat\t\t\tget statistics about sniffjoke configuration and network\n\n"\
	" info\t\t\tget massive info about sniffjoke internet stats\n\n"\
	" showport\t\tshow TCP ports strongness of injection\n"\
	" set start end value\tset per tcp ports the strongness of injection\n"\
	" \t\t\tthe values are: [heavy|normal|light|none]\n"\
	" \t\t\texample: sniffjoke set 22 80 heavy\n"\
	" clear\t\t\talias to \"set 1 65535 none\"\n"\
	" loglevel\t\t[1-6] change the loglevel\n\n"\
	"\t\t\thttp://www.delirandom.net/sniffjoke\n"

static void sj_help(const char *pname, const char *basedir)
{
	printf(SNIFFJOKE_HELP_FORMAT, pname, pname, DEFAULT_DEBUG_LEVEL, 
		basedir, LOGFILE, 
		DROP_USER, DROP_GROUP, 
		basedir, basedir, CONF_FILE, PLUGINSENABLER);
}

static void sj_version(const char *pname)
{
	printf("%s %s\n", SW_NAME, SW_VERSION);
}

runtime_error sj_runtime_exception(const char* func, const char* file, long line)
{
	stringstream stream;
	stream << file << "(" << line << ") function: " << func << "()";
	return std::runtime_error(stream.str());
}

void* memset_random(void *s, size_t n)
{
	unsigned char *cp = (unsigned char*)s;
	while (n-- > 0)
		*cp++ = (unsigned char)random();
	return s;
}

void sigtrap(int signal)
{
	if (signal)
		debug.log(ALL_LEVEL, "received signal %d, pid %d cleaning SniffJoke objects...", signal, getpid());
	
	sniffjoke.reset();
	
	exit(0);
}

int main(int argc, char **argv)
{
	/* set the default values in the configuration struct */
	snprintf(useropt.cfgfname, MEDIUMBUF, CONF_FILE);
	snprintf(useropt.enabler, MEDIUMBUF, PLUGINSENABLER);
	snprintf(useropt.user, MEDIUMBUF, DROP_USER);
	snprintf(useropt.group, MEDIUMBUF, DROP_GROUP);
	snprintf(useropt.chroot_dir, MEDIUMBUF, CHROOT_DIR);
	snprintf(useropt.logfname, LARGEBUF, "%s%s", CHROOT_DIR, LOGFILE);
	snprintf(useropt.logfname_packets, LARGEBUF, "%s%s", CHROOT_DIR, LOGFILE_PACKETS);
	snprintf(useropt.logfname_sessions, LARGEBUF, "%s%s", CHROOT_DIR, LOGFILE_SESSIONS);
	useropt.debug_level = DEFAULT_DEBUG_LEVEL;
	useropt.go_foreground = false;
	useropt.force_restart = false;
	useropt.logstream = stdout;
	useropt.packet_logstream = stdout;
	useropt.session_logstream = stdout;
	
	struct option sj_option[] =
	{
		{ "config", required_argument, NULL, 'f' },
		{ "user", required_argument, NULL, 'u' },
		{ "group", required_argument, NULL, 'g' },
		{ "chroot-dir", required_argument, NULL, 'c' },
		{ "debug", required_argument, NULL, 'd' },
		{ "logfile", required_argument, NULL, 'l' },
		{ "enabler", required_argument, NULL, 'e' },
		{ "foreground", no_argument, NULL, 'x' },
		{ "force", no_argument, NULL, 'r' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};

	useropt.process_type = SJ_CLIENT_PROC;

	memset(useropt.cmd_buffer, 0x00, MEDIUMBUF);
	/* check for direct commands */
	if ((argc >= 2) && !memcmp(argv[1], "start", strlen("start"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "start");
	} else if ((argc >= 2) && !memcmp(argv[1], "stop", strlen("stop"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "stop");
	} else if ((argc >= 2) && !memcmp(argv[1], "stat", strlen("stat"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "stat");
	} else if ((argc == 5) && !memcmp(argv[1], "set", strlen("set"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "set %s %s %s", argv[2], argv[3], argv[4]);
	} else if ((argc == 2) && !memcmp(argv[1], "clear", strlen("clear"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "clear");
	} else if ((argc == 2) && !memcmp(argv[1], "showport", strlen("showport"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "showport");
	}  else if ((argc == 2) && !memcmp(argv[1], "quit", strlen("quit"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "quit");
	} else if ((argc == 2) && !memcmp(argv[1], "info", strlen("info"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "info");
	} else if ((argc == 3) && !memcmp(argv[1], "loglevel", strlen("loglevel"))) {
		snprintf(useropt.cmd_buffer, MEDIUMBUF, "loglevel %s", argv[2]);
	} else {
		useropt.process_type = SJ_SERVER_PROC;
	}

	if (useropt.process_type == SJ_SERVER_PROC) {
		int charopt;
		while ((charopt = getopt_long(argc, argv, "f:e:u:g:c:d:l:xrhv", sj_option, NULL)) != -1) {
			switch(charopt) {
				case 'f':
					snprintf(useropt.cfgfname, MEDIUMBUF, "%s", optarg);
					break;
				case 'e':
					snprintf(useropt.enabler, MEDIUMBUF, "%s", optarg);
					break;
				case 'u':
					snprintf(useropt.user, MEDIUMBUF, "%s", optarg);
					break;
				case 'g':
					snprintf(useropt.group, MEDIUMBUF, "%s", optarg);
					break;
				case 'c':
					snprintf(useropt.chroot_dir, MEDIUMBUF, "%s", optarg);
					break;
				case 'l':
					snprintf(useropt.logfname, MEDIUMBUF, "%s", optarg);
					break;
				case 'd':
					useropt.debug_level = atoi(optarg);
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
				default:
					sj_help(argv[0], useropt.chroot_dir);
					return -1;

				argc -= optind;
				argv += optind;
			}
		}
	
	}

	try {
		sniffjoke = auto_ptr<SniffJoke> (new SniffJoke(useropt));
		sniffjoke->run();
	
	} catch (runtime_error &exception) {
		debug.log(ALL_LEVEL, "Runtime exception, going shutdown: %s", exception.what());
		
		sniffjoke.reset();
		exit(0);
	}
}
