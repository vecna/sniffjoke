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

#include "UserConf.h"

#include <cctype>

#include <sys/stat.h>

UserConf::UserConf(const struct sj_cmdline_opts &cmdline_opts, bool &sj_alive) :
	alive(sj_alive),
	chroot_status(false)
{
	debug.log(VERBOSE_LEVEL, __func__);

	char configfile[LARGEBUF];
	const char *realdir, *realfil;

	if(cmdline_opts.chroot_dir[0]) 	realdir = cmdline_opts.chroot_dir;
	else 				realdir = CHROOT_DIR;
	if(cmdline_opts.cfgfname[0])	realfil = cmdline_opts.cfgfname;
	else				realfil = CONF_FILE;

	snprintf(configfile, LARGEBUF, "%s%s", realdir, realfil); 
	memset(&runconfig, 0x00, sizeof(sj_config));
	
	if(!load(configfile)) {
		debug.log(ALL_LEVEL, "configuration file: %s not found: using defaults", configfile);

		/* set up defaults */	   
		runconfig.MAGIC = MAGICVAL;
		runconfig.active = false;
		runconfig.max_ttl_probe = DEFAULT_MAX_TTLPROBE;
		runconfig.max_sextrack = DEFAULT_MAX_SEXTRACK;
		runconfig.max_ttlfocus = DEFAULT_MAX_TTLFOCUS;

		/* default is to set all TCP ports in "NORMAL" aggressivity level */
		for(unsigned int i = 0; i < PORTNUMBER; i++)
			runconfig.portconf[i] = NORMAL;
	}

	/* the command line useopt is filled with the default in main.cc; if the user have overwritten with --options
	 * we need only to check if the previous value was different from the default */
	compare_check_copy(runconfig.cfgfname, sizeof(runconfig.cfgfname), CONF_FILE, cmdline_opts.cfgfname);
	compare_check_copy(runconfig.enabler, sizeof(runconfig.enabler), PLUGINSENABLER, cmdline_opts.enabler);
	compare_check_copy(runconfig.user, sizeof(runconfig.user), DROP_USER, cmdline_opts.user);
	compare_check_copy(runconfig.group, sizeof(runconfig.group), DROP_GROUP, cmdline_opts.group);
	compare_check_copy(runconfig.chroot_dir, sizeof(runconfig.chroot_dir), CHROOT_DIR, cmdline_opts.chroot_dir);
	compare_check_copy(runconfig.logfname, sizeof(runconfig.logfname), CHROOT_DIR""LOGFILE, cmdline_opts.logfname);
	compare_check_copy(runconfig.logfname_packets, sizeof(runconfig.logfname), CHROOT_DIR""LOGFILE""SUFFIX_LF_PACKETS, cmdline_opts.logfname);
	compare_check_copy(runconfig.logfname_sessions, sizeof(runconfig.logfname), CHROOT_DIR""LOGFILE""SUFFIX_LF_SESSIONS, cmdline_opts.logfname);

	if(cmdline_opts.debug_level != DEFAULT_DEBUG_LEVEL)
		runconfig.debug_level = cmdline_opts.debug_level;

	if(runconfig.debug_level == 0)
		runconfig.debug_level = DEFAULT_DEBUG_LEVEL; // equal to ALL_LEVEL
	
	if(cmdline_opts.onlyplugin[0])
		snprintf(runconfig.onlyplugin, LARGEBUF, "%s", cmdline_opts.onlyplugin);

	if(cmdline_opts.scramble[0]) {
		runconfig.scrambletech |= (cmdline_opts.scramble[0] == 'Y') ? SCRAMBLE_TTL : 0;
		runconfig.scrambletech |= (cmdline_opts.scramble[1] == 'Y') ? SCRAMBLE_CHECKSUM : 0;
		runconfig.scrambletech |= (cmdline_opts.scramble[2] == 'Y') ? SCRAMBLE_MALFORMED : 0;
		if(!runconfig.scrambletech) {
			debug.log(ALL_LEVEL, "--scramble: at least one scramble technique is required");
			SJ_RUNTIME_EXCEPTION();
		}
	} else {
		runconfig.scrambletech = (SCRAMBLE_TTL | SCRAMBLE_CHECKSUM | SCRAMBLE_MALFORMED);
	}

	/* the configuration file must remain root:root 666 because the user should/must/can overwrite later */
	chmod(configfile, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
	dump();
}

UserConf::~UserConf()
{
	debug.log(DEBUG_LEVEL, "%s [process %d chroot %s], referred config file %s",
		 __func__, getpid(), chroot_status ? "YES" : "NO", runconfig.cfgfname);
}

/* Read command line values if present, preserve the previous options, and otherwise import default */
void UserConf::compare_check_copy(char *target, unsigned int tlen, const char *sjdefault, const char *useropt)
{
	if(useropt[0]) strncpy(target, useropt, tlen);
	
	if(target[0]) strncpy(target, sjdefault, tlen);
}

/* private function useful for resolution of code/name */
const char *UserConf::resolve_weight_name(int command_code) 
{
	switch(command_code) {
		case HEAVY: return "heavy";
		case NORMAL: return "normal";
		case LIGHT: return "light";
		case NONE: return "no hacks";
		default: debug.log(ALL_LEVEL, "danger: found invalid code in ports configuration");
			 return "VERY BAD BUFFER CORRUPTION! I WISH NO ONE EVER SEE THIS LINE";
	}
}

void UserConf::autodetect_local_interface()
{
	/* check this command: the flag value, matched in 0003, is derived from:
	 * 	/usr/src/linux/include/linux/route.h
	 */
	const char *cmd = "grep 0003 /proc/net/route | grep 00000000 | cut -b -7";
	FILE *foca;
	char imp_str[SMALLBUF];
	unsigned int i;

	debug.log(ALL_LEVEL, "++ detecting external gateway interface with [%s]", cmd);

	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && isalnum(imp_str[i]); i++)
		runconfig.interface[i] = imp_str[i];

	if (i < 3) {
		debug.log(ALL_LEVEL, "-- default gateway not present: sniffjoke cannot be started");
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(ALL_LEVEL, "  == detected external interface with default gateway: %s", runconfig.interface);
	}
}


void UserConf::autodetect_local_interface_ip_address()
{
	char cmd[MEDIUMBUF];
	FILE *foca;
	char imp_str[SMALLBUF];
	unsigned int i;
	snprintf(cmd, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21-", 
		runconfig.interface
	);

	debug.log(ALL_LEVEL, "++ detecting interface %s ip address with [%s]", runconfig.interface, cmd);

	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isdigit(imp_str[i]) || imp_str[i] == '.'); i++)
		runconfig.local_ip_addr[i] = imp_str[i];

	debug.log(ALL_LEVEL, "  == acquired local ip address: %s", runconfig.local_ip_addr);
}


void UserConf::autodetect_gw_ip_address()
{
	const char *cmd = "route -n | grep ^0.0.0.0 | grep UG | cut -b 17-32"; 
	FILE *foca;
	char imp_str[SMALLBUF];
	unsigned int i;

	debug.log(ALL_LEVEL, "++ detecting gateway ip address with [%s]", cmd);

	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isdigit(imp_str[i]) || imp_str[i] == '.'); i++) 
		runconfig.gw_ip_addr[i] = imp_str[i];
	if (strlen(runconfig.gw_ip_addr) < 7) {
		debug.log(ALL_LEVEL, "  -- unable to autodetect gateway ip address, sniffjoke cannot be started");
		SJ_RUNTIME_EXCEPTION();
	} else  {
		debug.log(ALL_LEVEL, "  == acquired gateway ip address: %s", runconfig.gw_ip_addr);
	}
}

void UserConf::autodetect_gw_mac_address()
{
	char cmd[MEDIUMBUF];
	FILE *foca;
	char imp_str[SMALLBUF];
	unsigned int i;
	snprintf(cmd, MEDIUMBUF, "ping -W 1 -c 1 %s", runconfig.gw_ip_addr);

	debug.log(ALL_LEVEL, "++ pinging %s for ARP table popoulation motivations [%s]", runconfig.gw_ip_addr, cmd);
	
	foca = popen(cmd, "r");
	/* we do not need the output of ping, we need to wait the ping to finish
	 * and pclose does this =) */
	pclose(foca);
	
	memset(cmd, 0x00, sizeof(cmd));
	snprintf(cmd, MEDIUMBUF, "arp -n | grep %s | cut -b 34-50", runconfig.gw_ip_addr);
	debug.log(ALL_LEVEL, "++ detecting mac address of gateway with %s", cmd);
	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isxdigit(imp_str[i]) || imp_str[i] == ':'); i++)
		runconfig.gw_mac_str[i] = imp_str[i];
	if (i != 17) {
		debug.log(ALL_LEVEL, "  -- unable to autodetect gateway mac address");
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(ALL_LEVEL, "  == automatically acquired mac address: %s", runconfig.gw_mac_str);
		unsigned int mac[6];
		sscanf(runconfig.gw_mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		for (i=0; i<6; i++)
			runconfig.gw_mac_addr[i] = mac[i];	
	}
}

void UserConf::autodetect_first_available_tunnel_interface()
{
	const char *cmd = "ifconfig -a | grep tun | cut -b -7";
	FILE *foca;
	char imp_str[SMALLBUF];

	debug.log(ALL_LEVEL, "++ detecting first unused tunnel device with [%s]", cmd);
	
	foca = popen(cmd, "r");
	for (runconfig.tun_number = 0; ; runconfig.tun_number++)
	{
		memset(imp_str, 0x00, sizeof(imp_str));
		fgets(imp_str, SMALLBUF, foca);
		if (imp_str[0] == 0x00)
			break;
	}
	pclose(foca);
	debug.log(ALL_LEVEL, "  == detected %d as first unused tunnel device", runconfig.tun_number);
}

/* this method is used only in the ProcessType = SERVICE CHILD */
void UserConf::network_setup(void)
{

	debug.log(DEBUG_LEVEL, "Initializing network for service/child: %d", getpid());

	/* autodetect is always used, we should not trust the preloaded configuration */
	autodetect_local_interface();
	autodetect_local_interface_ip_address();
	autodetect_gw_ip_address();
	autodetect_gw_mac_address();
	autodetect_first_available_tunnel_interface();

	debug.log(VERBOSE_LEVEL, "-- system local interface: %s, %s address", runconfig.interface, runconfig.local_ip_addr);
	debug.log(VERBOSE_LEVEL, "-- default gateway mac address: %s", runconfig.gw_mac_str);
	debug.log(VERBOSE_LEVEL, "-- default gateway ip address: %s", runconfig.gw_ip_addr);
	debug.log(VERBOSE_LEVEL, "-- first available tunnel interface: tun%d", runconfig.tun_number);


	/* FIXME, is this incomplete? who does set this ? */
	if(runconfig.port_conf_set_n) {
		debug.log(VERBOSE_LEVEL,"-- loaded %d TCP port set, verify them with sniffjoke stat",
			runconfig.port_conf_set_n
		);
	}
}

bool UserConf::load(const char* configfile)
{
	FILE *loadfd;	
	debug.log(DEBUG_LEVEL, "opening configuration file: %s", configfile);

	if ((loadfd = fopen(configfile, "r")) != NULL) {
		memset(&runconfig, 0x00, sizeof(struct sj_config));

		if(fread((void *)&runconfig, sizeof(struct sj_config), 1, loadfd) != 1) {
			debug.log(ALL_LEVEL, "unable to read %d bytes from %s, maybe the wrong file ?",
				sizeof(runconfig), configfile, strerror(errno)
			);
			SJ_RUNTIME_EXCEPTION();
		}

		debug.log(DEBUG_LEVEL, "reading of %s: %d byte readed", configfile, sizeof(struct sj_config));

		if (runconfig.MAGIC != MAGICVAL) {
			debug.log(ALL_LEVEL, "sniffjoke config: %s seems to be corrupted - delete or check the argument",
				configfile
			);
			SJ_RUNTIME_EXCEPTION();
		}
		fclose(loadfd);
		return true;
	} else {
		return false;
	}
}

void UserConf::dump(void)
{
	char configfile[LARGEBUF];
	FILE *dumpfd;
	
	struct sj_config configcopy;
	memcpy(&configcopy, &runconfig, sizeof(runconfig));

	configcopy.MAGIC = MAGICVAL;

	if(!chroot_status)
		snprintf(configfile, LARGEBUF, "%s%s", configcopy.chroot_dir, configcopy.cfgfname);
	else
		snprintf(configfile, LARGEBUF, "%s", configcopy.cfgfname);
	
	if((dumpfd = fopen(configfile, "w")) != NULL) {	
		debug.log(VERBOSE_LEVEL, "dumping configcopy configuration to %s",  configfile);
				
		/* resetting variables we do not want to save */
		memset(configcopy.onlyplugin, 0, sizeof(configcopy.onlyplugin));
		configcopy.scrambletech = 0;

		if((fwrite(&configcopy, sizeof(struct sj_config), 1, dumpfd)) != 1) {
			/* ret - 1 because fwrite return the number of written item */
			debug.log(ALL_LEVEL, "unable to write configuration to %s: %s",	configfile, strerror(errno));
		}

		fclose(dumpfd);
	} else {
		debug.log(ALL_LEVEL, "unable to open configuration to %s: %s", configfile, strerror(errno));
	}
	
}

char *UserConf::handle_cmd(const char *cmd)
{
	memset(io_buf, 0x00, sizeof(io_buf));

	if (!memcmp(cmd, "start", strlen("start"))) {
		handle_cmd_start();
	} else if (!memcmp(cmd, "stop", strlen("stop"))) {
		handle_cmd_stop();
	} else if (!memcmp(cmd, "quit", strlen("quit"))) {
		handle_cmd_quit();
	} else if (!memcmp(cmd, "saveconf", strlen("saveconf"))) {
		handle_cmd_saveconf();
	} else if (!memcmp(cmd, "stat", strlen("stat"))) {
		handle_cmd_stat();
	} else if (!memcmp(cmd, "info", strlen("info"))) {
		handle_cmd_info();
	} else if (!memcmp(cmd, "listen", strlen("listen"))) {
		int port;
		const char *portstr = strchr(cmd, ' ');

		if(portstr == NULL)
			goto handle_listen_error;
		
		port = atoi(++portstr);
		if(port < 0 || port > PORTNUMBER)
			goto handle_listen_error;

		handle_cmd_listen(port);
	} else if (!memcmp(cmd, "showport", strlen("showport"))) {
		handle_cmd_showport();
	} else if (!memcmp(cmd, "set", strlen("set"))) {
		int start_port, end_port;
		Strength setValue;
		char weight[MEDIUMBUF];

		sscanf(cmd, "set %d %d %s", &start_port, &end_port, weight);

		if (start_port < 0 || start_port > PORTNUMBER || end_port < 0 || end_port > PORTNUMBER)
			goto handle_set_error;

		if (!parse_port_weight(weight, &setValue))
			goto handle_set_error;

		if (start_port > end_port)
			goto handle_set_error;

		handle_cmd_set(start_port, end_port, setValue);
	} else if (!memcmp(cmd, "clear", strlen("clear"))) {
		Strength clearValue = NONE;
		handle_cmd_set(0, PORTNUMBER, clearValue);
	} else if (!memcmp(cmd, "loglevel", strlen("loglevel")))  {
		int loglevel;

		sscanf(cmd, "loglevel %d", &loglevel);
		if (loglevel < 0 || loglevel > PACKETS_DEBUG) {
			snprintf(io_buf, sizeof(io_buf), "invalid log value: %d, must be > 0 and < than %d", loglevel, PACKETS_DEBUG);
			debug.log(ALL_LEVEL, "%s", io_buf);
		} else {
			handle_cmd_loglevel(loglevel);
		}
	} else {
		debug.log(ALL_LEVEL, "wrong command %s", cmd);
	}
	
	return &io_buf[0];

handle_listen_error:
	snprintf(io_buf, strlen(io_buf), "invalid listen command: expected a valid port as argument\n");
	debug.log(ALL_LEVEL, "%s", io_buf);
	return &io_buf[0];

handle_set_error:
	snprintf(io_buf, strlen(io_buf), "invalid set command: [startport] [endport] VALUE\n"\
		"startport and endport need to be less than %d\n"\
		"startport nedd to be less or equal endport\n"\
		"value would be: none|light|normal|heavy\n", PORTNUMBER);
	debug.log(ALL_LEVEL, "%s", io_buf);
	return &io_buf[0];
}

void UserConf::handle_cmd_start()
{
	if (runconfig.active != true) {
		snprintf(io_buf, sizeof(io_buf), "started sniffjoke as requested!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
		runconfig.active = true;
	} else /* sniffjoke is already runconfig */ {
		snprintf(io_buf, sizeof(io_buf), "received start request, but sniffjoke is already runconfig!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
	}
}

void UserConf::handle_cmd_stop()
{
	if (runconfig.active != false) {
		snprintf(io_buf, sizeof(io_buf), "stopped sniffjoke as requested!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
		runconfig.active = false;
	} else /* sniffjoke is already stopped */ {
		snprintf(io_buf, sizeof(io_buf), "received stop request, but sniffjoke is already stopped!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
	}
}

void UserConf::handle_cmd_quit()
{
	alive = false;
	debug.log(VERBOSE_LEVEL, "quit command requested: dumping configuration");
	snprintf(io_buf, sizeof(io_buf), "dumped configuration, starting shutdown\n");
}

void UserConf::handle_cmd_saveconf()
{
	dump();
	snprintf(io_buf, sizeof(io_buf), "configuration file dumped\n");
}

void UserConf::handle_cmd_stat(void) 
{
	debug.log(VERBOSE_LEVEL, "stat command requested");
	snprintf(io_buf, sizeof(io_buf), 
		"\nsniffjoke runconfig:\t\t%s\n" \
		"gateway mac address:\t\t%s\n" \
		"gateway ip address:\t\t%s\n" \
		"local interface:\t\t%s, %s address\n" \
		"dynamic tunnel interface:\ttun%d\n" \
		"log level:\t\t\t%d at file %s\n" \
		"plugins file:\t\t\t%s\n" \
		"chroot directory:\t\t%s\n",
		runconfig.active == true ? "TRUE" : "FALSE",
		runconfig.gw_mac_str,
		runconfig.gw_ip_addr,
		runconfig.interface, runconfig.local_ip_addr,
		runconfig.tun_number,
		runconfig.debug_level, runconfig.logfname,
		runconfig.enabler, runconfig.chroot_dir
	);
}

void UserConf::handle_cmd_info(void)
{
	snprintf(io_buf, sizeof(io_buf), "NOT IMPLEMENTED - analyze TTL and session\n");
}

void UserConf::handle_cmd_showport(void) 
{
	int i, acc_start = 0, kind, actual_io = 0;
	char *index = &io_buf[1];

	io_buf[0] = '\n';

	/* the first port work as initialization */
	kind = runconfig.portconf[0];

	for (i = 1; i < PORTNUMBER; i++) 
	{
		/* the kind has changed, so we must print the previous port range */
		if (runconfig.portconf[i] != kind) 
		{
			if (acc_start == (i - 1)) 
				snprintf(index, sizeof(io_buf) - actual_io, " %d\t%s\n", acc_start, resolve_weight_name(kind));
			else
				snprintf(index, sizeof(io_buf) - actual_io, " %d:%d\t%s\n", acc_start, i - 1, resolve_weight_name(kind));

			actual_io = strlen(io_buf);
			index = &io_buf[actual_io];

			kind = runconfig.portconf[i];
			acc_start = i;
		}
	}

	snprintf(index, sizeof(io_buf) - actual_io, " %d:%d\t%s\n", acc_start, PORTNUMBER, resolve_weight_name(kind));
}

void UserConf::handle_cmd_set(unsigned short start, unsigned short end, Strength what)
{
	const char *what_weightness;
	switch(what) {
		case HEAVY: what_weightness = "heavy"; break;
		case NORMAL: what_weightness = "normal"; break;
		case LIGHT: what_weightness = "light"; break;
		case NONE: what_weightness = "no hacking"; break;
		default: 
			snprintf(io_buf, sizeof(io_buf), "invalid strength code for TCP ports\n");
			debug.log(ALL_LEVEL, "BAD ERROR: %s", io_buf);
			return;
	}

	snprintf(io_buf, sizeof(io_buf), "set ports from %d to %d at [%s] level\n", start, end, what_weightness);
	debug.log(ALL_LEVEL, "%s", io_buf);

	if(end == PORTNUMBER) {
		runconfig.portconf[PORTNUMBER -1] = what;
		end--;
	}

	do {
		runconfig.portconf[start] = what;
		start++;
	} while (start <= end );
}

void UserConf::handle_cmd_listen(int bindport)
{
	runconfig.listenport[bindport] = true;
	snprintf(io_buf, sizeof(io_buf), "set port %d as listen service to protect\n", bindport);
	debug.log(ALL_LEVEL, "%s", io_buf);
}

void UserConf::handle_cmd_loglevel(int newloglevel)
{
	if(newloglevel < ALL_LEVEL || newloglevel > PACKETS_DEBUG) {
		snprintf(io_buf, sizeof(io_buf), 
			"error in the new loglevel requested: accepted >= %d and <= %d\n\n"\
			"\t1\tsuppressed log\n"\
			"\t2\tdefault, common log\n"\
			"\t3\tverbose\n"\
			"\t4\tdebug\n"\
			"\t5\tcreate $logfile.session, with a verbose logging in session tracking\n"\
			"\t6\tcreate $logfile.packets, with various logline for every packet\n",
			ALL_LEVEL, PACKETS_DEBUG
		);
	} else {
		snprintf(io_buf, sizeof(io_buf), "changing log level since %d to %d\n", runconfig.debug_level, newloglevel);
		runconfig.debug_level = newloglevel;
	}
}

bool UserConf::parse_port_weight(char *weightstr, Strength *value)
{
	struct parsedata {
		const char *keyword;
		const int keylen;
		Strength equiv;
	};
#define keywordToParse	4
	struct parsedata wParse[] = {
		{ "none", 	strlen("none"), 	NONE },
		{ "light", 	strlen("light"), 	LIGHT },
		{ "normal", 	strlen("normal"), 	NORMAL },
		{ "heavy", 	strlen("heavy"), 	HEAVY }
	};
	for(unsigned int i = 0; i < keywordToParse; i++) {
		if(!strncasecmp(weightstr, wParse[i].keyword, wParse[i].keylen)) {
			*value = wParse[i].equiv;
			return true;
		}
	}
	return false;
}
