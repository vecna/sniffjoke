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
#include "internalProtocol.h"

#include <cctype>
#include <sys/stat.h>

/* 
 * rules for parms:
 * sj_cmdline_opts contain only the option passed to the command line
 * ther other information are used as default.
 *
 * as priority, we use:
 * 1) a specific config or enabler file override location 
 * both of these file are looked by default in the INSTALL_SYSCONFDIR
 *
 * 3) if a location is used, is append to the base filename, and
 *    as default, is used the suffix ".generic"
 */
UserConf::UserConf(const struct sj_cmdline_opts &cmdline_opts, bool &sj_alive) :
	alive(sj_alive),
	chroot_status(false),
	sessiontrackmap(NULL),
	ttlfocusmap(NULL)
{
	debug.log(VERBOSE_LEVEL, __func__);

	memset(&runconfig, 0x00, sizeof(sj_config));

	if (!cmdline_opts.location[0]) {
		debug.log(ALL_LEVEL, "is highly suggestes to use sniffjoke specifying a location (--location option)");
		debug.log(ALL_LEVEL, "a defined location means that the network it's profiled for the best results");
		debug.log(ALL_LEVEL, "a brief explanation about this can be found at: http://www.delirandom.net/sniffjoke/location");
		memcpy(runconfig.location, DEFAULTLOCATION, strlen(DEFAULTLOCATION));
	} else {
		memcpy(runconfig.location, cmdline_opts.location, strlen(cmdline_opts.location));
		debug.log(ALL_LEVEL, "location will be '.%s' suffix to every config file required", cmdline_opts.location);
	}

	/* if the config file is explicit defined, are used, if not, are used the default.$LOCATION */
	if (cmdline_opts.cfgfname[0]) {
		snprintf(configfile, LARGEBUF, "%s", cmdline_opts.cfgfname);
	} else {
		snprintf(configfile, LARGEBUF, "%s.%s", CONF_FILE, runconfig.location);
	}

	/* load does NOT memset to 0 the runconfig struct! and load defaults if file are not present */
	load(cmdline_opts);

	/* the command line useopt is filled with the default in main.cc; if the user have overwritten with --options
	 * we need only to check if the previous value was different from the default */

	debug.log(DEBUG_LEVEL, "running variables: location %s enabled %s user %s group %s chroot %s admin address %s logfile %s packets log %s session log %s", runconfig.location, runconfig.enabler, runconfig.user, runconfig.group, runconfig.chroot_dir, runconfig.admin_address, runconfig.logfname, runconfig.logfname_packets, runconfig.logfname_sessions);


	/* SANITY CHECK BEFORE ACCEPT THE OPTIONS */
	FILE *test = sj_fopen(runconfig.enabler, runconfig.location, "r");
	if(test == NULL) {
		debug.log(ALL_LEVEL, "Sanity check: is required the enabler file, and the default (%s.%s) is not present", 
			runconfig.enabler, runconfig.location);
		debug.log(ALL_LEVEL, "sniffjoke-autotest script will generate the appropriate enabler for your location");
		SJ_RUNTIME_EXCEPTION("");
	}
	fclose(test);

	/* the configuration file must remain root:root 666 because the user should/must/can overwrite later */
	chmod(configfile, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
}

UserConf::~UserConf()
{
	debug.log(DEBUG_LEVEL, "%s [process %d chroot %s], referred config file %s",
		 __func__, getpid(), chroot_status ? "YES" : "NO", configfile);
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
	uint8_t i;

	debug.log(ALL_LEVEL, "++ detecting external gateway interface with [%s]", cmd);

	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && isalnum(imp_str[i]); ++i)
		runconfig.interface[i] = imp_str[i];

	if (i < 3) {
		debug.log(ALL_LEVEL, "-- default gateway not present: sniffjoke cannot be started");
		SJ_RUNTIME_EXCEPTION("");
	} else {
		debug.log(ALL_LEVEL, "  == detected external interface with default gateway: %s", runconfig.interface);
	}
}


void UserConf::autodetect_local_interface_ip_address()
{
	char cmd[MEDIUMBUF];
	FILE *foca;
	char imp_str[SMALLBUF];
	uint8_t i;
	snprintf(cmd, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21-", 
		runconfig.interface
	);

	debug.log(ALL_LEVEL, "++ detecting interface %s ip address with [%s]", runconfig.interface, cmd);

	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isdigit(imp_str[i]) || imp_str[i] == '.'); ++i)
		runconfig.local_ip_addr[i] = imp_str[i];

	debug.log(ALL_LEVEL, "  == acquired local ip address: %s", runconfig.local_ip_addr);
}


void UserConf::autodetect_gw_ip_address()
{
	const char *cmd = "route -n | grep ^0.0.0.0 | grep UG | cut -b 17-32"; 
	FILE *foca;
	char imp_str[SMALLBUF];
	uint8_t i;

	debug.log(ALL_LEVEL, "++ detecting gateway ip address with [%s]", cmd);

	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isdigit(imp_str[i]) || imp_str[i] == '.'); ++i) 
		runconfig.gw_ip_addr[i] = imp_str[i];
	if (strlen(runconfig.gw_ip_addr) < 7) {
		debug.log(ALL_LEVEL, "  -- unable to autodetect gateway ip address, sniffjoke cannot be started");
		SJ_RUNTIME_EXCEPTION("");
	} else  {
		debug.log(ALL_LEVEL, "  == acquired gateway ip address: %s", runconfig.gw_ip_addr);
	}
}

void UserConf::autodetect_gw_mac_address()
{
	char cmd[MEDIUMBUF];
	FILE *foca;
	char imp_str[SMALLBUF];
	uint8_t i;
	snprintf(cmd, MEDIUMBUF, "ping -W 1 -c 1 %s", runconfig.gw_ip_addr);

	debug.log(ALL_LEVEL, "++ pinging %s for ARP table popoulation motivations [%s]", runconfig.gw_ip_addr, cmd);
	
	foca = popen(cmd, "r");
	/* we do not need the output of ping, we need to wait the ping to finish
	 * and pclose does this =) */
	pclose(foca);
	
	memset(cmd, 0x00, sizeof(cmd));
	snprintf(cmd, MEDIUMBUF, "arp -n | grep \"%s \" | cut -b 34-50", runconfig.gw_ip_addr);
	debug.log(ALL_LEVEL, "++ detecting mac address of gateway with %s", cmd);
	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isxdigit(imp_str[i]) || imp_str[i] == ':'); ++i)
		runconfig.gw_mac_str[i] = imp_str[i];
	if (i != 17) {
		debug.log(ALL_LEVEL, "  -- unable to autodetect gateway mac address");
		SJ_RUNTIME_EXCEPTION("");
	} else {
		debug.log(ALL_LEVEL, "  == automatically acquired mac address: %s", runconfig.gw_mac_str);
		uint32_t mac[6];
		sscanf(runconfig.gw_mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		for (i=0; i<6; ++i)
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
	for (runconfig.tun_number = 0; ; ++runconfig.tun_number)
	{
		memset(imp_str, 0x00, sizeof(imp_str));
		fgets(imp_str, SMALLBUF, foca);
		if (imp_str[0] == 0x00)
			break;
	}
	pclose(foca);
	debug.log(ALL_LEVEL, "  == detected %d as first unused tunnel device", runconfig.tun_number);
}

/* this method is called by SniffJoke.cc */
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

	snprintf(runconfig.ttlfocuscache_file, MEDIUMBUF, "%s_%s", TTLFOCUSCACHE_FILE, runconfig.gw_mac_str);
}

/* internal function called by the overloaded parseMatch */
bool UserConf::parseLine(FILE *cf, char userchoose[SMALLBUF], const char *keyword) {
	rewind(cf);
	char line[MEDIUMBUF];

	do {
		fgets(line, MEDIUMBUF, cf);

                if (line[0] == '#' || line[0] == '\n' || line[0] == ' ')
                        continue;

		if(strlen(line) < (strlen(keyword) + 3) )
			continue;

		if(!memcmp(keyword, line, strlen(keyword))) {
			/* C's chop() */
			line[strlen(line) -1] = 0x00;
			memcpy(userchoose, (&line[strlen(keyword) + 1]), strlen(line) - strlen(keyword) - 1);
			return true;
		}
	} while(!feof(cf));

	return false;
}

/* start with the less used (only one time, for this reason differ) parseMatch overloaded name */
bool UserConf::parseMatch(bool &dst, const char *name, FILE *cf, bool cmdopt, const bool difolt)
{
	char useropt[SMALLBUF];

	/* command line priority always */
	if(cmdopt != difolt)
		return cmdopt;
	else
		dst = difolt;

	if(cf == NULL)
		return difolt;

	memset(useropt, 0x00, SMALLBUF);

	if(parseLine(cf, useropt, name)) 
	{
		debug.log(ALL_LEVEL, "%s/bool: parsed keyword %s [%s] option in conf file", __func__, name, useropt);
		/* dst is large MEDIUMBUF, and none useropt will overflow this size */
		if(!memcmp(useropt, "true", strlen("true")))
			dst = true;

		if(!memcmp(useropt, "false", strlen("false")))
			dst = false;

		return true;
	}
	return false;
}

bool UserConf::parseMatch(char *dst, const char *name, FILE *cf, const char *cmdopt, const char *difolt)
{
	char useropt[SMALLBUF];
	memset(useropt, 0x00, SMALLBUF);

	/* only-plugin will be empty, no other cases */
	if(cf == NULL && difolt == NULL)
		return false;

	/* if the file is NULL, the default is used */
	if(cf == NULL) {
		memcpy(dst, difolt, strlen(difolt));
		return true;
	}

	if(parseLine(cf, useropt, name)) 
	{
		debug.log(ALL_LEVEL, "%s/string: parsed keyword %s [%s] option in conf file", __func__, name, useropt);
		/* dst is large MEDIUMBUF, and none useropt will overflow this size */
		memcpy(dst, useropt, strlen(useropt));

		if(!memcmp(dst,cmdopt,strlen(dst)) && !memcmp(dst,difolt,strlen(difolt))) 
		{
			debug.log(ALL_LEVEL, "warning, config file specify '%s' as %s, command line as %s (default %s). used %s",
				name, dst, cmdopt, difolt, cmdopt);
			memcpy(dst, cmdopt, strlen(cmdopt));
		}
		return true;
	}

	if(difolt != NULL)
		memcpy(dst, difolt, strlen(difolt));

	return false;
}

bool UserConf::parseMatch(uint16_t &dst, const char *name, FILE *cf, uint16_t cmdopt, const uint16_t difolt)
{
	char useropt[SMALLBUF];
	/* if the file is NULL, the default is used */
	if(cf == NULL) {
		memcpy( (void *)&dst, (void *)&difolt, sizeof(difolt));
		return true;
	}
	memset(useropt, 0x00, SMALLBUF);

	if(parseLine(cf, useropt, name)) 
	{
		debug.log(ALL_LEVEL, "%s/uint16: parsed keyword %s [%s] option in conf file", __func__, name, useropt);
		dst = atoi(useropt);

		if(dst != cmdopt && dst != difolt) 
		{
			debug.log(ALL_LEVEL, "warning, config file specify '%s' as %d, command line as %d (default %d). used %d",
				name, dst, cmdopt, difolt, cmdopt);
			dst = cmdopt;
		}
		return true;
	}

	if(difolt)
		dst = difolt;

	return false;
}

bool UserConf::load(const struct sj_cmdline_opts &cmdline_opts)
{
	FILE *loadfd;	

	if ((loadfd = sj_fopen(configfile, "r")) == NULL)
		debug.log(ALL_LEVEL, "configuration file %s not accessible: %s, using default", configfile, strerror(errno));
	else
		debug.log(DEBUG_LEVEL, "opening configuration file: %s", configfile);

	parseMatch(runconfig.enabler, "enabler", loadfd, cmdline_opts.enabler, PLUGINSENABLER);
	parseMatch(runconfig.user, "user", loadfd, cmdline_opts.user, DROP_USER);
	parseMatch(runconfig.group, "group", loadfd, cmdline_opts.group, DROP_GROUP);
	parseMatch(runconfig.chroot_dir, "chroot", loadfd, cmdline_opts.chroot_dir, CHROOT_DIR);
	parseMatch(runconfig.admin_address, "management", loadfd, cmdline_opts.admin_address, DEFAULT_ADMIN_ADDRESS);

	parseMatch(runconfig.logfname, "logfile", loadfd, cmdline_opts.admin_address, LOGFILE);
	if(runconfig.logfname[0] == '/' || runconfig.logfname[0] == '.') 
		SJ_RUNTIME_EXCEPTION("the logfile option will only be under chroot: not accepted path with '/' or '..'");
	snprintf(runconfig.logfname_packets, LARGEBUF, "%s.%s", runconfig.logfname, SUFFIX_LF_PACKETS);
	snprintf(runconfig.logfname_sessions, LARGEBUF, "%s.%s", runconfig.logfname, SUFFIX_LF_SESSIONS);

	parseMatch(runconfig.admin_port, "management-port", loadfd, cmdline_opts.admin_port, DEFAULT_ADMIN_PORT);
	parseMatch(runconfig.debug_level, "debug", loadfd, cmdline_opts.debug_level, DEFAULT_DEBUG_LEVEL);
	parseMatch(runconfig.onlyplugin, "only-plugin", loadfd, cmdline_opts.onlyplugin, NULL);
	if(runconfig.onlyplugin[0])
		debug.log(VERBOSE_LEVEL, "single plugin %s will override plugins list in the enabler file", runconfig.onlyplugin);

	parseMatch(runconfig.active, "active", loadfd, cmdline_opts.active, DEFAULT_START_STOPPED);
	parseMatch(runconfig.max_ttl_probe, "max-ttl-probe", loadfd, cmdline_opts.max_ttl_probe, DEFAULT_MAX_TTLPROBE);

	/* in main.cc not supporte ATM */
	parseMatch(runconfig.aggressivity_file, "aggressivity-file", loadfd, cmdline_opts.aggressivity_file, NULL);
	parseMatch(runconfig.frequency_file, "frequency-file", loadfd, cmdline_opts.frequency_file, NULL);

	/* TODO BOTH OF THEM 						*/
	/* loadAggressivity(runconfig.aggressivity_file); 		*/
	/* loadFrequency(runconfig.frequency_file); 			*/
	/* YES, XXX, TODO INSTEAD OF: 					*/
	for(uint16_t i = 0; i < PORTNUMBER; ++i)
		runconfig.portconf[i] = NORMAL;

	if(loadfd)
		fclose(loadfd);

	return true;
}

void UserConf::attach_sessiontrackmap(SessionTrackMap* s)
{
	sessiontrackmap = s;
}

void UserConf::attach_ttlfocusmap(TTLFocusMap* t)
{
	ttlfocusmap = t;
}

uint8_t* UserConf::handle_cmd(const char *cmd)
{
	memset(io_buf, 0x00, sizeof(io_buf));

	debug.log(DEBUG_LEVEL, "command received begin processed: [%s]", cmd);

	/* the handle_cmd_* fill partialy the io_buf, as defined
	 * protocol, the first 4 byte represent the length of the
	 * data, uint32_t lenght included.
	 * the data returned is conform
	 * to the specification in doc/SJ-PROTOCOL.txt */

	if (!memcmp(cmd, "start", strlen("start"))) {
		handle_cmd_start();
	} else if (!memcmp(cmd, "stop", strlen("stop"))) {
		handle_cmd_stop();
	} else if (!memcmp(cmd, "quit", strlen("quit"))) {
		handle_cmd_quit();
	} else if (!memcmp(cmd, "dump", strlen("dump"))) {
		handle_cmd_dump();
	} else if (!memcmp(cmd, "stat", strlen("stat"))) {
		handle_cmd_stat();
	} else if (!memcmp(cmd, "info", strlen("info"))) {
		handle_cmd_info();
	} else if (!memcmp(cmd, "showport", strlen("showport"))) {
		handle_cmd_showport();
	} else if (!memcmp(cmd, "set", strlen("set"))) {
		uint32_t start_port, end_port, value;
		/* Strength setValue; did Strenght be required anymore ? */

		sscanf(cmd, "set %u %u %u", &start_port, &end_port, &value);

		if (start_port < 0 || start_port > PORTNUMBER || end_port < 0 || end_port > PORTNUMBER)
			goto handle_error;

		if (start_port > end_port)
			goto handle_error;

		handle_cmd_set(start_port, end_port, value);
	} else if (!memcmp(cmd, "clear", strlen("clear"))) {
		uint8_t clearPortValue = NONE;
		handle_cmd_set(0, PORTNUMBER, clearPortValue);
	} else if (!memcmp(cmd, "debug", strlen("debug")))  {
		int32_t debuglevel;

		sscanf(cmd, "debug %d", &debuglevel);
		if (debuglevel < 0 || debuglevel > PACKETS_DEBUG)
			goto handle_error;

		handle_cmd_debuglevel(debuglevel);
	}
	else {
		debug.log(ALL_LEVEL, "Invalid command received");
	}

	/* extract the size of the answer: ((unsigned int *)io_buf)[0] */
	debug.log(ALL_LEVEL, "handled command (%s): answer %d bytes length", cmd, ((unsigned int *)io_buf)[0] );
	return &io_buf[0];

handle_error:
	debug.log(ALL_LEVEL, "invalid command received");
	write_SJProtoError();

	return &io_buf[0];
}

void UserConf::handle_cmd_start()
{
	if (runconfig.active != true) {
		debug.log(VERBOSE_LEVEL, "%s: started sniffjoke as requested!", __func__);
	} else /* sniffjoke is already runconfig */ {
		debug.log(VERBOSE_LEVEL, "%s: start requested by already running service", __func__);
	}
	runconfig.active = true;
	/* this function fill io_buf with the status information */
	write_SJStatus(START_COMMAND_TYPE);
}

void UserConf::handle_cmd_stop()
{
	if (runconfig.active != false) {
		debug.log(VERBOSE_LEVEL, "%s: stopped sniffjoke as requested!", __func__);
	} else /* sniffjoke is already runconfig */ {
		debug.log(VERBOSE_LEVEL, "%s: stop requested by already stopped service", __func__);
	}
	runconfig.active =false;
	/* this function fill io_buf with the status information */
	write_SJStatus(STOP_COMMAND_TYPE);
}

void UserConf::handle_cmd_quit()
{
	alive = false;
	debug.log(VERBOSE_LEVEL, "%s: starting shutdown", __func__);
	write_SJStatus(QUIT_COMMAND_TYPE);
}

/* simple utiliy for dumping */
uint32_t UserConf::dumpIfPresent(uint8_t *p, uint32_t datal, const char *name, char *data) {
	uint32_t written = 0;

	if(data[0]) {
		written = snprintf((char *)p, datal, "%s:%s\n", name, data);
	}
	return written;
}

uint32_t UserConf::dumpComment(uint8_t *p, uint32_t datal, const char *writedblock) {
	return snprintf((char *)p, datal, writedblock);
}

void UserConf::handle_cmd_dump()
{
	struct command_ret retInfo;
	uint32_t dumplen = sizeof(retInfo);
	uint32_t avail = HUGEBUF - dumplen;

	debug.log(VERBOSE_LEVEL, "%s: configuration dumped to the client", __func__);
	avail -= dumpComment(io_buf, avail, "# this is a dumped file by SniffJoke version ");
	avail -= dumpComment(io_buf, avail, SW_VERSION);
	avail -= dumpComment(io_buf, avail, "\n");
	avail -= dumpIfPresent(io_buf, avail, "enabler", runconfig.enabler);
	avail -= dumpIfPresent(io_buf, avail, "chroot", runconfig.chroot_dir);

	retInfo.command_type = DUMP_COMMAND_TYPE;
	retInfo.len = HUGEBUF - avail;
	memcpy(&io_buf[0], &retInfo, sizeof(retInfo));
}

void UserConf::handle_cmd_stat(void) 
{
	debug.log(VERBOSE_LEVEL, "%s: stat requested", __func__);
	write_SJStatus(STAT_COMMAND_TYPE);
}

void UserConf::handle_cmd_info(void)
{
	write_SJStatus(INFO_COMMAND_TYPE);
	debug.log(VERBOSE_LEVEL, "%s: info command NOT IMPLEMENTED", __func__);
}

void UserConf::handle_cmd_showport(void) 
{
	write_SJPortStat(SHOWPORT_COMMAND_TYPE);
}

void UserConf::handle_cmd_set(uint16_t start, uint16_t end, uint8_t what)
{
	debug.log(VERBOSE_LEVEL, "%s: set TCP ports from %d to %d at %d strenght level", 
		__func__, start, end, what);

	if (end == PORTNUMBER) {
		runconfig.portconf[PORTNUMBER - 1] = what;
		--end;
	}

	do {
		runconfig.portconf[start++] = what;
	} while (start <= end);

	write_SJPortStat(SETPORT_COMMAND_TYPE);
}

void UserConf::handle_cmd_debuglevel(int32_t newdebuglevel)
{
	if (newdebuglevel < ALL_LEVEL || newdebuglevel > PACKETS_DEBUG) {
		debug.log(ALL_LEVEL, "%s: requested debuglevel %d invalid (>= %d <= %d permitted)",
			__func__, newdebuglevel, ALL_LEVEL, PACKETS_DEBUG
		);
	} else {
		debug.log(ALL_LEVEL, "%s: changing log level since %d to %d\n", __func__, runconfig.debug_level, newdebuglevel);
		runconfig.debug_level = newdebuglevel;
	}
	write_SJStatus(LOGLEVEL_COMMAND_TYPE);
}

/*
 * follow the method used for compose the io_buf with the internalProtocol.h struct,
 * those methods are intetnal in UserConf, and are, exception noted for handle_cmd_dump,
 * the only commands writing in io_buf and generating answer.
 */
void UserConf::write_SJPortStat(uint8_t type)
{
	int i, prev_port = 1, prev_kind;
	struct command_ret retInfo;

	/* clean the buffer and fix the starting pointer */
	memset(io_buf, 0x00, HUGEBUF);
	uint8_t *p = &io_buf[sizeof(retInfo)];

	/* the first port work as initialization */
	prev_kind = runconfig.portconf[0];

	for (i = 1; i < PORTNUMBER; ++i) 
	{
		if (runconfig.portconf[i] != prev_kind)
		{
			p = append_SJportBlock(p, prev_port, i - 1, prev_kind);

			prev_kind = runconfig.portconf[i];
			prev_port = i;
		}
	}

	p = append_SJportBlock(p, prev_port, PORTNUMBER, prev_kind);

	retInfo.len = p - &io_buf[0];
	retInfo.command_type = type;
	memcpy(&io_buf[0], &retInfo, sizeof(retInfo));
}

void UserConf::write_SJStatus(uint8_t commandReceived)
{
	struct command_ret retInfo;

	/* clean the buffer and fix the starting pointer */
	memset(io_buf, 0x00, HUGEBUF);
	uint8_t *p = &io_buf[sizeof(retInfo)];

	/* SJStatus is totally inspired by the IP/TCP options */
	p = appendSJStatus(p, STAT_ACTIVE, sizeof(bool), runconfig.active);
	p = appendSJStatus(p, STAT_MACGW, strlen(runconfig.gw_mac_str), runconfig.gw_mac_str);
	p = appendSJStatus(p, STAT_GWADDR, strlen(runconfig.gw_ip_addr), runconfig.gw_ip_addr);
	p = appendSJStatus(p, STAT_IFACE, strlen(runconfig.interface), runconfig.interface);
	p = appendSJStatus(p, STAT_LOIP, strlen(runconfig.local_ip_addr), runconfig.local_ip_addr);
	p = appendSJStatus(p, STAT_TUNN, sizeof(uint16_t), (uint16_t)runconfig.tun_number);
	p = appendSJStatus(p, STAT_DEBUGL, sizeof(uint16_t), (uint16_t)runconfig.debug_level);
	p = appendSJStatus(p, STAT_LOGFN, strlen(runconfig.logfname), runconfig.logfname);
	p = appendSJStatus(p, STAT_CHROOT, strlen(runconfig.chroot_dir), runconfig.chroot_dir);
	p = appendSJStatus(p, STAT_ENABLR, strlen(runconfig.enabler), runconfig.enabler);
	p = appendSJStatus(p, STAT_LOCAT, strlen(runconfig.location), runconfig.location);
	p = appendSJStatus(p, STAT_ONLYP, strlen(runconfig.onlyplugin), runconfig.onlyplugin);
	p = appendSJStatus(p, STAT_BINDA, strlen(runconfig.admin_address), runconfig.admin_address);
	p = appendSJStatus(p, STAT_BINDP, sizeof(uint16_t), runconfig.admin_port);
	p = appendSJStatus(p, STAT_USER, strlen(runconfig.user), runconfig.user);
	p = appendSJStatus(p, STAT_GROUP, strlen(runconfig.group), runconfig.group);

	retInfo.len = (uint32_t)p - (uint32_t)&io_buf[0];
	retInfo.command_type = commandReceived;
	memcpy(&io_buf[0], &retInfo, sizeof(retInfo));
}

void UserConf::write_SJProtoError(void) 
{
	struct command_ret retInfo;
	memset(io_buf, 0x00, HUGEBUF);
	retInfo.len = sizeof(retInfo);
	retInfo.command_type = COMMAND_ERROR_MSG;
	memcpy(&io_buf[0], &retInfo, sizeof(retInfo));
}

/* follow the most "internal" method for io_buf creation, called from the methods before  */
uint8_t *UserConf::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, uint16_t value)
{
	*p = len + 2;
	*++p = (uint8_t)WHO;
	p++;
	memcpy(p, &value, len);

	return (p + len);
}

uint8_t *UserConf::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, bool value)
{
	*p = len + 2;
	*++p = (uint8_t)WHO;
	*++p = value;

	return (p + len);
}

uint8_t *UserConf::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, char value[MEDIUMBUF])
{
	*p = len + 2;
	*++p = (uint8_t)WHO;
	p++;
	memcpy(p, value, len);

	return (p + len);
}

uint8_t *UserConf::append_SJportBlock(uint8_t *p, uint16_t startP, uint16_t endP, uint8_t weight)
{
	struct port_info pInfo;

	pInfo.start = startP;
	pInfo.end = endP;
	pInfo.weight = weight;

	memcpy(p, &pInfo, sizeof(pInfo));
	return (p + sizeof(pInfo) );
}
