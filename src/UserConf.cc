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

/* Read command line values if present, preserve the previous options, and otherwise import default */
void UserConf::compare_check_copy(char *target, unsigned int tlen, const char *useropt, unsigned int ulen, const char *sjdefault)
{
	int blen = ulen > strlen(sjdefault) ? strlen(sjdefault) : ulen;

	/* zero choice: if running.data[0] == 0x00, is the first start: write the default in the empty buffer */
	memcpy(target, sjdefault, strlen(sjdefault));

	/* first choice: if the user had specify an option (!= default), is used immediatly */
	if(memcmp(useropt, sjdefault, blen)) {
		memcpy(target, useropt, ulen > tlen ? tlen : ulen );
		return;
	}

	/* second choice: take the useropt/default remaining */
	memcpy(target, useropt, ulen > tlen ? tlen : ulen);
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
		running.interface[i] = imp_str[i];

	if (i < 3) {
		debug.log(ALL_LEVEL, "-- default gateway not present: sniffjoke cannot be started");
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(ALL_LEVEL, "  == detected external interface with default gateway: %s", running.interface);
	}
}


void UserConf::autodetect_local_interface_ip_address()
{
	char cmd[MEDIUMBUF];
	FILE *foca;
	char imp_str[SMALLBUF];
	unsigned int i;
	snprintf(cmd, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21-", 
		running.interface
	);

	debug.log(ALL_LEVEL, "++ detecting interface %s ip address with [%s]", running.interface, cmd);

	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isdigit(imp_str[i]) || imp_str[i] == '.'); i++)
		running.local_ip_addr[i] = imp_str[i];

	debug.log(ALL_LEVEL, "  == acquired local ip address: %s", running.local_ip_addr);
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
		running.gw_ip_addr[i] = imp_str[i];
	if (strlen(running.gw_ip_addr) < 7) {
		debug.log(ALL_LEVEL, "  -- unable to autodetect gateway ip address, sniffjoke cannot be started");
		SJ_RUNTIME_EXCEPTION();
	} else  {
		debug.log(ALL_LEVEL, "  == acquired gateway ip address: %s", running.gw_ip_addr);
	}
}

void UserConf::autodetect_gw_mac_address()
{
	char cmd[MEDIUMBUF];
	FILE *foca;
	char imp_str[SMALLBUF];
	unsigned int i;
	snprintf(cmd, MEDIUMBUF, "ping -W 1 -c 1 %s", running.gw_ip_addr);

	debug.log(ALL_LEVEL, "++ pinging %s for ARP table popoulation motivations [%s]", running.gw_ip_addr, cmd);
	
	system(cmd);
	sleep(1);
	memset(cmd, 0x00, MEDIUMBUF);
	snprintf(cmd, MEDIUMBUF, "arp -n | grep %s | cut -b 34-50", running.gw_ip_addr);
	debug.log(ALL_LEVEL, "++ detecting mac address of gateway with %s", cmd);
	foca = popen(cmd, "r");
	fgets(imp_str, SMALLBUF, foca);
	pclose(foca);

	for (i = 0; i < strlen(imp_str) && (isxdigit(imp_str[i]) || imp_str[i] == ':'); i++)
		running.gw_mac_str[i] = imp_str[i];
	if (i != 17) {
		debug.log(ALL_LEVEL, "  -- unable to autodetect gateway mac address");
		SJ_RUNTIME_EXCEPTION();
	} else {
		debug.log(ALL_LEVEL, "  == automatically acquired mac address: %s", running.gw_mac_str);
		unsigned int mac[6];
		sscanf(running.gw_mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		for (i=0; i<6; i++)
			running.gw_mac_addr[i] = mac[i];
	
	}
}

void UserConf::autodetect_first_available_tunnel_interface()
{
	const char *cmd = "ifconfig -a | grep tun | cut -b -7";
	FILE *foca;
	char imp_str[SMALLBUF];

	debug.log(ALL_LEVEL, "++ detecting first unused tunnel device with [%s]", cmd);
	
	foca = popen(cmd, "r");
	for (running.tun_number = 0; ; running.tun_number++)
	{
		memset(imp_str, 0x00, SMALLBUF);
		fgets(imp_str, SMALLBUF, foca);
		if (imp_str[0] == 0x00)
			break;
	}
	pclose(foca);
	debug.log(ALL_LEVEL, "  == detected %d as first unused tunnel device", running.tun_number);
}

/* this method is used only in the ProcessType = SERVICE CHILD */
void UserConf::network_setup(void)
{

	debug.log(DEBUG_LEVEL, "Initializing network for service/child: %d", getpid());

	if(running.active)
		debug.log(VERBOSE_LEVEL, "-- sniffjoke loaded to run immediatly");
	else
		debug.log(VERBOSE_LEVEL, "-- sniffjoke loaded and stopped at the moment, waiting for \"sniffjoke start\" command");

	/* autodetect is always used, we should not trust the preloaded configuration */
	autodetect_local_interface();
	autodetect_local_interface_ip_address();
	autodetect_gw_ip_address();
	autodetect_gw_mac_address();
	autodetect_first_available_tunnel_interface();

	debug.log(VERBOSE_LEVEL, "-- system local interface: %s, %s address", running.interface, running.local_ip_addr);
	debug.log(VERBOSE_LEVEL, "-- default gateway mac address: %s", running.gw_mac_str);
	debug.log(VERBOSE_LEVEL, "-- default gateway ip address: %s", running.gw_ip_addr);
	debug.log(VERBOSE_LEVEL, "-- first available tunnel interface: tun%d", running.tun_number);


	/* FIXME, is this incomplete? who does set this ? */
	if(running.port_conf_set_n) {
		debug.log(VERBOSE_LEVEL,"-- loaded %d TCP port set, verify them with sniffjoke stat",
			running.port_conf_set_n
		);
	}
}

UserConf::UserConf(const struct sj_cmdline_opts &cmdline_opts) :
	chroot_status(false)
{
	setup_debug(cmdline_opts);

	char configfile[LARGEBUF];	
	snprintf(configfile, LARGEBUF, "%s%s", cmdline_opts.chroot_dir, cmdline_opts.cfgfname);	
	
	memset(&running, 0x00, sizeof(sj_config));
	
	if(!load(configfile)) {
		debug.log(ALL_LEVEL, "configuration file: %s not found: using defaults", configfile);

		/* set up defaults */	   
		running.MAGIC = MAGICVAL;
		running.active = false;
		running.chrooted = false;
		running.max_ttl_probe = 30;
		running.max_sex_track = 4096;

		/* default is to set all TCP ports in "NORMAL" aggressivity level */
		for(int i = 0; i < PORTNUMBER; i++)
			running.portconf[i] = NORMAL;
	}

	/* the command line useopt is filled with the default in main.cc; if the user have overwritten with --options
	 * we need only to check if the previous value was different from the default */
	compare_check_copy(running.cfgfname, MEDIUMBUF, cmdline_opts.cfgfname, strlen(cmdline_opts.cfgfname), CONF_FILE);
	compare_check_copy(running.enabler, MEDIUMBUF, cmdline_opts.enabler, strlen(cmdline_opts.enabler), PLUGINSENABLER);
	compare_check_copy(running.user, MEDIUMBUF, cmdline_opts.user, strlen(cmdline_opts.user), DROP_USER);
	compare_check_copy(running.group, MEDIUMBUF, cmdline_opts.group, strlen(cmdline_opts.group), DROP_GROUP);
	compare_check_copy(running.chroot_dir, MEDIUMBUF, cmdline_opts.chroot_dir, strlen(cmdline_opts.chroot_dir), CHROOT_DIR);
	compare_check_copy(running.logfname, MEDIUMBUF, cmdline_opts.logfname, strlen(cmdline_opts.logfname), LOGFILE);

	/* because write a sepecific "unsigned int" version of compare_check_copy was dirty ... */
	if(cmdline_opts.debug_level != DEFAULT_DEBUG_LEVEL)
		running.debug_level = cmdline_opts.debug_level;

	if(running.debug_level == 0)
		running.debug_level = DEFAULT_DEBUG_LEVEL; // equal to ALL_LEVEL

	dump();

	/* the configuration file must remain root:root 666 because the user should/must/can overwrite later */
	chmod(configfile, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
}

UserConf::~UserConf()
{
	debug.log(ALL_LEVEL, "UserConf: pid %d cleaning configuration object", getpid());
}

bool UserConf::load(const char* configfile)
{
	FILE *loadfd;
	
	debug.log(DEBUG_LEVEL, "opening configuration file: %s", configfile);

	if ((loadfd = fopen(configfile, "r")) != NULL) 
	{
		memset(&running, 0x00, sizeof(struct sj_config));

		if(fread((void *)&running, sizeof(struct sj_config), 1, loadfd) != 1) {
			debug.log(ALL_LEVEL, "unable to read %d bytes from %s, maybe the wrong file ?",
				sizeof(running), configfile, strerror(errno)
			);
			SJ_RUNTIME_EXCEPTION();
		}

		debug.log(DEBUG_LEVEL, "reading of %s: %d byte readed", configfile, sizeof(struct sj_config));

		if (running.MAGIC != MAGICVAL) {
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

	running.MAGIC = MAGICVAL;

	if(!chroot_status)
		snprintf(configfile, LARGEBUF, "%s%s", running.chroot_dir, running.cfgfname);
	else
		snprintf(configfile, LARGEBUF, "%s", running.cfgfname);
	
	if((dumpfd = fopen(configfile, "w")) != NULL) {	
		debug.log(VERBOSE_LEVEL, "dumping running configuration to %s",  configfile);

		if((fwrite(&running, sizeof(struct sj_config), 1, dumpfd)) != 1) /* ret - 1 because fwrite return the number of written item */
		{
			debug.log(ALL_LEVEL, "unable to write configuration to %s: %s", 
				configfile, strerror(errno)
			);
		}
		fclose(dumpfd);
	}
}

char *UserConf::handle_cmd_start(void)
{
	memset(io_buf, 0x00, HUGEBUF);
	if (running.active != true) {
		snprintf(io_buf, HUGEBUF, "started sniffjoke as requested!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
		running.active = true;
	} else /* sniffjoke is already running */ {
		snprintf(io_buf, HUGEBUF, "received start request, but sniffjoke is already running!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
	}
	return &io_buf[0];
}

char *UserConf::handle_cmd_stop(void)
{
	memset(io_buf, 0x00, HUGEBUF);
	if (running.active != false) {
		snprintf(io_buf, HUGEBUF, "stopped sniffjoke as requested!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
		running.active = false;
	} else /* sniffjoke is already stopped */ {
		snprintf(io_buf, HUGEBUF, "received stop request, but sniffjoke is already stopped!\n");
		debug.log(VERBOSE_LEVEL, "%s", io_buf);
	}
	return &io_buf[0];
}

char *UserConf::handle_cmd_quit(void)
{
	memset(io_buf, 0x00, HUGEBUF);
	debug.log(VERBOSE_LEVEL, "quit command requested: dumping configuration");
	/* dump the configuration in the binconf file */
	dump();

	snprintf(io_buf, HUGEBUF, "dumped configuration, starting shutdown\n");

	return &io_buf[0];
}

char *UserConf::handle_cmd_saveconfig()
{
	memset(io_buf, 0x00, HUGEBUF);
	
	dump();

	snprintf(io_buf, HUGEBUF, "configuration file dumped\n");

	return &io_buf[0];
}

char *UserConf::handle_cmd_stat(void) 
{
	memset(io_buf, 0x00, HUGEBUF);
	debug.log(VERBOSE_LEVEL, "stat command requested");
	snprintf(io_buf, HUGEBUF, 
		"\nsniffjoke running:\t\t%s\n" \
		"gateway mac address:\t\t%s\n" \
		"gateway ip address:\t\t%s\n" \
		"local interface:\t\t%s, %s address\n" \
		"dynamic tunnel interface:\ttun%d\n" \
		"log level:\t\t%d at file %s\n" \
		"plugins file:\t\t%s\n" \
		"chroot directory:\t%s\n",
		running.active == true ? "TRUE" : "FALSE",
		running.gw_mac_str,
		running.gw_ip_addr,
		running.interface, running.local_ip_addr,
		running.tun_number,
		running.debug_level, running.logfname,
		running.enabler, running.chroot_dir
	);
	return &io_buf[0];
}

char *UserConf::handle_cmd_info(void)
{
	memset(io_buf, 0x00, HUGEBUF);
	snprintf(io_buf, HUGEBUF, "NOT IMPLEMENTED - analyze TTL and session\n");

	return &io_buf[0];
}

char *UserConf::handle_cmd_showport(void) 
{
	int i, acc_start = 0, kind, actual_io = 0;
	char *index = &io_buf[1];
	memset(io_buf, 0x00, HUGEBUF);
	io_buf[0] = '\n';

	/* the first port work as initialization */
	kind = running.portconf[0];

	for (i = 1; i < PORTNUMBER; i++) 
	{
		/* the kind has changed, so we must print the previous port range */
		if (running.portconf[i] != kind) 
		{
			if (acc_start == (i - 1)) 
				snprintf(index, HUGEBUF - actual_io, " %d\t%s\n", acc_start, resolve_weight_name(kind));
			else
				snprintf(index, HUGEBUF - actual_io, " %d:%d\t%s\n", acc_start, i - 1, resolve_weight_name(kind));

			actual_io = strlen(io_buf);
			index = &io_buf[actual_io];

			kind = running.portconf[i];
			acc_start = i;
		}
	}

	snprintf(index, HUGEBUF - actual_io, " %d:%d\t%s\n", acc_start, PORTNUMBER, resolve_weight_name(kind));

	return &io_buf[0];
}

char *UserConf::handle_cmd_set(unsigned short start, unsigned short end, Strength what)
{
	const char *what_weightness;
	memset(io_buf, 0x00, HUGEBUF);

	switch(what) {
		case HEAVY: what_weightness = "heavy"; break;
		case NORMAL: what_weightness = "normal"; break;
		case LIGHT: what_weightness = "light"; break;
		case NONE: what_weightness = "no hacking"; break;
		default: 
			snprintf(io_buf, HUGEBUF, "invalid strength code for TCP ports\n");
			debug.log(ALL_LEVEL, "BAD ERROR: %s", io_buf);
			return &io_buf[0];
	}

	snprintf(io_buf, HUGEBUF, "set ports from %d to %d at [%s] level\n", start, end, what_weightness);
	debug.log(ALL_LEVEL, "%s", io_buf);

	if(end == PORTNUMBER) {
		running.portconf[PORTNUMBER -1] = what;
		end--;
	}

	do {
		running.portconf[start] = what;
		start++;
	} while (start <= end );

	return &io_buf[0];
}

char *UserConf::handle_cmd_loglevel(int newloglevel)
{
	memset(io_buf, 0x00, HUGEBUF);
	if(newloglevel < ALL_LEVEL || newloglevel > PACKETS_DEBUG) {
		snprintf(io_buf, HUGEBUF, 
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
		snprintf(io_buf, HUGEBUF, "changing log level since %d to %d\n", running.debug_level, newloglevel);
		running.debug_level = newloglevel;
	}

	return &io_buf[0];
}

void UserConf::setup_debug(const struct sj_cmdline_opts &cmdline_opts)
{
	if (!cmdline_opts.go_foreground) {
		char tmpfname[LARGEBUF];
		if ((debug.logstream = fopen(cmdline_opts.logfname, "a+")) == NULL) {
			debug.log(ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", cmdline_opts.logfname, strerror(errno));
			SJ_RUNTIME_EXCEPTION();
		} else {
			debug.log(DEBUG_LEVEL, "opened log file %s", cmdline_opts.logfname);
		}	
	
		debug.debuglevel = cmdline_opts.debug_level;
		if (debug.debuglevel >= PACKETS_DEBUG) {
			snprintf(tmpfname, LARGEBUF, "%s.packets", cmdline_opts.logfname);
			if ((debug.packet_logstream = fopen(tmpfname, "a+")) == NULL) {
				debug.log(ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				SJ_RUNTIME_EXCEPTION();
			} else {
				debug.log(ALL_LEVEL, "opened for packets debug: %s successful", tmpfname);
			}
		}

		if (debug.debuglevel >= SESSION_DEBUG) {
			snprintf(tmpfname, LARGEBUF, "%s.session", cmdline_opts.logfname);
			if ((debug.session_logstream = fopen(tmpfname, "a+")) == NULL) {
				debug.log(ALL_LEVEL, "FATAL ERROR: unable to open %s: %s", tmpfname, strerror(errno));
				SJ_RUNTIME_EXCEPTION();
			} else {
				debug.log(ALL_LEVEL, "opened for hacks debug: %s successful", tmpfname);
			}
		}
	} else {
		debug.logstream = stdout;
		debug.log(ALL_LEVEL, "foreground running: logging set on standard output, block with ^c");
	}	
}
