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
 * are used for detect the user specified working directory and 
 * location, or use the default.
 *
 * when the configuration file are found, the priority is given to
 * 1) command line options
 * 2) configuration files
 * 3) defaults
 */

UserConf::UserConf(const struct sj_cmdline_opts &cmdline_opts) :
cmdline_opts(cmdline_opts)
{
    LOG_DEBUG("");
    const char *selected_basedir = NULL, *selected_location = NULL;

    /* generating referringdir and configfile (public) */
    if (cmdline_opts.basedir[0])
    {
        if (access(cmdline_opts.basedir, X_OK))
            RUNTIME_EXCEPTION("--dir parameter is not accessible");
        else
            selected_basedir = cmdline_opts.basedir;
    }
    else /* no option used, default in hardcoded-defines.h */
    {
        selected_basedir = WORK_DIR;
    }

    if (cmdline_opts.location[0])
    {
        LOG_VERBOSE("is highly suggestes to use sniffjoke specifying a location (--location option)");
        LOG_VERBOSE("a defined location means that the network it's profiled for the best results");
        LOG_VERBOSE("a brief explanation about this can be found at: http://www.delirandom.net/sniffjoke/location");
        selected_location = cmdline_opts.location;
    }
    else
        selected_location = DEFAULT_LOCATION;

    /* length sanity check, the input value are MEDIUMBUF (256) the generated buf are LARGEBUF (1024) */
    if (strlen(selected_basedir) + strlen(selected_location) > (LARGEBUF - strlen(FILE_CONF) - 1))
    {
        RUNTIME_EXCEPTION("internal error: the length of --dir and --location argument is over %d byte lenght",
                          (LARGEBUF - strlen(FILE_CONF) - 1));
    }

    /* setting up che 'struct sj_config runconfig', the public member of UserConf class */
    memset(&runconfig, 0x00, sizeof (sj_config));
    memcpy(runconfig.location_name, selected_location, strlen(selected_location));

    /* in main.cc, near getopt, basedir last char if set to be '/' */
    snprintf(runconfig.working_dir, sizeof (runconfig.working_dir), "%s%s", selected_basedir, selected_location);

    /* checking if the option --location has sense: will be a typo! */
    if (access(runconfig.working_dir, X_OK))
    {
        RUNTIME_EXCEPTION("invalid parm: basedir (%s) and location (%s) point to a non accessible directory: %s",
                          selected_basedir, selected_location, strerror(errno));
    }
    else
    {
        LOG_DEBUG("checked working directory %s accessible",
                  runconfig.working_dir);
    }

    snprintf(configfile, sizeof (configfile), "%s%s/%s", selected_basedir, selected_location, FILE_CONF);

    /* loadDiskConfiguration() use the default name defined in hardcoded-defines.h, so is required change the current working directory */
    if (chdir(runconfig.working_dir))
        RUNTIME_EXCEPTION("Unable to chdir in the specifiy location");
    /* load does NOT memset to 0 the runconfig struct! and load defaults if file are not present */
    loadDiskConfiguration();

    /* check integrity in the configuration loaded */
    if (runconfig.no_tcp && runconfig.no_udp)
        RUNTIME_EXCEPTION("configuration conflict: both tcp and udp can't be disabled");

    if (runconfig.use_blacklist && runconfig.use_whitelist)
        RUNTIME_EXCEPTION("configuration conflict: both blacklist and whitelist seem to be enabled");

    if (runconfig.onlyplugin[0])
    {
        LOG_VERBOSE("plugin %s override the plugins settings in %s", runconfig.onlyplugin,
                    FILE_PLUGINSENABLER);
    }
    else
    {
        if (access(FILE_PLUGINSENABLER, R_OK))
        {
            RUNTIME_EXCEPTION("unable to access to enabler file %s: %s: location unaccepted",
                              FILE_PLUGINSENABLER, strerror(errno));
        }
        else
        {
            LOG_VERBOSE("accepted location %s with accessible enabler fileconf",
                        runconfig.location_name);
        }
    }

    LOG_DEBUG("runconfig pass the sanity checks");
}

UserConf::~UserConf(void)
{
    LOG_DEBUG("[pid %d], config %s", getpid(), configfile);
}

void UserConf::autodetectLocalInterface(void)
{
    /* check this command: the flag value, matched in 0003, is derived from:
     *     /usr/src/linux/include/linux/route.h
     */
    const char *cmd = "grep 0003 /proc/net/route | grep 00000000 | cut -b -7 2>/dev/null";
    FILE *foca;
    char imp_str[SMALLBUF];
    uint8_t i;

    LOG_ALL("detecting external gateway interface with [%s]", cmd);

    foca = popen(cmd, "r");
    fgets(imp_str, SMALLBUF, foca);
    pclose(foca);

    for (i = 0; i < strlen(imp_str) && isalnum(imp_str[i]); ++i)
        runconfig.interface[i] = imp_str[i];

    if (i < 3)
        RUNTIME_EXCEPTION("default gateway not present: sniffjoke cannot be started");
    else
    {
        LOG_ALL("detected external interface with default gateway: %s",
                runconfig.interface);
    }
}

void UserConf::autodetectLocalInterfaceIPAddress(void)
{
    char cmd[MEDIUMBUF];
    FILE *foca;
    char imp_str[SMALLBUF];
    uint8_t i;
    snprintf(cmd, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21- 2>/dev/null",
             runconfig.interface);

    LOG_ALL("detecting interface %s ip address with [%s]", runconfig.interface, cmd);

    foca = popen(cmd, "r");
    fgets(imp_str, SMALLBUF, foca);
    pclose(foca);

    for (i = 0; i < strlen(imp_str) && (isdigit(imp_str[i]) || imp_str[i] == '.'); ++i)
        runconfig.local_ip_addr[i] = imp_str[i];

    LOG_ALL("acquired local ip address: %s", runconfig.local_ip_addr);
}

void UserConf::autodetectGWIPAddress(void)
{
    const char *cmd = "route -n | grep ^0.0.0.0 | grep UG | cut -b 17-32 2>/dev/null";
    FILE *foca;
    char imp_str[SMALLBUF];
    uint8_t i;

    LOG_ALL("detecting gateway ip address with [%s]", cmd);

    foca = popen(cmd, "r");
    fgets(imp_str, SMALLBUF, foca);
    pclose(foca);

    for (i = 0; i < strlen(imp_str) && (isdigit(imp_str[i]) || imp_str[i] == '.'); ++i)
        runconfig.gw_ip_addr[i] = imp_str[i];

    if (strlen(runconfig.gw_ip_addr) < 7)
        RUNTIME_EXCEPTION("unable to autodetect gateway ip address, sniffjoke cannot be started");
    else
    {
        LOG_ALL("acquired gateway ip address: %s", runconfig.gw_ip_addr);
    }
}

void UserConf::autodetectGWMACAddress(void)
{
    char cmd[MEDIUMBUF];
    FILE *foca;
    char imp_str[SMALLBUF];
    uint8_t i;
    snprintf(cmd, MEDIUMBUF, "ping -W 1 -c 1 %s 2>/dev/null", runconfig.gw_ip_addr);

    LOG_ALL("pinging %s trying to populate ARP table [%s]", runconfig.gw_ip_addr, cmd);

    foca = popen(cmd, "r");
    /* we do not need the output of ping, we need to wait the ping to finish
     * and pclose does this =) */
    pclose(foca);

    memset(cmd, 0x00, sizeof (cmd));
    snprintf(cmd, MEDIUMBUF, "arp -n | grep \"%s \" | cut -b 34-50 2>/dev/null", runconfig.gw_ip_addr);

    LOG_ALL("detecting mac address of gateway with [%s]", cmd);

    foca = popen(cmd, "r");
    fgets(imp_str, SMALLBUF, foca);
    pclose(foca);

    for (i = 0; i < strlen(imp_str) && (isxdigit(imp_str[i]) || imp_str[i] == ':'); ++i)
        runconfig.gw_mac_str[i] = imp_str[i];

    if (i != 17)
        RUNTIME_EXCEPTION("unable to autodetect gateway mac address");
    else
    {
        LOG_ALL("acquired mac address from the arp table: %s", runconfig.gw_mac_str);
        uint32_t mac[6];
        sscanf(runconfig.gw_mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        for (i = 0; i < 6; ++i)
            runconfig.gw_mac_addr[i] = mac[i];
    }
}

void UserConf::autodetectFirstAvailableTunnelInterface(void)
{
    const char *cmd = "ifconfig -a | grep tun | cut -b -7 2>/dev/null";
    FILE *foca;
    char imp_str[SMALLBUF];

    LOG_ALL("detecting first unused tunnel device with [%s]", cmd);

    foca = popen(cmd, "r");
    for (runconfig.tun_number = 0;; ++runconfig.tun_number)
    {
        memset(imp_str, 0x00, sizeof (imp_str));
        fgets(imp_str, SMALLBUF, foca);
        if (imp_str[0] == 0x00)
            break;
    }
    pclose(foca);

    LOG_ALL("detected %d as first unused tunnel device", runconfig.tun_number);
}

/* this method is called by SniffJoke.cc */
void UserConf::networkSetup(void)
{
    LOG_DEBUG("initializing network for service/child: %d", getpid());

    /* autodetect is always used, we should not trust the preloaded configuration */
    autodetectLocalInterface();
    autodetectLocalInterfaceIPAddress();
    autodetectGWIPAddress();
    autodetectGWMACAddress();
    autodetectFirstAvailableTunnelInterface();

    LOG_VERBOSE("* system local interface: %s, %s address", runconfig.interface, runconfig.local_ip_addr);
    LOG_VERBOSE("* default gateway mac address: %s", runconfig.gw_mac_str);
    LOG_VERBOSE("* default gateway ip address: %s", runconfig.gw_ip_addr);
    LOG_VERBOSE("* first available tunnel interface: tun%d", runconfig.tun_number);
    LOG_VERBOSE("* the traffic from the gateway mac address has been blocked by iptables");
    sleep(1);
}

/*
 * BELOW FOLLOW THE LIST OF PARSING METHOD. 
 * some also low level, with strstr, memcmp, sscanf, ...
 *
 * IN THE FUTURE MAYBE SPLITTED IN ANOTHER CLASS, BUT UNTIL WE AUGMENT 
 * THE NUMBER OF CONFIGURATION FILES, IS NOT A PRIORITY.
 *
 * BETTER WILL BE CREATE A CLASS like IPListMap, with Port instead of IP.
 * IS A C++ SOLUTION INSTEAD OF THIS OLDISH C-like spaghetti code.
 *
 */

/* internal function called by the overloaded parseMatch */
bool UserConf::parseLine(FILE *cf, char userchoose[SMALLBUF], const char *keyword)
{
    rewind(cf);
    char line[MEDIUMBUF];

    do
    {
        fgets(line, MEDIUMBUF, cf);

        if (line[0] == '#' || line[0] == '\n' || line[0] == ' ')
            continue;

        if (strlen(line) < (strlen(keyword) + 3))
            continue;

        if (!memcmp(keyword, line, strlen(keyword)))
        {
            /* C's chop() */
            if (line[strlen(line) - 1] == '\n')
                line[strlen(line) - 1] = 0x00;

            memcpy(userchoose, (&line[strlen(keyword) + 1]), strlen(line) - strlen(keyword) - 1);
            return true;
        }
    }
    while (!feof(cf));

    return false;
}

/* start with the less used (only one time, for this reason differ) parseMatch overloaded name */
void UserConf::parseMatch(bool &dst, const char *name, FILE *cf, bool cmdopt, const bool difolt)
{
    char useropt[SMALLBUF];
    const char *debugfmt = NULL;

    /* command line priority always */
    if (cmdopt != difolt)
    {
        dst = cmdopt;
        debugfmt = "bool: keyword %s used command line value: [%s]";
        goto EndparseMatchBool;
    }

    if (cf == NULL)
    {
        dst = difolt;
        debugfmt = "bool: keyword %s config file not present, used default: [%s]";
        goto EndparseMatchBool;
    }

    memset(useropt, 0x00, SMALLBUF);

    /* in the configuration file, if a boolean is present, then is TRUE */
    if (parseLine(cf, useropt, name))
    {
        dst = true;
        debugfmt = "bool: keyword %s read from config file: [%s]";
    }
    else
    {
        dst = difolt;
        debugfmt = "bool: not found %s option in conf file, using default: [%s]";
    }

EndparseMatchBool:
    LOG_DEBUG(debugfmt, name, dst ? "true" : "false");
}

void UserConf::parseMatch(char *dst, const char *name, FILE *cf, const char *cmdopt, const char *difolt)
{
    char useropt[SMALLBUF];
    const char *debugfmt = NULL;

    memset(useropt, 0x00, SMALLBUF);

    if (cmdopt != NULL && strlen(cmdopt) && (difolt == NULL ? true : memcmp(cmdopt, difolt, strlen(difolt))))
    {
        debugfmt = "%s/string: keyword %s command line %s used";
        memcpy(dst, cmdopt, strlen(cmdopt));
        goto EndparseMatchString;
    }

    /* only-plugin will be empty, no other cases */
    if (cf == NULL && difolt == NULL)
    {
        debugfmt = "string: conf file not found and option neither: used no value in %s";
        memset(dst, 0x00, MEDIUMBUF);
        goto EndparseMatchString;
    }

    /* if the file is NULL, the default is used */
    if (cf == NULL)
    {
        debugfmt = "string: conf file not found, for %s used default %s";
        memcpy(dst, difolt, strlen(difolt));
        goto EndparseMatchString;
    }

    if (parseLine(cf, useropt, name))
    {
        debugfmt = "string: parsed keyword %s [%s] option in conf file";
        /* dst is large MEDIUMBUF, and none useropt will overflow this size */
        memcpy(dst, useropt, strlen(useropt));
        goto EndparseMatchString;
    }

    /* if was not found in the file, the default is used */
    if (difolt != NULL)
    {
        memset(dst, 0x00, MEDIUMBUF);
        memcpy(dst, difolt, strlen(difolt));
        debugfmt = "string: %s not found in config file, used default %s";
    }

EndparseMatchString:
    LOG_DEBUG(debugfmt, name, dst);
}

void UserConf::parseMatch(uint16_t &dst, const char *name, FILE *cf, uint16_t cmdopt, uint16_t difolt)
{
    char useropt[SMALLBUF];
    const char *debugfmt = NULL;

    if (cmdopt != difolt && cmdopt != 0)
    {
        debugfmt = "uint16: for %s used command line option %d";
        dst = cmdopt;
        goto EndparseMatchShort;
    }

    /* if the file is NULL, the default is used */
    if (cf == NULL)
    {
        memcpy((void *) &dst, (void *) &difolt, sizeof (difolt));
        debugfmt = "uint16: conf file not found, for %s used default %d";
        goto EndparseMatchShort;
    }
    memset(useropt, 0x00, SMALLBUF);

    if (parseLine(cf, useropt, name))
    {
        debugfmt = "uint16: parsed keyword %s [%d] option in conf file";
        dst = atoi(useropt);
        goto EndparseMatchShort;
    }

    if (difolt)
    {
        debugfmt = "uint16: %s not found in config file, used default %d";
        dst = difolt;
    }

EndparseMatchShort:
    LOG_DEBUG(debugfmt, name, dst);
}

/* this is the function that load the settings, it merge the command line options with
 * the file defined in hardcoded-define.h (all the .conf files) expected in the working_dir
 * derived by the --dir and --location options
 *
 * are not verified the integrity of such configuration, but only loaded, the integrity
 * is checked in the constructor of UserConf */
bool UserConf::loadDiskConfiguration(void)
{
    FILE *loadstream;

    if ((loadstream = fopen(FILE_CONF, "r")) == NULL)
        LOG_ALL("configuration file %s not accessible: %s, using default", configfile, strerror(errno));
    else
        LOG_DEBUG("opening configuration file: %s", configfile);

    parseMatch(runconfig.user, "user", loadstream, cmdline_opts.user, DEFAULT_USER);
    parseMatch(runconfig.group, "group", loadstream, cmdline_opts.group, DEFAULT_GROUP);
    parseMatch(runconfig.admin_address, "management-address", loadstream, cmdline_opts.admin_address, DEFAULT_ADMIN_ADDRESS);
    parseMatch(runconfig.admin_port, "management-port", loadstream, cmdline_opts.admin_port, DEFAULT_ADMIN_PORT);
    parseMatch(runconfig.chaining, "chaining", loadstream, cmdline_opts.chaining, DEFAULT_CHAINING);
    parseMatch(runconfig.no_tcp, "no-tcp", loadstream, cmdline_opts.no_tcp, DEFAULT_NO_TCP);
    parseMatch(runconfig.no_udp, "no-udp", loadstream, cmdline_opts.no_udp, DEFAULT_NO_UDP);
    parseMatch(runconfig.use_whitelist, "whitelist", loadstream, cmdline_opts.use_whitelist, DEFAULT_USE_WHITELIST);
    parseMatch(runconfig.use_blacklist, "blacklist", loadstream, cmdline_opts.use_blacklist, DEFAULT_USE_BLACKLIST);
    parseMatch(runconfig.active, "active", loadstream, cmdline_opts.active, DEFAULT_START_STOPPED);
    parseMatch(runconfig.go_foreground, "foreground", loadstream, cmdline_opts.go_foreground, DEFAULT_GO_FOREGROUND);
    parseMatch(runconfig.debug_level, "debug", loadstream, cmdline_opts.debug_level, DEFAULT_DEBUG_LEVEL);
    parseMatch(runconfig.onlyplugin, "only-plugin", loadstream, cmdline_opts.onlyplugin, NULL);
    parseMatch(runconfig.max_ttl_probe, "max-ttl-probe", loadstream, cmdline_opts.max_ttl_probe, DEFAULT_MAX_TTLPROBE);

    /* those files act in portconf[PORTNUMBER]; array, merging the ports configuration */
    loadAggressivity();

    /* loading of IP lists, in future also the source IP address should be useful */
    if (runconfig.use_blacklist)
        runconfig.blacklist = new IPListMap(FILE_IPBLACKLIST);

    if (runconfig.use_whitelist)
        runconfig.whitelist = new IPListMap(FILE_IPWHITELIST);

    if (loadstream)
        fclose(loadstream);

    return true;
}

/* function for loading of the TCP port files */
void UserConf::loadAggressivity(void)
{
    FILE *loadstream;

    for (int32_t i = 0; i < PORTSNUMBER; i++)
        runconfig.portconf[i] = AGG_NONE;

    if ((loadstream = fopen(FILE_AGGRESSIVITY, "r")) == NULL)
    {
        LOG_ALL("port aggrssivity specifications in %s/%s: %s, using defaults",
                runconfig.working_dir, FILE_AGGRESSIVITY, strerror(errno));

        /* the default is NONE. in the file port-aggrssivity.conf
         * the configured default is:
         *
         * 1:65535      RARE
         *
         * but is not an absolute truth, I like the user that choose for himself
         */

        return;
    }

    /* the classes portLine has been written specifically for parse
     * ... without Boost
     * is defined in portConfParsing.h and implemented in PortConfParsing.cc
     */
    portLine pl;
    char line[MEDIUMBUF];
    uint32_t linecnt = 0;

    /* the minimum length of a line is 6 */
    while (!feof(loadstream))
    {
        ++linecnt;
        fgets(line, MEDIUMBUF, loadstream);

        /* C's chop() */
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = 0x00;

        if (!strlen(line) || line[0] == '#' || line[0] == '\n')
            continue;

        /* setup function clear the previously used private variables */
        pl.setup(line);

        pl.extractPorts();
        pl.extractValue();

        if (pl.error_message)
            RUNTIME_EXCEPTION("Unable to parse aggressivity file %s/%s line %d: %s", runconfig.working_dir, FILE_AGGRESSIVITY, linecnt, pl.error_message);

        pl.mergeLine(runconfig.portconf);
    }

    fclose(loadstream);
}

/* simple utiliy for dumping */
uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, char *data, const char* difolt)
{
    uint32_t written = 0;
    return 0;

    if (data != NULL && strncmp(data, difolt, strlen(data)))
        written = fprintf(out, "%s:%s\n", name, data);

    return written;
}

uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, uint16_t shortdat, uint16_t difolt)
{
    uint32_t written = 0;

    if (shortdat != difolt)
        written = fprintf(out, "%s:%u\n", name, shortdat);

    return written;
}

uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, bool yndata, bool difolt)
{
    uint32_t written = 0;

    if (yndata != difolt)
        written = fprintf(out, "%s\n", name);

    return written;
}

bool UserConf::syncDiskConfiguration(void)
{
    uint32_t written = 0;
    char tempdumpfname[LARGEBUF];
    FILE *out;

    snprintf(tempdumpfname, LARGEBUF, "%s.temp", FILE_CONF);

    if ((out = fopen(tempdumpfname, "w")) == NULL)
    {
        LOG_ALL("Abort operation: unable to open new configuration file %s: %s", tempdumpfname, strerror(errno));
        return false;
    }

    /* this is bad, this segment of code is more coherent in UserConf.cc */
    written += fprintf(out, "# this is a dumped file by SniffJoke version %s\n", SW_VERSION);
    written += dumpIfPresent(out, "user", runconfig.user, DEFAULT_USER);
    written += dumpIfPresent(out, "group", runconfig.group, DEFAULT_GROUP);
    written += dumpIfPresent(out, "management-address", runconfig.admin_address, DEFAULT_ADMIN_ADDRESS);
    written += dumpIfPresent(out, "management-port", runconfig.admin_port, DEFAULT_ADMIN_PORT);
    written += dumpIfPresent(out, "chaining", runconfig.chaining, DEFAULT_CHAINING);
    written += dumpIfPresent(out, "no-tcp", runconfig.no_tcp, DEFAULT_NO_TCP);
    written += dumpIfPresent(out, "no-udp", runconfig.no_udp, DEFAULT_NO_UDP);
    written += dumpIfPresent(out, "whitelist", runconfig.use_whitelist, DEFAULT_USE_WHITELIST);
    written += dumpIfPresent(out, "blacklist", runconfig.use_blacklist, DEFAULT_USE_BLACKLIST);
    written += dumpIfPresent(out, "active", runconfig.active, DEFAULT_START_STOPPED);
    written += dumpIfPresent(out, "foreground", runconfig.go_foreground, DEFAULT_GO_FOREGROUND);
    written += dumpIfPresent(out, "debug", runconfig.debug_level, DEFAULT_DEBUG_LEVEL);
    written += dumpIfPresent(out, "only-plugin", runconfig.onlyplugin, NULL);
    written += dumpIfPresent(out, "max-ttl-probe", runconfig.max_ttl_probe, DEFAULT_MAX_TTLPROBE);

    if (!syncPortsFiles() || !syncIPListsFiles())
    {
        LOG_ALL("interrupted dumping of running configuration in the %s location", runconfig.location_name);
        goto faultyreturn;
    }

    if ((uint32_t) ftell(out) != written)
    {
        LOG_ALL("the written size of the new configuration file unable to open new configuration file %s: %s",
                tempdumpfname, strerror(errno));

        goto faultyreturn;
    }

    fclose(out);
    out = NULL;

    if (rename(tempdumpfname, FILE_CONF))
    {
        LOG_ALL("unable to update the configuration file, moving the temporary %s to %s: %s",
                tempdumpfname, FILE_CONF, strerror(errno));

        goto faultyreturn;
    }

    return true;

faultyreturn:

    if (out != NULL)
        fclose(out);

    unlink(tempdumpfname);
    return false;
}

bool UserConf::syncPortsFiles(void)
{
    /* TODO */
    return true;
}

bool UserConf::syncIPListsFiles(void)
{
    /* TODO */
    return true;
}