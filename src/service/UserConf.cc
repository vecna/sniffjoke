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

#include "UserConf.h"

/*
 * rules for parms:
 * sj_cmdline_opts contains only the option passed to the command line.
 * for uninitializated values will be used default ones.
 *
 * when a configuration file is present, the priority is given to
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
        if (cmdline_opts.basedir[0] != '/')
            RUNTIME_EXCEPTION("--dir must have absolute resolution");

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
        selected_location = cmdline_opts.location;
    }
    else
    {
        LOG_ALL("is strongly suggest to use sniffjoke specifying a location (--location option): 'generic/' is used");
        selected_location = DEFAULT_LOCATION;
    }

    /* length sanity check, the input value are MEDIUMBUF (256) the generated buf are LARGEBUF (1024) */
    if (strlen(selected_basedir) + strlen(selected_location) > (LARGEBUF - strlen(FILE_CONF) - 1))
    {
        RUNTIME_EXCEPTION("internal error: the length of --dir and --location argument is over %d byte lenght",
                          (LARGEBUF - strlen(FILE_CONF) - 1));
    }

    /* setting up che 'struct sj_config runconfig', the public member of UserConf class */
    memset(&runcfg, 0x00, sizeof (sj_config));
    memcpy(runcfg.location, selected_location, strlen(selected_location));

    /* in main.cc, near getopt, basedir last char if set to be '/' */
    snprintf(runcfg.working_dir, sizeof (runcfg.working_dir), "%s%s", selected_basedir, selected_location);

    /* checking if the option --location has sense: will be a typo! */
    if (access(runcfg.working_dir, X_OK))
    {
        RUNTIME_EXCEPTION("invalid parm: basedir (%s) and location (%s) point to a non accessible directory: %s",
                          selected_basedir, selected_location, strerror(errno));
    }
    else
    {
        LOG_DEBUG("checked working directory %s accessible", runcfg.working_dir);
    }

    /* generic has been make usefull again as default, but without MALfORMED attacks supports, this section of code
     * is kept until stabilized. */
#if 0
    char generic_errormsg[MEDIUMBUF];
    snprintf(generic_errormsg, sizeof (generic_errormsg), "%s%s/%s", selected_basedir, selected_location, GENERIC_MARKER_FILE);

    /* if the user has not specify a location, and thus we are on the generic: show them the fatal error */
    if (!(access(generic_errormsg, R_OK)))
    {
        FILE *ferrormsg = fopen(generic_errormsg, "r");

        while(!feof(ferrormsg))
        {
            fgets(generic_errormsg, MEDIUMBUF, ferrormsg);
            fputs(generic_errormsg, stdout);
        }

        fclose(ferrormsg);

        LOG_ALL("The 'generic' configuration is located here: %s", selected_basedir);
        RUNTIME_EXCEPTION("location required: generate with sniffjoke-autotest");
    }
#endif

    snprintf(configfile, sizeof (configfile), "%s%s/%s", selected_basedir, selected_location, FILE_CONF);

    /* loadDiskConfiguration() use the default name defined in hardcoded-defines.h, so is required change the current working directory */
    if (chdir(runcfg.working_dir))
        RUNTIME_EXCEPTION("unable to chdir in the specifiy location");
    /* load does NOT memset to 0 the runconfig struct! and load defaults if file are not present */
    loadDiskConfiguration();

    /* check integrity in the configuration loaded */
    if (runcfg.no_tcp && runcfg.no_udp)
        RUNTIME_EXCEPTION("configuration conflict: both tcp and udp can't be disabled");

    if (runcfg.use_blacklist && runcfg.use_whitelist)
        RUNTIME_EXCEPTION("configuration conflict: both blacklist and whitelist seem to be enabled");

    if (runcfg.onlyplugin[0])
    {
        LOG_VERBOSE("plugin %s override the plugins settings in %s", runcfg.onlyplugin,
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
            LOG_VERBOSE("accepted location [%s] and related [%s]", 
                       runcfg.location, FILE_PLUGINSENABLER);
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
    const char *cmd = "route -n | grep ^0.0.0.0 | grep UG | awk '{print $8}'";
    string imp_str;
    uint8_t i;

    LOG_ALL("detecting external gateway interface with [%s]", cmd);

    imp_str = execOSCmd(cmd);

    for (i = 0; i < strlen(imp_str.c_str()) && isalnum((imp_str.c_str())[i]); ++i)
        runcfg.net_iface_name[i] = (imp_str.c_str())[i];

    if (i < 3)
        RUNTIME_EXCEPTION("default gateway not present: sniffjoke cannot be started");
    else
    {
        LOG_ALL("detected external interface with default gateway: %s",
                runcfg.net_iface_name);
    }
}

void UserConf::autodetectLocalInterfaceIPAddress(void)
{
    char cmd[MEDIUMBUF];
    string imp_str;

    snprintf(cmd, MEDIUMBUF, "ifconfig %s | grep \"inet addr\" | cut -b 21- | awk '{print $1}'",
             runcfg.net_iface_name);

    LOG_ALL("detecting interface %s ip address with [%s]", runcfg.net_iface_name, cmd);

    imp_str = execOSCmd(cmd);

    strncpy(runcfg.net_iface_ip, imp_str.c_str(), sizeof (runcfg.net_iface_ip));

    LOG_ALL("acquired local ip address: %s", runcfg.net_iface_ip);
}

void UserConf::autodetectGWIPAddress(void)
{
    const char *cmd = "route -n | grep ^0.0.0.0 | grep UG | awk '{print $2}'";
    string imp_str;

    LOG_ALL("detecting gateway ip address with [%s]", cmd);

    imp_str = execOSCmd(cmd);

    for (uint8_t i = 0; i < strlen(imp_str.c_str()) && (isdigit((imp_str.c_str())[i]) || (imp_str.c_str())[i] == '.'); ++i)
        runcfg.gw_ip_addr[i] = (imp_str.c_str())[i];

    if (strlen(runcfg.gw_ip_addr) < 7)
        RUNTIME_EXCEPTION("unable to autodetect gateway ip address, sniffjoke cannot be started");
    else
    {
        LOG_ALL("acquired gateway ip address: %s", runcfg.gw_ip_addr);
    }
}

void UserConf::importMacAddr(const char *cmd_out)
{
    uint32_t mac[6];
    uint32_t i;

    for (i = 0; i < strlen(cmd_out) && (isxdigit(cmd_out[i])) || (cmd_out[i] == ':'); ++i)
        runcfg.gw_mac_str[i] = cmd_out[i];

    if (i != 17)
        RUNTIME_EXCEPTION("invalid mac address format: [%s] is not long 17 bytes", cmd_out);

    LOG_ALL("acquired gateway mac address from the arp table: %s", runcfg.gw_mac_str);
    sscanf(runcfg.gw_mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    for (i = 0; i < ETH_ALEN; ++i)
        runcfg.gw_mac_addr[i] = mac[i];
}

void UserConf::autodetectGWMACAddress(void)
{
    char cmd[MEDIUMBUF];
    string cmdout_str;

    snprintf(cmd, MEDIUMBUF, "arp -ni %s %s | grep %s | awk '{print $3}'",
             runcfg.net_iface_name, runcfg.gw_ip_addr, runcfg.gw_ip_addr);

    LOG_ALL("detecting mac address of gateway with [%s]", cmd);

    cmdout_str = execOSCmd(cmd);
    LOG_VERBOSE("received output to detect gateway mac address: %s", cmdout_str.c_str() );
    importMacAddr( cmdout_str.c_str() );
}

/* this method is called by SniffJoke.cc */
void UserConf::networkSetup(void)
{
    LOG_DEBUG("initializing network for service/child: %d", getpid());

    /* autodetect is always used, but will be override by --options, for this reason is checked
     * the presence of previously assignments */

    autodetectLocalInterface();
    autodetectLocalInterfaceIPAddress();
    autodetectGWIPAddress();

    if(!strlen(runcfg.gw_mac_str))
        autodetectGWMACAddress();

    LOG_VERBOSE("* system local interface: %s, %s address", runcfg.net_iface_name, runcfg.net_iface_ip);
    LOG_VERBOSE("* default gateway mac address: %s", runcfg.gw_mac_str);
    LOG_VERBOSE("* default gateway ip address: %s", runcfg.gw_ip_addr);
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
bool UserConf::parseKeyword(FILE *cf, char* userchoose, const char *keyword)
{
    char line[MEDIUMBUF] = {0};

    rewind(cf);

    do
    {
        if(fgets(line, MEDIUMBUF, cf) == NULL)
            break;

        if (line[0] == '#' || line[0] == '\n' || line[0] == ' ')
            continue;

        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = 0x00;

        if (!strncmp(keyword, line, strlen(keyword)))
        {
            if (strlen(line) > strlen(keyword))
                strncpy(userchoose, (&line[strlen(keyword) + 1]), strlen(line) - strlen(keyword) - 1);
            return true;
        }
    }
    while (!feof(cf));

    return false;
}

void UserConf::parseMatch(char *dst, const char *name, FILE *cf, const char *cmdopt, const char *difolt)
{
    char useropt[MEDIUMBUF] = {0};
    const char *debugfmt = NULL;

    /* command line priority always */
    if (cmdopt != NULL && strncmp(cmdopt, difolt, strlen(cmdopt)))
    {
        debugfmt = "string: option %s read from command line: [%s]";        
        strncpy(dst, cmdopt, MEDIUMBUF);
    }
    else if (cf != NULL && parseKeyword(cf, useropt, name))
    {
        debugfmt = "string: option %s read from config file: [%s]";
        strncpy(dst, useropt, MEDIUMBUF);
    }
    else
    {
        debugfmt = "string: not found %s option in conf file, using default: [%s]";
        strncpy(dst, difolt, strlen(difolt));
    }

    LOG_DEBUG(debugfmt, name, dst);
}

void UserConf::parseMatch(uint16_t &dst, const char *name, FILE *cf, uint16_t cmdopt, uint16_t difolt)
{
    char useropt[MEDIUMBUF] = {0};
    const char *debugfmt = NULL;

    /* command line priority always */
    if (cmdopt != difolt)
    {
        debugfmt = "uint16: option %s read from command line: [%d]";
        dst = cmdopt;
    }
    else if (cf != NULL && parseKeyword(cf, useropt, name))
    {
        debugfmt = "uint16: option %s read from config file: [%d]";
        dst = atoi(useropt);
    }
    else
    {
        debugfmt = "uint16: not found %s option in conf file, using default: [%d]";
        dst = difolt;
    }

    LOG_DEBUG(debugfmt, name, dst);
}

void UserConf::parseMatch(bool &dst, const char *name, FILE *cf, bool cmdopt, bool difolt)
{
    char useropt[MEDIUMBUF] = {0};
    const char *debugfmt = NULL;

    /* command line priority always */
    if (cmdopt != difolt)
    {
        dst = cmdopt;
        debugfmt = "bool: option %s read from command line: [%s]";
    }
    else if (cf != NULL && parseKeyword(cf, useropt, name))
    {
        dst = true;
        debugfmt = "bool: option %s read from config file: [%s]";
    }
    else
    {
        dst = difolt;
        debugfmt = "bool: not found %s option in conf file, using default: [%s]";
    }

    LOG_DEBUG(debugfmt, name, dst ? "true" : "false");
}

/* this is the function that load the settings, it merge the command line options with
 * the file defined in hardcoded-define.h (all the .conf files) expected in the working_dir
 * derived by the --dir and --location options
 *
 * are not verified the integrity of such configuration, but only loaded, the integrity
 * is checked in the constructor of UserConf */
bool UserConf::loadDiskConfiguration(void)
{
    FILE *loadstream = fopen(FILE_CONF, "r");
    if (loadstream == NULL)
        LOG_ALL("configuration file %s not accessible: %s, using default", configfile, strerror(errno));
    else
        LOG_DEBUG("opening configuration file: %s", configfile);

    parseMatch(runcfg.user, "user", loadstream, cmdline_opts.user, DEFAULT_USER);
    parseMatch(runcfg.group, "group", loadstream, cmdline_opts.group, DEFAULT_GROUP);
    parseMatch(runcfg.admin_address, "management-address", loadstream, cmdline_opts.admin_address, DEFAULT_ADMIN_ADDRESS);
    parseMatch(runcfg.admin_port, "management-port", loadstream, cmdline_opts.admin_port, DEFAULT_ADMIN_PORT);
    parseMatch(runcfg.chaining, "chaining", loadstream, cmdline_opts.chaining, DEFAULT_CHAINING);
    parseMatch(runcfg.no_tcp, "no-tcp", loadstream, cmdline_opts.no_tcp, DEFAULT_NO_TCP);
    parseMatch(runcfg.no_udp, "no-udp", loadstream, cmdline_opts.no_udp, DEFAULT_NO_UDP);
    parseMatch(runcfg.use_whitelist, "whitelist", loadstream, cmdline_opts.use_whitelist, DEFAULT_USE_WHITELIST);
    parseMatch(runcfg.use_blacklist, "blacklist", loadstream, cmdline_opts.use_blacklist, DEFAULT_USE_BLACKLIST);
    parseMatch(runcfg.active, "active", loadstream, cmdline_opts.active, DEFAULT_START_STOPPED);
    parseMatch(runcfg.go_foreground, "foreground", loadstream, cmdline_opts.go_foreground, DEFAULT_GO_FOREGROUND);
    parseMatch(runcfg.debug_level, "debug", loadstream, cmdline_opts.debug_level, DEFAULT_DEBUG_LEVEL);
    parseMatch(runcfg.onlyplugin, "only-plugin", loadstream, cmdline_opts.onlyplugin, DEFAULT_ONLYPLUGIN);
    parseMatch(runcfg.max_ttl_probe, "max-ttl-probe", loadstream, cmdline_opts.max_ttl_probe, DEFAULT_MAX_TTLPROBE);
    parseMatch(runcfg.gw_mac_str, "gw-mac-addr", loadstream, cmdline_opts.gw_mac_str, DEFAULT_GW_MAC_ADDR);

    /* loading of IP lists, in future also the source IP address should be useful */
    if (runcfg.use_blacklist)
    {
        runcfg.blacklist = new IPListMap(FILE_IPBLACKLIST);
        if ((*(runcfg.blacklist)).empty())
            RUNTIME_EXCEPTION("requested blacklist but blacklist file not found or empty");
    }

    /* if the network details are passed by options, complete the acquisition */
    if (strlen(runcfg.gw_mac_str))
    {
        importMacAddr(runcfg.gw_mac_str);
    }

    if (runcfg.use_whitelist)
    {
        runcfg.whitelist = new IPListMap(FILE_IPWHITELIST);
        if ((*(runcfg.whitelist)).empty())
            RUNTIME_EXCEPTION("requested whitelist but whitelist file not found or empty");
    }

    if (loadstream)
        fclose(loadstream);

    /* those files act in portconf[PORTNUMBER]; array, merging the ports configuration */
    loadAggressivity();

    return true;
}

/* function for loading of the TCP port files */
void UserConf::loadAggressivity(void)
{
    for (uint32_t i = 0; i < PORTSNUMBER; i++)
        runcfg.portconf[i] = AGG_NONE;

    FILE *loadstream = fopen(FILE_AGGRESSIVITY, "r");
    if (loadstream == NULL)
    {
        LOG_ALL("port aggressivity specifications in %s/%s: %s, using defaults",
                runcfg.working_dir, FILE_AGGRESSIVITY, strerror(errno));

        /* the default is NONE. in the file port-aggrssivity.conf
         * the configured default is:
         *
         * 1:65535      RARE
         *
         * but is not an absolute truth, I like the user that choose for himself
         */

        return;
    }

    uint32_t linecnt = 0;

    /* the minimum length of a line is 6 */
    while (!feof(loadstream))
    {
        ++linecnt;

        char line[MEDIUMBUF];

        if(fgets(line, MEDIUMBUF, loadstream) == NULL)
            break;

        if (!strlen(line) || line[0] == '#' || line[0] == '\n')
            continue;

        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = 0x00;

        portLine pl;
        pl.setup(line);
        pl.extractPorts();
        pl.extractValue();

        if (pl.error_message)
            RUNTIME_EXCEPTION("unable to parse aggressivity file %s/%s line %d: %s", 
                              runcfg.working_dir, FILE_AGGRESSIVITY, linecnt, pl.error_message);

        pl.mergeLine(runcfg.portconf);
    }

    fclose(loadstream);
}

/* simple utiliy for dumping */
uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, char *data, const char* difolt)
{
    uint32_t written = 0;

    if (data != NULL && (difolt == NULL || strncmp(data, difolt, strlen(difolt))))
        written = fprintf(out, "%s:%s\n", name, data);

    return written;
}

uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, uint16_t data, uint16_t difolt)
{
    uint32_t written = 0;

    if (data != difolt)
        written = fprintf(out, "%s:%u\n", name, data);

    return written;
}

uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, bool data, bool difolt)
{
    uint32_t written = 0;

    if (data != difolt)
        written = fprintf(out, "%s\n", name);

    return written;
}

bool UserConf::syncDiskConfiguration(void)
{
    uint32_t written = 0;

    char tempdumpfname[LARGEBUF];
    snprintf(tempdumpfname, LARGEBUF, "%s.temp", FILE_CONF);

    FILE *out = fopen(tempdumpfname, "w");
    if (out == NULL)
    {
        LOG_ALL("unable to open new configuration file %s: %s", tempdumpfname, strerror(errno));
        return false;
    }

    /* this is bad, this segment of code is more coherent in UserConf.cc */
    written += fprintf(out, "# this is a dumped file by SniffJoke version %s\n", SW_VERSION);
    written += dumpIfPresent(out, "user", runcfg.user, DEFAULT_USER);
    written += dumpIfPresent(out, "group", runcfg.group, DEFAULT_GROUP);
    written += dumpIfPresent(out, "management-address", runcfg.admin_address, DEFAULT_ADMIN_ADDRESS);
    written += dumpIfPresent(out, "management-port", runcfg.admin_port, DEFAULT_ADMIN_PORT);
    written += dumpIfPresent(out, "chaining", runcfg.chaining, DEFAULT_CHAINING);
    written += dumpIfPresent(out, "no-tcp", runcfg.no_tcp, DEFAULT_NO_TCP);
    written += dumpIfPresent(out, "no-udp", runcfg.no_udp, DEFAULT_NO_UDP);
    written += dumpIfPresent(out, "whitelist", runcfg.use_whitelist, DEFAULT_USE_WHITELIST);
    written += dumpIfPresent(out, "blacklist", runcfg.use_blacklist, DEFAULT_USE_BLACKLIST);
    written += dumpIfPresent(out, "active", runcfg.active, DEFAULT_START_STOPPED);
    written += dumpIfPresent(out, "foreground", runcfg.go_foreground, DEFAULT_GO_FOREGROUND);
    written += dumpIfPresent(out, "debug", runcfg.debug_level, DEFAULT_DEBUG_LEVEL);
    written += dumpIfPresent(out, "max-ttl-probe", runcfg.max_ttl_probe, DEFAULT_MAX_TTLPROBE);

    if (!syncPortsFiles() || !syncIPListsFiles())
    {
        LOG_ALL("interrupted dumping of running configuration in the %s location", runcfg.location);
        goto faultyreturn;
    }

    if ((uint32_t) ftell(out) != written)
    {
        LOG_ALL("incomplete data written for the new configuration file: %s", strerror(errno));
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
