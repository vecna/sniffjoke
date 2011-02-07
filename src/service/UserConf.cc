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
#include "portConfParsing.h"
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
    debug.log(VERBOSE_LEVEL, __func__);
    char *selected_basedir = NULL, *selected_location = NULL;

    /* generating referringdir and configfile (public) */
    if (cmdline_opts.basedir[0])
    {
        if(access(cmdline_opts.basedir, X_OK))
            SJ_RUNTIME_EXCEPTION("--dir parameter is not accessible");
        else
            selected_basedir = const_cast<char *>(cmdline_opts.basedir);
    }
    else /* no option used, default in hardcoded-defines.h */
    {
        selected_basedir = const_cast<char *>(WORK_DIR);
    }

    if (cmdline_opts.location[0])
    {
        debug.log(VERBOSE_LEVEL, "is highly suggestes to use sniffjoke specifying a location (--location option)");
        debug.log(VERBOSE_LEVEL, "a defined location means that the network it's profiled for the best results");
        debug.log(VERBOSE_LEVEL, "a brief explanation about this can be found at: http://www.delirandom.net/sniffjoke/location");
        selected_location = const_cast<char *>(cmdline_opts.location);
    }
    else
        selected_location = const_cast<char *>(DEFAULT_LOCATION);

    /* length sanity check, the input value are MEDIUMBUF (256) the generated buf are LARGEBUF (1024) */
    if(strlen(selected_basedir) + strlen(selected_location) > (LARGEBUF - strlen(FILE_CONF) -1) )
    {
        debug.log(ALL_LEVEL, "Internal error: the length of --dir and --location argument is over %d byte lenght",
            (LARGEBUF - strlen(FILE_CONF) -1));
        SJ_RUNTIME_EXCEPTION("parameters too long");
    }

    /* setting up che 'struct sj_config runconfig', the public member of UserConf class */
    memset(&runconfig, 0x00, sizeof (sj_config));
    memcpy(runconfig.location_name, selected_location, strlen(selected_location));

    /* in main.cc, near getopt, basedir last char if set to be '/' */
    snprintf(runconfig.working_dir, sizeof(runconfig.working_dir), "%s%s", selected_basedir, selected_location);

    /* checking if the option --location has sense: will be a typo! */
    if(access(runconfig.working_dir, X_OK)) 
    {
        debug.log(ALL_LEVEL, "Invalid parm: basedir (%s) and location (%s) point to a non accessible directory: %s",
            selected_basedir, selected_location, strerror(errno));
        SJ_RUNTIME_EXCEPTION("Inaccessible chroot/conf/logs directory");
    }
    else
        debug.log(DEBUG_LEVEL, "checked working directory %s accessible", runconfig.working_dir);

    snprintf(configfile, sizeof(configfile), "%s%s/%s", selected_basedir, selected_location, FILE_CONF);

    /* load() use the default name defined in hardcoded-defines.h, so is required change the current working directory */
    if(chdir(runconfig.working_dir))
        SJ_RUNTIME_EXCEPTION("Unable to chdir in the specifiy location");
    /* load does NOT memset to 0 the runconfig struct! and load defaults if file are not present */
    load();

    /* check integrity in the configuration loaded */
    if(runconfig.use_blacklist && runconfig.use_whitelist)
    {
        debug.log(ALL_LEVEL, "configuration conflict: both blacklist and whitelist seem to be enabled");
        SJ_RUNTIME_EXCEPTION("configuration conflict");
    }

    if (runconfig.onlyplugin[0])
    {
        debug.log(VERBOSE_LEVEL, "plugin %s override the plugins settings in %s", runconfig.onlyplugin, FILE_PLUGINSENABLER);
    }
    else
    {
        if(access(FILE_PLUGINSENABLER, R_OK))
        {
            debug.log(ALL_LEVEL, "unable to access to enabler file %s: %s: location unaccepted", FILE_PLUGINSENABLER, strerror(errno));
            SJ_RUNTIME_EXCEPTION("Unacceptable location because enabler file not found nor --only-plugin specified");
        }
        else
        {
            debug.log(VERBOSE_LEVEL, "accepted location %s with accessible enabler fileconf", runconfig.location_name);
        }
    }

    debug.log(DEBUG_LEVEL, "runconfig pass the sanity checks");
}

UserConf::~UserConf()
{
    debug.log(DEBUG_LEVEL, "%s [pid %d], config %s", __func__, getpid(), configfile);
}

void UserConf::autodetect_local_interface()
{
    /* check this command: the flag value, matched in 0003, is derived from:
     *     /usr/src/linux/include/linux/route.h
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

    if (i < 3)
    {
        debug.log(ALL_LEVEL, "-- default gateway not present: sniffjoke cannot be started");
        SJ_RUNTIME_EXCEPTION("");
    }
    else
    {
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
    if (strlen(runconfig.gw_ip_addr) < 7)
    {
        debug.log(ALL_LEVEL, "  -- unable to autodetect gateway ip address, sniffjoke cannot be started");
        SJ_RUNTIME_EXCEPTION("");
    }
    else
    {
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

    memset(cmd, 0x00, sizeof (cmd));
    snprintf(cmd, MEDIUMBUF, "arp -n | grep \"%s \" | cut -b 34-50", runconfig.gw_ip_addr);
    debug.log(ALL_LEVEL, "++ detecting mac address of gateway with %s", cmd);
    foca = popen(cmd, "r");
    fgets(imp_str, SMALLBUF, foca);
    pclose(foca);

    for (i = 0; i < strlen(imp_str) && (isxdigit(imp_str[i]) || imp_str[i] == ':'); ++i)
        runconfig.gw_mac_str[i] = imp_str[i];
    if (i != 17)
    {
        debug.log(ALL_LEVEL, "  -- unable to autodetect gateway mac address");
        SJ_RUNTIME_EXCEPTION("");
    }
    else
    {
        debug.log(ALL_LEVEL, "  == automatically acquired mac address: %s", runconfig.gw_mac_str);
        uint32_t mac[6];
        sscanf(runconfig.gw_mac_str, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        for (i = 0; i < 6; ++i)
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
    for (runconfig.tun_number = 0;; ++runconfig.tun_number)
    {
        memset(imp_str, 0x00, sizeof (imp_str));
        fgets(imp_str, SMALLBUF, foca);
        if (imp_str[0] == 0x00)
            break;
    }
    pclose(foca);
    debug.log(ALL_LEVEL, "  == detected %d as first unused tunnel device", runconfig.tun_number);
}

/* this method is called by SniffJoke.cc */
void UserConf::networkSetup(void)
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
            if(line[strlen(line) - 1] == '\n')
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
        debugfmt = "%s/bool: keyword %s used command line value: [%s]";
        goto EndparseMatchBool;
    }

    if (cf == NULL)
    {
        dst = difolt;
        debugfmt = "%s/bool: keyword %s config file not present, used default: [%s]";
        goto EndparseMatchBool;
    }

    memset(useropt, 0x00, SMALLBUF);

    /* in the configuration file, if a boolean is present, then is TRUE */
    if (parseLine(cf, useropt, name))
    {
        dst = true;
        debugfmt = "%s/bool: keyword %s read from config file: [%s]";
    }
    else
    {
        dst = difolt;
        debugfmt = "%s/bool: not found %s option in conf file, using default: [%s]";
    }

EndparseMatchBool:
    debug.log(DEBUG_LEVEL, debugfmt, __func__, name, dst ? "true" : "false");
}

void UserConf::parseMatch(char *dst, const char *name, FILE *cf, const char *cmdopt, const char *difolt)
{
    char useropt[SMALLBUF];
    const char *debugfmt = NULL;

    memset(useropt, 0x00, SMALLBUF);

    if(cmdopt != NULL && strlen(cmdopt) && ( difolt == NULL ? true : memcmp(cmdopt, difolt, strlen(difolt))) )
    {
        debugfmt = "%s/string: keyword %s command line %s used";
        memcpy(dst, cmdopt, strlen(cmdopt));
        goto EndparseMatchString;
    }

    /* only-plugin will be empty, no other cases */
    if (cf == NULL && difolt == NULL)
    {
        debugfmt = "%s/string: conf file not found and option neither: used no value in %s";
        memset(dst, 0x00, MEDIUMBUF);
        goto EndparseMatchString;
    }

    /* if the file is NULL, the default is used */
    if (cf == NULL)
    {
        debugfmt = "%s/string: conf file not found, for %s used default %s";
        memcpy(dst, difolt, strlen(difolt));
        goto EndparseMatchString;
    }

    if (parseLine(cf, useropt, name))
    {
        debugfmt = "%s/string: parsed keyword %s [%s] option in conf file";
        /* dst is large MEDIUMBUF, and none useropt will overflow this size */
        memcpy(dst, useropt, strlen(useropt));
        goto EndparseMatchString;
    }

    /* if was not found in the file, the default is used */
    if (difolt != NULL)
    {
        memset(dst, 0x00, MEDIUMBUF);
        memcpy(dst, difolt, strlen(difolt));
        debugfmt = "%s/string: %s not found in config file, used default %s";
    }

EndparseMatchString:
    debug.log(DEBUG_LEVEL, debugfmt, __func__, name, dst);
}

void UserConf::parseMatch(uint16_t &dst, const char *name, FILE *cf, uint16_t cmdopt, const uint16_t difolt)
{
    char useropt[SMALLBUF];
    const char *debugfmt = NULL;

    if (cmdopt != difolt && cmdopt != 0)
    {
        debugfmt = "%s/uint16: for %s used command line option %d";
        dst = cmdopt;
        goto EndparseMatchShort;
    }

    /* if the file is NULL, the default is used */
    if (cf == NULL)
    {
        memcpy((void *) &dst, (void *) &difolt, sizeof (difolt));
        debugfmt = "%s/uint16: conf file not found, for %s used default %d";
        goto EndparseMatchShort;
    }
    memset(useropt, 0x00, SMALLBUF);

    if (parseLine(cf, useropt, name))
    {
        debugfmt = "%s/uint16: parsed keyword %s [%d] option in conf file";
        dst = atoi(useropt);
        goto EndparseMatchShort;
    }

    if (difolt)
    {
        debugfmt = "%s/uint16: %s not found in config file, used default %d";
        dst = difolt;
    }

EndparseMatchShort:
    debug.log(DEBUG_LEVEL, debugfmt, __func__, name, dst);
}

/* this is the function that load the settings, it merge the command line options with
 * the file defined in hardcoded-define.h (all the .conf files) expected in the working_dir
 * derived by the --dir and --location options
 *
 * are not verified the integrity of such configuration, but only loaded, the integrity
 * is checked in the constructor of UserConf */
bool UserConf::load(void)
{
    FILE *loadfd;

    if ((loadfd = sj_fopen(FILE_CONF, "r")) == NULL)
        debug.log(ALL_LEVEL, "configuration file %s not accessible: %s, using default", configfile, strerror(errno));
    else
        debug.log(DEBUG_LEVEL, "opening configuration file: %s", configfile);

    /* the boolean value: if are present, are sets */
    parseMatch(runconfig.use_whitelist, "whitelist", loadfd, cmdline_opts.use_whitelist, false);
    parseMatch(runconfig.use_blacklist, "blacklist", loadfd, cmdline_opts.use_blacklist, false);
    parseMatch(runconfig.go_foreground, "foreground", loadfd, cmdline_opts.go_foreground, false);
    parseMatch(runconfig.active, "active", loadfd, cmdline_opts.active, DEFAULT_START_STOPPED);

    parseMatch(runconfig.user, "user", loadfd, cmdline_opts.user, DROP_USER);
    parseMatch(runconfig.group, "group", loadfd, cmdline_opts.group, DROP_GROUP);
    parseMatch(runconfig.admin_address, "management-address", loadfd, cmdline_opts.admin_address, DEFAULT_ADMIN_ADDRESS);
    parseMatch(runconfig.onlyplugin, "only-plugin", loadfd, cmdline_opts.onlyplugin, NULL);
    parseMatch(runconfig.max_ttl_probe, "max-ttl-probe", loadfd, cmdline_opts.max_ttl_probe, MAX_TTLPROBE);

    parseMatch(runconfig.admin_port, "management-port", loadfd, cmdline_opts.admin_port, DEFAULT_ADMIN_PORT);
    parseMatch(runconfig.debug_level, "debug", loadfd, cmdline_opts.debug_level, DEFAULT_DEBUG_LEVEL);

    /* those files act in portconf[PORTNUMBER]; array, merging the ports configuration */
    loadAggressivity();

    /* loading of IP lists, in future also the source IP address should be useful */
    if(runconfig.use_blacklist)
        runconfig.blacklist = new IPListMap(FILE_IPBLACKLIST);

    if(runconfig.use_whitelist)
        runconfig.whitelist = new IPListMap(FILE_IPWHITELIST);

    if (loadfd)
        fclose(loadfd);

    return true;
}

/* function for loading of the TCP port files */
void UserConf::loadAggressivity(void)
{
    FILE *aggressivityFp;

    if((aggressivityFp = fopen(FILE_AGGRESSIVITY, "r")) == NULL) 
    {
        debug.log(ALL_LEVEL, "port aggrssivity specifications in %s/%s: %s, loading defaults", 
            runconfig.working_dir, FILE_AGGRESSIVITY, strerror(errno)
        );
 
        /* the default is:
         *
         * 1:65535      NORMAL,COMMON
         */
        for (uint16_t i = 0; i < PORTNUMBER; ++i)
            runconfig.portconf[i] = FREQ_NORMAL & AGG_COMMON;

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
    while(!feof(aggressivityFp))
    {
        linecnt++;
        fgets(line, MEDIUMBUF, aggressivityFp);

        /* C's chop() */
        if(line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = 0x00;

       if ( strlen(line) < 6 || line[0] == '#' || line[0] == '\n' )
            continue;

        /* setup function clear the previously used private variables */
        pl.setup(line);

        pl.extractPorts();
        pl.extractValue();

        if(pl.error_message)
        {
            debug.log(ALL_LEVEL, "%s/%s line %d: %s", runconfig.working_dir, FILE_AGGRESSIVITY, linecnt, pl.error_message);
            SJ_RUNTIME_EXCEPTION("Unable to parse aggressivity file");
        }

        pl.mergeLine(runconfig.portconf);
    }
}

/* simple utiliy for dumping */
uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, char *data)
{
    uint32_t written = 0;

    if (data[0])
        written = fprintf(out, "%s:%s\n", name, data);

    return written;
}

uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, uint16_t shortdat)
{
    uint32_t written = 0;

    if(shortdat)
        written = fprintf(out, "%s:%u\n", name, shortdat);

    return written;
}

uint32_t UserConf::dumpIfPresent(FILE *out, const char *name, bool yndata)
{
    uint32_t written = 0;

    if (yndata)
        written = fprintf(out, "%s\n", name);

    return written;
}

bool UserConf::syncDiskConfiguration(void)
{
    uint32_t written = 0;
    char tempdumpfname[LARGEBUF];
    FILE *out;

    snprintf(tempdumpfname, LARGEBUF, "%s~.~", configfile);

    if((out = fopen(tempdumpfname, "w+")) == NULL) 
    {
        debug.log(ALL_LEVEL, "Abort operation: unable to open new configuration file %s: %s", tempdumpfname, strerror(errno));
        return false;
    }

    /* this is bad, this segment of code is more coherent in UserConf.cc */
    written += fprintf(out, "# this is a dumped file by SniffJoke version %s\n", SW_VERSION);
    written += dumpIfPresent(out, "user", runconfig.user);
    written += dumpIfPresent(out, "group", runconfig.group);
    written += dumpIfPresent(out, "management-address", runconfig.admin_address);
    written += dumpIfPresent(out, "management-port", runconfig.admin_port);
    written += dumpIfPresent(out, "debug", runconfig.debug_level);
    written += dumpIfPresent(out, "foreground", runconfig.go_foreground);
    written += dumpIfPresent(out, "whitelist", runconfig.use_whitelist);
    written += dumpIfPresent(out, "blacklist", runconfig.use_blacklist);
    written += dumpIfPresent(out, "active", runconfig.active);
    written += dumpIfPresent(out, "only-plugin", runconfig.active);

    if(!syncPortsFiles() || !syncIPListsFiles() )
    {
        debug.log(ALL_LEVEL, "interrupted dumping of running configuration in the %s location", runconfig.location_name);
        goto faultyreturn;
    }

    if( (uint32_t)ftell(out) != written)
    {
        debug.log(ALL_LEVEL, "the written size of the new configuration file unable to open new configuration file %s: %s", 
            tempdumpfname, strerror(errno));

        goto faultyreturn;
    }

    fclose(out);
    out = NULL;

    if(rename(tempdumpfname, configfile))
    {
        debug.log(ALL_LEVEL, "unable to update the configuration file, moving the temporary %s to %s: %s", 
            tempdumpfname, configfile, strerror(errno));

        goto faultyreturn;
    }

    return true;

faultyreturn:

    if(out != NULL)
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
