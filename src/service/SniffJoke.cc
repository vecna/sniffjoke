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

#include "SniffJoke.h"

#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

SniffJoke::SniffJoke(struct sj_cmdline_opts &opts) :
alive(true),
opts(opts),
userconf(opts),
proc(userconf.runconfig),
service_pid(0)
{
    setupDebug(stdout);
    LOG_VERBOSE("");
}

SniffJoke::~SniffJoke()
{
    if (getuid() || geteuid())
    {
        LOG_DEBUG("service with user privileges [%d]", getpid());
        cleanServerUser();
    }
    else
    {
        LOG_DEBUG("service with root privileges [%d]", getpid());
        cleanServerRoot();
    }
    /* closing the log files */
    cleanDebug();
}

void SniffJoke::run()
{
    pid_t old_service_pid = proc.readPidfile();
    if (old_service_pid != 0)
    {
        if (!opts.force_restart)
        {
            LOG_ALL("SniffJoke is already runconfig, use --force or check --help");
            LOG_ALL("the pidfile %s contains the apparently running pid: %d", SJ_PIDFILE, old_service_pid);
            return;
        }
        else
        {
            LOG_VERBOSE("forcing exit of previous running service %d ...", old_service_pid);

            /* we have to do quite the same as in sniffjoke_server_cleanup,
             * but relative to the service_pid read with readPidfile;
             * here we can not use the waitpid because the process to kill it's not a child of us;
             * we can use a sleep(2) instead. */
            kill(old_service_pid, SIGTERM);
            sleep(2);
            proc.unlinkPidfile(true);

            LOG_ALL("a new instance of SniffJoke is going background");
        }
    }

    if (!old_service_pid && opts.force_restart)
        LOG_VERBOSE("option --force ignore: not found a previously running SniffJoke");

    if (!userconf.runconfig.active)
        LOG_ALL("SniffJoke is INACTIVE: use \"sniffjokectl start\" or use the --start option");
    else
        LOG_VERBOSE("SniffJoke started and ACTIVE");

    /* we run the network setup before the background, to keep the software output visible on the console */
    userconf.networkSetup();

    if (!opts.go_foreground)
    {
        proc.background();

        /* Log Object must be reinitialized after background and before the chroot! */
        setupDebug(NULL);

        proc.isolation();
    }

    /* the code flow reach here, SniffJoke is ready to instance network environment */
    mitm = auto_ptr<NetIO > (new NetIO(userconf.runconfig));

    /* sigtrap handler mapped the same in both Sj processes */
    proc.sigtrapSetup(sigtrap);

    /* proc.detach: fork() into two processes,
       from now on the real configuration is the one mantained by the child */
    service_pid = proc.detach();

    /* this is the root privileges thread, need to run for restore the network
     * environment in shutdown */
    if (service_pid)
    {
        int deadtrace;

        proc.writePidfile();
        if (waitpid(service_pid, &deadtrace, WUNTRACED) > 0)
        {
            if (WIFEXITED(deadtrace))
                LOG_VERBOSE("child %d WIFEXITED", service_pid);
            if (WIFSIGNALED(deadtrace))
                LOG_VERBOSE("child %d WIFSIGNALED", service_pid);
            if (WIFSTOPPED(deadtrace))
                LOG_VERBOSE("child %d WIFSTOPPED", service_pid);
        }
        else
            LOG_VERBOSE("child waitpid failed with: %s", strerror(errno));

        LOG_DEBUG("child %d died, going to shutdown", service_pid);

    }
    else
    {

        /* loading the plugins used for tcp hacking, MUST be done before proc.jail() */
        hack_pool = auto_ptr<HackPool > (new HackPool(userconf.runconfig));

        proc.jail(userconf.runconfig.working_dir);
        userconf.chroot_status = true;

        proc.privilegesDowngrade();

        sessiontrack_map = auto_ptr<SessionTrackMap > (new SessionTrackMap);
        ttlfocus_map = auto_ptr<TTLFocusMap > (new TTLFocusMap());
        conntrack = auto_ptr<TCPTrack > (new TCPTrack(userconf.runconfig, *hack_pool, *sessiontrack_map, *ttlfocus_map));

        mitm->prepareConntrack(conntrack.get());

        setupAdminSocket();

        /* main block */
        while (alive)
        {

            sj_clock = time(NULL);

            proc.sigtrapDisable();

            mitm->networkIO();

            handleAdminSocket();

            proc.sigtrapEnable();
        }
    }
}

void SniffJoke::setupDebug(FILE *forcedoutput) const
{
    debug.debuglevel = userconf.runconfig.debug_level;

    /* when sniffjoke start force the output to be stdout */
    if (forcedoutput != NULL)
    {
        debug.logstream = forcedoutput;
        return;
    }

    if (!opts.go_foreground)
    {
        /* Logfiles are used only by a Sniffjoke SERVER runnning in background */
        if (!debug.resetLevel(const_cast<const char *> (userconf.runconfig.working_dir)))
            RUNTIME_EXCEPTION("opening log files");
    }
    else /* userconf.runconfig.go_foreground */
    {
        debug.logstream = stdout;
        LOG_ALL("foreground logging enable, use ^c for quit SniffJoke");
    }
}

/* this function must not close the FILE *desc, because in the destructor of the
 * auto_ptr some debug call will be present. It simple need to flush the FILE,
 * and the descriptor are closed with the process, after. */
void SniffJoke::cleanDebug()
{
    if (debug.logstream != NULL && debug.logstream != stdout)
        fflush(debug.logstream);
    if (debug.packet_logstream != NULL && debug.packet_logstream != stdout)
        fflush(debug.packet_logstream);
    if (debug.session_logstream != NULL && debug.session_logstream != stdout)
        fflush(debug.session_logstream);
}

void SniffJoke::cleanServerRoot()
{
    if (service_pid)
    {
        LOG_VERBOSE("found server root pid %d (from %d)", service_pid, getpid());
        kill(service_pid, SIGTERM);
        waitpid(service_pid, NULL, WUNTRACED);
    }

    proc.unlinkPidfile(false);
}

void SniffJoke::cleanServerUser()
{
    LOG_VERBOSE("");
}

void SniffJoke::setupAdminSocket()
{
    int tmp;
    struct sockaddr_in in_service;

    if ((tmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        RUNTIME_EXCEPTION("unable to open UDP socket: %s",
                          strerror(errno));

    memset(&in_service, 0x00, sizeof (in_service));
    /* here we are running under chroot, resolution will not work without /etc/hosts and /etc/resolv.conf */
    if (!inet_aton(userconf.runconfig.admin_address, &in_service.sin_addr))
        RUNTIME_EXCEPTION("unable to accept hostname (%s): only IP address allow",
                          userconf.runconfig.admin_address);

    in_service.sin_family = AF_INET;
    in_service.sin_port = htons(userconf.runconfig.admin_port);

    if (bind(tmp, (struct sockaddr *) &in_service, sizeof (in_service)) == -1)
    {
        close(tmp);
        RUNTIME_EXCEPTION("unable to bind UDP socket %s:%d: %s",
                          userconf.runconfig.admin_address, ntohs(in_service.sin_port), strerror(errno));
    }
    LOG_VERBOSE("bind %u UDP port in %s ip interface for administration",
                userconf.runconfig.admin_port, userconf.runconfig.admin_address);

    admin_socket_flags_blocking = fcntl(tmp, F_GETFL);
    admin_socket_flags_nonblocking = admin_socket_flags_blocking | O_NONBLOCK;

    if (fcntl(tmp, F_SETFL, admin_socket_flags_nonblocking) == -1)
    {
        close(tmp);
        RUNTIME_EXCEPTION("unable to set non blocking administration socket: %s",
                          strerror(errno));
    }

    admin_socket = tmp;
}

void SniffJoke::handleAdminSocket()
{
    char r_buf[MEDIUMBUF];
    uint8_t* output_buf = NULL;
    struct sockaddr_in fromaddr;

    memset(r_buf, 0x00, sizeof (r_buf));
    int fromlen = sizeof (struct sockaddr_in);
    if ((recvfrom(admin_socket, r_buf, sizeof (r_buf), 0, (sockaddr*) & fromaddr, (socklen_t *) & fromlen)) == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return;
        }
        RUNTIME_EXCEPTION("unable to receive from local socket: %s",
                          strerror(errno));
    }

    LOG_VERBOSE("received command from the client: %s", r_buf);

    output_buf = handleCmd(r_buf);

    /* checking if the command require SniffJoke class interaction (loglevel change), these are the
     * command that could cause an interruption of the service - require to be modify the "char *output"
     * with the appropriate error - TODO ATM */
    if (debug.debuglevel != userconf.runconfig.debug_level)
    {
        debug.debuglevel = userconf.runconfig.debug_level;

        if (!debug.resetLevel(const_cast<const char *> (userconf.runconfig.working_dir)))
            RUNTIME_EXCEPTION("Changing logfile settings");
    }

    /* send the answer message to the client, maybe scattered in more packets (HUGEBUF are 4k bytes large) */
    if (output_buf != NULL)
    {
        uint32_t sent =0, avail =((uint32_t *) output_buf)[0] ;

        fcntl(admin_socket, F_SETFL, admin_socket_flags_blocking);

        do
        {
            uint32_t this_block = (avail - sent) > LARGEBUF ? LARGEBUF : (avail - sent);
            sendto(admin_socket, &output_buf[sent], this_block, 0, (struct sockaddr *) &fromaddr, sizeof (fromaddr));
            sent += this_block;
        } 
        while(sent < avail);

        fcntl(admin_socket, F_SETFL, admin_socket_flags_nonblocking);
    }
    else
    {
        LOG_ALL("BUG: command handling of [%s] don't return any answer", r_buf);
    }
}

int SniffJoke::recvCommand(int sock, char *databuf, int bufsize, struct sockaddr *from, FILE *error_flow, const char *usermsg)
{
    memset(databuf, 0x00, bufsize);

    int fromlen = sizeof (struct sockaddr_in), ret;

    if ((ret = recvfrom(sock, databuf, bufsize, MSG_WAITALL, from, (socklen_t *) & fromlen)) == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;

        RUNTIME_EXCEPTION("unable to receive from local socket: %s: %s",
                          usermsg, strerror(errno));
    }

    return ret;
}

uint8_t* SniffJoke::handleCmd(const char *cmd)
{
    memset(io_buf, 0x00, sizeof (io_buf));
    uint16_t* psize = (uint16_t *) io_buf;

    LOG_DEBUG("command received begin processed: [%s]", cmd);

    /* the handleCmd* fill partialy the io_buf, as defined
     * protocol, the first 4 byte represent the length of the
     * data, uint32_t lenght included.
     * the data returned is conform
     * to the specification in doc/SJ-PROTOCOL.txt */

    if (!memcmp(cmd, "start", strlen("start")))
    {
        handleCmdStart();
    }
    else if (!memcmp(cmd, "stop", strlen("stop")))
    {
        handleCmdStop();
    }
    else if (!memcmp(cmd, "quit", strlen("quit")))
    {
        handleCmdQuit();
    }
    else if (!memcmp(cmd, "saveconf", strlen("saveconf")))
    {
        handleCmdSaveconf();
    }
    else if (!memcmp(cmd, "stat", strlen("stat")))
    {
        handleCmdStat();
    }
    else if (!memcmp(cmd, "info", strlen("info")))
    {
        handleCmdInfo();
    }
    else if (!memcmp(cmd, "showport", strlen("showport")))
    {
        handleCmdShowport();
    }
    else if (!memcmp(cmd, "set", strlen("set")))
    {
        uint32_t start_port, end_port, value;
        /* Strength setValue; did Strenght be required anymore ? */

        sscanf(cmd, "set %u %u %u", &start_port, &end_port, &value);

        if (start_port < 0 || start_port > PORTNUMBER || end_port < 0 || end_port > PORTNUMBER)
            goto handle_error;

        if (start_port > end_port)
            goto handle_error;

        handleCmdSet(start_port, end_port, value);
    }
    else if (!memcmp(cmd, "clear", strlen("clear")))
    {
        uint8_t clearPortValue = NONE;
        handleCmdSet(0, PORTNUMBER, clearPortValue);
    }
    else if (!memcmp(cmd, "debug", strlen("debug")))
    {
        int32_t debuglevel;

        sscanf(cmd, "debug %d", &debuglevel);
        if (debuglevel < 0 || debuglevel > PACKET_LEVEL)
            goto handle_error;

        handleCmdDebuglevel(debuglevel);
    }
    else
    {
        LOG_ALL("Invalid command received");
    }

    LOG_ALL("handled command (%s): answer %d bytes length", cmd, *psize);
    return &io_buf[0];

handle_error:
    LOG_ALL("invalid command received");
    writeSJProtoError();

    return &io_buf[0];
}

void SniffJoke::handleCmdStart(void)
{
    if (userconf.runconfig.active != true)
        LOG_VERBOSE("started SniffJoke as requested!");
    else /* SniffJoke is already running */
        LOG_VERBOSE("SniffJoke it's already in run status");

    userconf.runconfig.active = true;
    /* this function fill io_buf with the status information */
    writeSJStatus(START_COMMAND_TYPE);
}

void SniffJoke::handleCmdStop(void)
{
    if (userconf.runconfig.active != false)
        LOG_VERBOSE("stopped SniffJoke as requested!");
    else /* SniffJoke is already runconfig */
        LOG_VERBOSE("SniffJoke it's already in stop status");

    userconf.runconfig.active = false;
    /* this function fill io_buf with the status information */
    writeSJStatus(STOP_COMMAND_TYPE);
}

void SniffJoke::handleCmdQuit(void)
{
    alive = false;
    LOG_VERBOSE("starting shutdown");
    writeSJStatus(QUIT_COMMAND_TYPE);
}

/* this function like the debug level change, call some operations
 * that may fail. But in this case, is possibile know the status 
 * of the operation immediatly.
 *
 * this function is never autocalled, but only specifically request by the client
 */
void SniffJoke::handleCmdSaveconf(void)
{
    /* beside dump the FILE_CONF, sync_disk_configuration save the TCP port and list files */
    if (!userconf.syncDiskConfiguration())
    {
        /* TODO - handle the communication of the error in the client */
        LOG_ALL("error in communication error in loggin error in keyboad");
    }
    /* as generic rule, when a command has not an output, write the status */
    writeSJStatus(SAVECONF_COMMAND_TYPE);
}

void SniffJoke::handleCmdStat(void)
{
    LOG_VERBOSE("stat requested");
    writeSJStatus(STAT_COMMAND_TYPE);
}


void SniffJoke::handleCmdInfo(void)
{
    LOG_VERBOSE("info command requested: sessions only supported in this version");
    writeSJInfoDump(INFO_COMMAND_TYPE);
}

void SniffJoke::handleCmdShowport(void)
{
    writeSJPortStat(SHOWPORT_COMMAND_TYPE);
}

void SniffJoke::handleCmdSet(uint16_t start, uint16_t end, uint8_t what)
{
    LOG_VERBOSE("set TCP ports from %d to %d at %d strenght level", start, end, what);

    if (end == PORTNUMBER)
    {
        userconf.runconfig.portconf[PORTNUMBER - 1] = what;
        --end;
    }

    do userconf.runconfig.portconf[start++] = what; while (start <= end);

    writeSJPortStat(SETPORT_COMMAND_TYPE);
}

void SniffJoke::handleCmdDebuglevel(int32_t newdebuglevel)
{
    if (newdebuglevel < ALL_LEVEL || newdebuglevel > PACKET_LEVEL)
    {
        LOG_ALL("requested debuglevel %d invalid (>= %d <= %d permitted)",
                newdebuglevel, ALL_LEVEL, PACKET_LEVEL);
    }
    else
    {
        LOG_ALL("changing log level since %d to %d\n", userconf.runconfig.debug_level, newdebuglevel);
        userconf.runconfig.debug_level = newdebuglevel;
    }
    writeSJStatus(LOGLEVEL_COMMAND_TYPE);
}

/*
 * follow the method used for compose the io_buf with the internalProtocol.h struct,
 * those methods are intetnal in UserConf, and are, exception noted for handleCmdSaveconf
 * the only commands writing in io_buf and generating answer.
 */
void SniffJoke::writeSJPortStat(uint8_t type)
{
    uint16_t prev_port = 1, prev_kind;
    struct command_ret retInfo;
    uint32_t accumulen = sizeof (retInfo);

    /* clean the buffer and fix the starting pointer */
    memset(io_buf, 0x00, HUGEBUF);

    /* the first port work as initialization */
    prev_kind = userconf.runconfig.portconf[0];

    for (uint32_t i = 1; i < PORTNUMBER; ++i)
    {
        if (userconf.runconfig.portconf[i] != prev_kind)
        {
            accumulen += appendSJPortBlock(&io_buf[accumulen], prev_port, i - 1, prev_kind);

            if (accumulen > HUGEBUF)
                RUNTIME_EXCEPTION("someone has a very stupid sniffjoke configuration, or is trying to overflow me");

            prev_kind = userconf.runconfig.portconf[i];
            prev_port = i;
        }
    }

    accumulen += appendSJPortBlock(&io_buf[accumulen], prev_port, PORTNUMBER, prev_kind);

    retInfo.cmd_len = accumulen;
    retInfo.cmd_type = type;
    memcpy(&io_buf[0], (void *) &retInfo, sizeof (retInfo));
}

void SniffJoke::writeSJStatus(uint8_t commandReceived)
{
    struct command_ret retInfo;
    uint32_t accumulen = sizeof (retInfo);

    /* clean the buffer and fix the starting pointer */
    memset(io_buf, 0x00, HUGEBUF);

    /* SJStatus is totally inspired by the IP/TCP options */
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_ACTIVE, sizeof (userconf.runconfig.active), userconf.runconfig.active);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_MACGW, strlen(userconf.runconfig.gw_mac_str), userconf.runconfig.gw_mac_str);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_GWADDR, strlen(userconf.runconfig.gw_ip_addr), userconf.runconfig.gw_ip_addr);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_IFACE, strlen(userconf.runconfig.interface), userconf.runconfig.interface);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_LOIP, strlen(userconf.runconfig.local_ip_addr), userconf.runconfig.local_ip_addr);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_TUNN, sizeof (uint16_t), (uint16_t) userconf.runconfig.tun_number);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_DEBUGL, sizeof (userconf.runconfig.debug_level), userconf.runconfig.debug_level);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_ONLYP, strlen(userconf.runconfig.onlyplugin), userconf.runconfig.onlyplugin);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_BINDA, strlen(userconf.runconfig.admin_address), userconf.runconfig.admin_address);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_BINDP, sizeof (userconf.runconfig.admin_port), userconf.runconfig.admin_port);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_USER, strlen(userconf.runconfig.user), userconf.runconfig.user);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_GROUP, strlen(userconf.runconfig.group), userconf.runconfig.group);
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_LOCAT, strlen(userconf.runconfig.location_name), userconf.runconfig.location_name);
    /**
    accumulen += appendSJStatus(&io_buf[accumulen], STAT_CHROOT, strlen(userconf.runconfig.working_dir), userconf.runconfig.working_dir);
     **/

    retInfo.cmd_len = accumulen;
    retInfo.cmd_type = commandReceived;
    memcpy(&io_buf[0], &retInfo, sizeof (retInfo));
}

void SniffJoke::writeSJInfoDump(uint8_t type)
{
    struct command_ret retInfo;
    uint32_t accumulen = sizeof (retInfo);

    /* clean the buffer and fix the starting pointer */
    memset(io_buf, 0x00, HUGEBUF);

    for (SessionTrackMap::iterator it = sessiontrack_map->begin(); it != sessiontrack_map->end(); ++it)
    {
        if(accumulen > HUGEBUF)
            RUNTIME_EXCEPTION("Overflow detected! io_buf for client-service communication too much short!?");

        SessionTrack &Tracked = *((*it).second);
        accumulen += appendSJSessionInfo(&io_buf[accumulen], Tracked);
    }

    retInfo.cmd_len = accumulen;
    retInfo.cmd_type = type;
    memcpy(&io_buf[0], &retInfo, sizeof (retInfo));
}

void SniffJoke::writeSJProtoError(void)
{
    struct command_ret retInfo;
    memset(io_buf, 0x00, HUGEBUF);
    retInfo.cmd_len = sizeof (retInfo);
    retInfo.cmd_type = COMMAND_ERROR_MSG;
    memcpy(&io_buf[0], &retInfo, sizeof (retInfo));
}

/* follow the most "internal" method for io_buf creation, called from the methods before  */
uint32_t SniffJoke::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, uint16_t value)
{
    struct single_block singleData;

    singleData.len = len;
    singleData.WHO = WHO;
    memcpy(p, &singleData, sizeof (singleData));
    p += sizeof (singleData);
    memcpy(p, &value, len);

    return len + sizeof (singleData);
}

uint32_t SniffJoke::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, bool value)
{
    struct single_block singleData;

    singleData.len = len;
    singleData.WHO = WHO;
    memcpy(p, &singleData, sizeof (singleData));
    p += sizeof (singleData);
    *p = (uint8_t) value;

    return len + sizeof (singleData);
}

uint32_t SniffJoke::appendSJStatus(uint8_t *p, int32_t WHO, uint32_t len, char value[MEDIUMBUF])
{
    if (len)
    {
        struct single_block singleData;

        singleData.len = len;
        singleData.WHO = WHO;
        memcpy(p, &singleData, sizeof (singleData));
        p += sizeof (singleData);
        memcpy(p, value, len);

        len += sizeof (singleData);
    }
    return len;
}

uint32_t SniffJoke::appendSJPortBlock(uint8_t *p, uint16_t startP, uint16_t endP, uint8_t weight)
{
    struct port_info pInfo;

    pInfo.start = startP;
    pInfo.end = endP;
    pInfo.weight = weight;

    memcpy(p, &pInfo, sizeof (pInfo));
    return (sizeof (pInfo));
}

/* follow the most "internal" method for io_buf creation, called from the methods before  */
uint32_t SniffJoke::appendSJSessionInfo(uint8_t *p, SessionTrack &SexToDump)
{
    struct sex_record sr;

    if(!SexToDump.packet_number)
        return 0;

    sr.daddr = SexToDump.daddr;
    sr.dport = SexToDump.dport;
    sr.sport = SexToDump.sport;
    sr.packet_number = SexToDump.packet_number;

    memcpy( (void *)p, (void *)&sr, sizeof (sr));

    return sizeof (sr);
}
