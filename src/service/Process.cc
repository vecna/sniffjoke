/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
    
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

#include "Process.h"
#include "UserConf.h"

#include <fcntl.h>

extern auto_ptr<UserConf> userconf;

/* startup of the process */
Process::Process(void)
{
    LOG_DEBUG("");
}

Process::~Process(void)
{
    LOG_DEBUG("[process id %d, uid %d]", getpid(), getuid());
}

void Process::sigtrapSetup(sig_t sigtrap_function)
{
    sigemptyset(&sig_nset);
    sigemptyset(&sig_oset);

    sigaddset(&sig_nset, SIGINT);
    sigaddset(&sig_nset, SIGABRT);
    sigaddset(&sig_nset, SIGPIPE);
    sigaddset(&sig_nset, SIGTERM);
    sigaddset(&sig_nset, SIGQUIT);

    struct sigaction action;
    memset(&action, 0, sizeof (struct sigaction));
    action.sa_handler = sigtrap_function;
    action.sa_mask = sig_nset;

    sigaction(SIGINT, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);
}

void Process::sigtrapEnable(void)
{
    sigprocmask(SIG_SETMASK, &sig_oset, NULL);
}

void Process::sigtrapDisable(void)
{
    sigprocmask(SIG_BLOCK, &sig_nset, &sig_oset);
}

pid_t Process::readPidfile(void)
{
    int ret = 0;

    FILE *pidFile = fopen(SJ_PIDFILE, "r");
    if (pidFile == NULL)
    {
        LOG_DEBUG("pidfile %s not present: %s", SJ_PIDFILE, strerror(errno));
        return ret;
    }

    char tmpstr[7];
    if (fgets(tmpstr, sizeof(tmpstr), pidFile) != NULL)
        ret = atoi(tmpstr);
    fclose(pidFile);


    return ret;
}

void Process::writePidfile(void)
{
    FILE *pidFile = fopen(SJ_PIDFILE, "w");
    if (pidFile == NULL)
        RUNTIME_EXCEPTION("unable to open pidfile %s for pid %d for writing", SJ_PIDFILE, getpid());

    LOG_DEBUG("created pidfile %s from %d", SJ_PIDFILE, getpid());

    fprintf(pidFile, "%d", getpid());
    fclose(pidFile);
}

/* pidfile will be deleted if personal or derived from another process, the argument mean this */
void Process::unlinkPidfile(bool killOther)
{
    FILE *pidFile = fopen(SJ_PIDFILE, "r");
    char line[SMALLBUF];
    pid_t written;

    if (pidFile == NULL)
    {
        LOG_DEBUG("error with file %s: %s", SJ_PIDFILE, strerror(errno));
        return;
    }

    if( fgets(line, SMALLBUF, pidFile) == NULL)
    {
        LOG_ALL("weird, %s unable to read ? or empty ? [%s] anyway, will be removed", SJ_PIDFILE, strerror(errno));
        written = 0;
    }
    else
        written = atoi(line);

    fclose(pidFile);

    if (!written)
    {
        LOG_DEBUG("unable to read of %s", SJ_PIDFILE);
        goto __unlinkPidfile;
    }

    if (written != getpid() && killOther)
    {
        LOG_DEBUG("ready to delete %s with %d pid (we are %d)", SJ_PIDFILE, written, getpid());
        goto __unlinkPidfile;
    }

    if (written != getpid())
    {
        LOG_DEBUG("ignored request (written %d we %d)", written, getpid());
        return;
    }

__unlinkPidfile:

    if (unlink(SJ_PIDFILE))
        RUNTIME_EXCEPTION("weird, I'm able to open but not to unlink %s: %s", SJ_PIDFILE, strerror(errno));

    LOG_DEBUG("pid %d unlinked pidfile %s", getpid(), SJ_PIDFILE);
}

void Process::changedir(void)
{
    if(chdir(userconf->runcfg.working_dir))
    {
        RUNTIME_EXCEPTION("chdir into %s: %s: unable to start sniffjoke",
                          userconf->runcfg.working_dir, strerror(errno));
    }
}

void Process::background(void)
{
    if (fork())
        exit(0);

    int i;
    for (i = getdtablesize(); i >= 0; --i)
        close(i);

    if ((i = open("/dev/null", O_RDWR)) != 0 || dup(i) != 1 || dup(i) != 2)
        RUNTIME_EXCEPTION("unable to go in background: %s", strerror(errno));
}

void Process::isolation(void)
{
    LOG_DEBUG("the pid %d, uid %d is isolating themeself", getpid(), getuid());

    setsid();
    umask(027);
}

