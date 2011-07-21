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

/* the main must implement it */
void sigtrap(int);

/* startup of the process */
Process::Process(void)
{
    LOG_DEBUG("");
}

Process::~Process(void)
{
    LOG_DEBUG("[process id %d, uid %d]", getpid(), getuid());
}

void Process::sigtrapSetup(void)
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
    action.sa_handler = sigtrap;
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

    FILE *pidFile = fopen(userconf->runcfg.pidabspath, "r");
    if (pidFile == NULL)
    {
        LOG_DEBUG("pidfile %s not present: %s", userconf->runcfg.pidabspath, strerror(errno));
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
    FILE *pidFile = fopen(userconf->runcfg.pidabspath, "w");
    if (pidFile == NULL)
        RUNTIME_EXCEPTION("unable to open pidfile %s for pid %d for writing", userconf->runcfg.pidabspath, getpid());

    LOG_DEBUG("created pidfile %s from %d", userconf->runcfg.pidabspath, getpid());

    fprintf(pidFile, "%d", getpid());
    fclose(pidFile);
}

void Process::unlinkPidfile(void)
{
    if (unlink(userconf->runcfg.pidabspath))
        RUNTIME_EXCEPTION("unable to unlink %s: %s", userconf->runcfg.pidabspath, strerror(errno));

    LOG_DEBUG("pid %d unlinked pidfile %s", getpid(), userconf->runcfg.pidabspath);
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

