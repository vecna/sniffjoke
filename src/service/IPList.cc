/*
 *   SniffJoke is a software able to confuse the Internet traffic analysis,
 *   developed with the aim to improve digital privacy in communications and
 *   to show and test some securiy weakness in traffic analysis software.
 *   
 *   Copyright (C) 2011 vecna <vecna@delirandom.net>
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

#include "IPList.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

typedef char ipconfig_cache_record[23]; /* "max size is 192.168.254.254,A,B,C" plus "\0" */

IPList::IPList(uint32_t ip, char a, char b, char c) :
ip(ip),
a(a),
b(b),
c(c)
{
    selflog(__func__, NULL);
}

IPList::~IPList()
{
    selflog(__func__, NULL);
}

void IPList::selflog(const char *func, const char *lmsg) const
{
    if (debug.level() == SUPPRESS_LOG)
        return;

    debug.log(SESSIONS_DEBUG, "antani");
}

IPListMap::IPListMap(const char* dumpfile)
{
    debug.log(ALL_LEVEL, "%s: loading ipconfig from %s", __func__, dumpfile);

    if ((diskcache = sj_fopen(dumpfile, "r+")) == NULL)
    {
        debug.log(ALL_LEVEL, "keeping a ipconfig cache is required, link it to /dev/null if don't like it");
        SJ_RUNTIME_EXCEPTION(strerror(errno));
    }
    load();
}

IPListMap::~IPListMap()
{
    debug.log(VERBOSE_LEVEL, __func__);
    dump();
    for (IPListMap::iterator it = begin(); it != end();)
    {
        delete &(*it->second);
        erase(it++);
    }
}

IPList& IPListMap::add(uint32_t ip, char a, char b, char c)
{
    IPList *ipcnf;

    a = (a == 'Y' ? 'Y' : 'N');
    b = (b == 'Y' ? 'Y' : 'N');
    c = (c == 'Y' ? 'Y' : 'N');

    /* check if the key it's already present */
    IPListMap::iterator it = find(ip);
    if (it != end())
    { /* on hit: update the IPConfig object. */
        ipcnf = &(*it->second);
        ipcnf->a = a;
        ipcnf->b = b;
        ipcnf->c = c;
    }
    else
    { /* on miss: create a new IPConfig and insert it into the map */
        ipcnf = &(*insert(pair<uint32_t, IPList*>(ip, new IPList(ip, a, b, c))).first->second);
    }

    return *ipcnf;
}

bool IPListMap::isPresent(uint32_t ip)
{
    IPListMap::iterator it;
    return (find(ip) != end());
}

void IPListMap::load()
{
    uint32_t records_num = 0;
    ipconfig_cache_record record;
    char tmp_ip[17];
    char tmp_a, tmp_b, tmp_c;
    void* ret;

    fseek(diskcache, 0, SEEK_END);
    if (!ftell(diskcache))
        debug.log(ALL_LEVEL, "unable to access ipconfig cache: sniffjoke will start without it");
    else
    {
        rewind(diskcache);
        while ((ret = fgets(record, sizeof (record), diskcache)) != NULL)
        {
            sscanf(record, "%s,%c,%c,%c\n", tmp_ip, &tmp_a, &tmp_b, &tmp_c);
            printf("%s,%c,%c,%c\n", tmp_ip, tmp_a, tmp_b, tmp_c);
            tmp_a = (tmp_a == 'Y' ? 'Y' : 'N');
            tmp_b = (tmp_b == 'Y' ? 'Y' : 'N');
            tmp_c = (tmp_c == 'Y' ? 'Y' : 'N');
            records_num++;
        }
    }

    debug.log(ALL_LEVEL, "ipconfigmap load completed: %u records loaded", records_num);
}

void IPListMap::dump()
{
    uint32_t records_num = 0;

    ipconfig_cache_record record;

    rewind(diskcache);

    for (IPListMap::iterator it = begin(); it != end(); ++it)
    {

        IPList *tmp = &(*it->second);

        snprintf(record, sizeof (record), "%s,%c,%c,%c\n", inet_ntoa(*((struct in_addr *) &(tmp->ip))), tmp->a, tmp->b, tmp->c);

        if (fwrite(&record, strlen(record), 1, diskcache) != 1)
        {
            debug.log(ALL_LEVEL, "unable to dump ipconfig: %s", strerror(errno));
            return;
        }

        ++records_num;
    }

    debug.log(ALL_LEVEL, "ipconfigmap dump completed with %u records dumped", records_num);
}
