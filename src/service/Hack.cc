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

#include "Hack.h"

vector<cacheRecord *>::iterator Hack::cacheCheck(bool(*filter)(const cacheRecord &, const Packet &), const Packet &pkt)
{
    for (vector<cacheRecord *>::iterator it = hackCache.begin(); it != hackCache.end();)
    {
        cacheRecord &record = **it;
        if (filter(record, pkt)) {
            record.access_timestamp = sj_clock; /* update the access timestamp */
            return it;
        }

        if (record.access_timestamp < sj_clock - hackCacheTimeout)
        {
            cacheDelete(it); /* the ++ is done internally by the cacheDelete
                                to keep the iterator valid */
        }
        else
        {
            it++;
        }
    }

    return hackCache.end();
}

vector<cacheRecord *>::iterator Hack::cacheCreate(const Packet &pkt)
{
    cacheRecord *newrecord = new cacheRecord(pkt);
    hackCache.push_back(newrecord);
    return hackCache.end() - 1;
}

vector<cacheRecord *>::iterator Hack::cacheCreate(const Packet &pkt, void *data, size_t data_size)
{
    cacheRecord *newrecord = new cacheRecord(pkt, data, data_size);
    hackCache.push_back(newrecord);
    return hackCache.end() - 1;
}

void Hack::cacheDelete(vector<struct cacheRecord *>::iterator it)
{
    if ((*it)->cached_data != NULL)
        delete (*it)->cached_data;
    delete *it;
    hackCache.erase(it++);
}
