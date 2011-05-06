/*
 * SniffJoke is a software able to confuse the Internet traffic analysis,
 * developed with the aim to improve digital privacy in communications and
 * to show and test some securiy weakness in traffic analysis software.
 * 
 * Copyright (C) 2011 vecna <vecna@delirandom.net>
 *                    evilaliv3 <giovanni.pellerano@evilaliv3.org>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Entertainment offered Order of the Stick, which link is 
 * http://www.giantitp.com/comics/oots0001.html, anyway we was talkin'
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SJ_PARSINGLINE_H
#define SJ_PARSINGLINE_H

#include "Utils.h"

struct mapTheKeys
{
    uint16_t value;
    const char *keyword;
};

class portLine
{
private:
    char line[MEDIUMBUF], keywordblock[MEDIUMBUF], portsblock[MEDIUMBUF];
    uint32_t linelen;

    uint16_t OrValue;
    bool portSelected[PORTSNUMBER];

    void fixPointer(void);

public:
    const char *error_message;

    void setup(const char *);
    void extractPorts(void);
    void extractValue(void);
    void mergeLine(uint16_t *);
};

#endif /* SJ_PARSINGLINE_H */
