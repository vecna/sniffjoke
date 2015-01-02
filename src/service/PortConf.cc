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

#include "PortConf.h"

/* find the first separator, port:port<sep>keyword. will be a ' ' or a \t */
void portLine::fixPointer(void)
{
    uint32_t portLen = 0, i = 0;
    bool spacing = false, before = true;
    char *startStrPort = NULL, *startKeyword = NULL;

    while (i < linelen)
    {
        /* this happen when "line[i]" match an invalid byte before the port number */
        if (spacing == false && before && !isdigit(line[i]))
            goto error_before;

        /* this happen when the first digit is matched, at the first space */
        if (spacing == false && before && isdigit(line[i]))
            before = false;

        /* this is used for set the pointer to the first byte */
        if (spacing == false && startStrPort == NULL && isdigit(line[i]))
            startStrPort = &line[i];

        /* continue to set endStrPort to the last byte in port1,porti2 or port1:portN */
        if (spacing == false && (isdigit(line[i]) || line[i] == ':' || line[i] == ','))
            portLen++;

        /* this is the spacing */
        if (spacing == false && (line[i] == ' ' || line[i] == '\t'))
            spacing = true;

        /* pointer to the keyword, break the loop */
        if (spacing == true && (line[i] != ' ' && line[i] != '\t') && isupper(line[i]))
        {
            startKeyword = &line[i];
            break;
        }

        i++;
    }

    if (startStrPort == NULL || portLen == 0 || startKeyword == NULL)
    {
        error_message = "not all fields found in this line";
        return;
    }

    /* copy in the right buffer the pointed data */
    memset(portsblock, 0x00, MEDIUMBUF);
    memcpy(portsblock, startStrPort, portLen);

    memset(keywordblock, 0x00, MEDIUMBUF);
    memcpy(keywordblock, startKeyword, strlen(startKeyword));

    return;

error_before:
    error_message = "separator between ports and keywords not found";
}

void portLine::setup(const char *readedline)
{
    memset(line, 0x00, MEDIUMBUF);
    memcpy(line, readedline, strlen(readedline));

    /* this is a modification that make more easy the extractValue for/strchr loop */
    linelen = strlen(line);

    OrValue = 0;
    memset(portSelected, 0x00, sizeof (portSelected));

    error_message = NULL;

    fixPointer();
}

void portLine::extractPorts(void)
{
    char *p = portsblock;
    uint32_t readedp;

    /* check if the user is not too much optimistic about conf flexibility */
    char *comma = strchr(p, ',');
    char *dpoints = strchr(p, ':');

    if ((comma != NULL) && (dpoints != NULL))
        goto not_so_flexibility_error;

    if (comma != NULL) /* block of code when the comma list is detected */
    {
        do
        {
            *comma = 0x00;

            readedp = atoi(p);

            if (readedp >= PORTSNUMBER || readedp < 0)
                goto invalid_range;

            portSelected[(uint16_t) atoi(p)] = true;

            p = ++comma;
        }
        while ((comma = strchr(p, ',')) != NULL);

        /* the last port, eg, one,two,three, here is trapped "three" because before is not */
        readedp = atoi(p);
        if (readedp >= PORTSNUMBER || readedp < 0)
            goto invalid_range;

        portSelected[(uint16_t) atoi(p)] = true;
    }
    else if (dpoints != NULL) /* block of code handling the startport:endport range */
    {
        uint32_t readedendp;

        *dpoints = 0x00;

        readedp = atoi(p);

        if (readedp >= PORTSNUMBER || readedp < 0)
            goto invalid_range;

        p = ++dpoints;

        readedendp = atoi(p);

        if (readedendp >= PORTSNUMBER || readedendp < 0)
            goto invalid_range;

        while (readedp <= readedendp)
        {
            portSelected[(uint16_t) readedp] = true;
            ++readedp;
        }
    }
    else /* the "single port" */
    {
        readedp = atoi(p);

        if (readedp >= PORTSNUMBER || readedp < 0)
            goto invalid_range;

        portSelected[(uint16_t) readedp] = true;
    }

    return;

invalid_range:
    error_message = "invalid range found, permitted goes since 1 to 65535";
    return;
not_so_flexibility_error:
    error_message = "a configuration line will support comma separation OR port range with ':', not both";
}

void portLine::extractValue(void)
{
    char *p = &keywordblock[0];
    const struct mapTheKeys *mtk;
    bool foundK;

    const struct mapTheKeys mappedKeywords[] = {
        { AGG_NONE, AGG_N_NONE},
        { AGG_VERYRARE, AGG_N_VERYRARE},
        { AGG_RARE, AGG_N_RARE},
        { AGG_COMMON, AGG_N_COMMON},
        { AGG_HEAVY, AGG_N_HEAVY},
        { AGG_ALWAYS, AGG_N_ALWAYS},
        { AGG_PACKETS10PEEK, AGG_N_PACKETS10PEEK},
        { AGG_PACKETS30PEEK, AGG_N_PACKETS30PEEK},
        { AGG_TIMEBASED5S, AGG_N_TIMEBASED5S},
        { AGG_TIMEBASED20S, AGG_N_TIMEBASED20S},
        { AGG_STARTPEEK, AGG_N_STARTPEEK},
        { AGG_LONGPEEK, AGG_N_LONGPEEK},
        { AGG_HANDSHAKE, AGG_N_HANDSHAKE},
        { 0, NULL}
    };

    do
    {
        /* every keywork checked must be found, otherwise is an error */
        foundK = false;

        if (*p == ',')
        {
            *p = 0x00;
            ++p;
        }

        for (mtk = &mappedKeywords[0]; mtk->value; ++mtk)
        {
            if (!memcmp(mtk->keyword, p, strlen(mtk->keyword)))
            {
                foundK = true;
                OrValue |= mtk->value;
                break;
            }
        }

        if (!foundK)
            goto keyword_not_found;
    }
    while ((p = strchr(p, ',')) != NULL);

    return;

keyword_not_found:
    error_message = "invalid keyword found in this line";
}

void portLine::mergeLine(uint16_t *portarray)
{
    for (uint32_t i = 0; i < PORTSNUMBER; ++i)
    {
        if (portSelected[i])
            portarray[i] = OrValue;
    }
}

