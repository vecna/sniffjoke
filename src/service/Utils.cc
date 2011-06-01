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

#include "Utils.h"

/* runtime_error runtime_exception(const char* func, const char* file, uint32_t line, const char* format, ...) */
runtime_error runtime_exception(const char* func, const char* format, ...)
{
    char error[LARGEBUF];
    char complete_error[LARGEBUF];
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(error, sizeof (error), format, arguments);
    /* snprintf(complete_error, sizeof (complete_error), "%s:%d %s() [ %s ]", file, line, func, error); */
    snprintf(complete_error, sizeof (complete_error), "%s() [ %s ]", func, error);
    va_end(arguments);

    stringstream stream;
    stream << complete_error;
    return std::runtime_error(stream.str());
}

string execOSCmd(string cmd)
{

    string data;
    char buffer[4096];

    /* cmd.append("| tr -d '\n'"); */

    FILE *stream = popen(cmd.c_str(), "r");

    /* get only the first line, to avoid the use of "| line" at the end of every command line,
     * before the data.append was derived collecting  */
    if(fgets(buffer, sizeof (buffer), stream) == NULL)
    {
        LOG_DEBUG("command [%s] return no any answer!", cmd.c_str());
    }
    else
    {
        /* cut the '\n' instead append "| tr -d '\n'", because this will join togheder more lines */
        buffer[strlen(buffer) -1] = 0x00;
        data.append(buffer);
    }

    pclose(stream);

    return data;
}

void init_random()
{
    /* random pool initialization */
    srandom(time(NULL));
    for (uint8_t i = 0; i < ((uint8_t) random() % 10); ++i)
        srandom(random());
}

void* memset_random(void *s, size_t n)
{
    /*
     * highly optimized memset_random
     *
     * long int random(void).
     *
     * long int is variable on different architectures;
     * for example on linux 64 bit is 8 chars long,
     * so do a while using single chars its an inefficient choice.
     *
     */

    if (debug.level() == TESTING_LEVEL)
    {
        memset(s, '6', n);
    }
    else
    {
        size_t longint = n / sizeof (long int);
        size_t finalbytes = n % sizeof (long int);
        unsigned char *cp = (unsigned char*) s;

        while (longint-- > 0)
        {
            *((long int*) cp) = random();
            cp += sizeof (long int);
        }

        while (finalbytes-- > 0)
        {
            *cp = (unsigned char) random();
            ++cp;
        }

    }

    return s;
}

bool random_percent(int32_t percent)
{
    if(debug.level() == TESTING_LEVEL)
        return true;

    return ( (random() % 100) + 1 <= percent );
}

int snprintfScramblesList(char *str, size_t size, uint8_t scramblesList)
{
    int len = snprintf(str, size, "%s%s%s%s",
                       scramblesList & SCRAMBLE_TTL ? "PRESCRIPTION," : "",
                       scramblesList & SCRAMBLE_MALFORMED ? "MALFORMED," : "",
                       scramblesList & SCRAMBLE_CHECKSUM ? "GUILTY," : "",
                       scramblesList & SCRAMBLE_INNOCENT ? "INNOCENT" : "");

    if (str[strlen(str) - 1] == ',')
    {
        str[strlen(str) - 1] = '\0';
        --len;
    }

    return len;
}
