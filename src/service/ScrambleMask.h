#ifndef SCRAMBLEMASK_H
#define SCRAMBLEMASK_H

/* this is the base enum used for keep track of which scramble has been used/requested */
enum scramble_t
{   /* -- Scramble.h has to be updated whenever a new value here is addedd -- */
    NOSCRAMBLESET = 0, TTL = 1, IPTCPOPT = 2, CKSUM = 4, FINRST = 8, FRAGMENT = 16, TCPOVERLAP = 32
};

#define NO_ONE_SCRAMBLE "No scramble set"
#define TTL_SCRAMBLE_N  "TTL"
#define OPT_SCRAMBLE_N  "IPTCPOPT"
#define CKS_SCRAMBLE_N  "Checksum"
#define FNR_SCRAMBLE_N  "FinRst"
#define FRAG_SCRAMBLE_N "IPfragment"
#define TCPO_SCRAMBLE_N "TCPoverlap"

/* the scramble_t is defined in Packet.h */
struct implementedScramble {
    const char *keyword;
    scramble_t scrambleBit;
};

#define SCRAMBLE_SUPPORTED  6

/* a global variable called by PluginPool.cc and [fixme] */
const struct implementedScramble sjImplementedScramble[SCRAMBLE_SUPPORTED] =  {
    { TTL_SCRAMBLE_N, TTL },
    { OPT_SCRAMBLE_N, IPTCPOPT },
    { CKS_SCRAMBLE_N, CKSUM },
    { FNR_SCRAMBLE_N, FINRST },
    { FRAG_SCRAMBLE_N, FRAGMENT },
    { TCPO_SCRAMBLE_N, TCPOVERLAP }
};


class scrambleMask
{
private:
    static char scrambleList[ SCRAMBLE_SUPPORTED * 14 ];

public:
    uint8_t innerMask;

    scrambleMask & operator+=(const scramble_t);
    scrambleMask & operator-=(const scramble_t);
    scrambleMask & operator=(const scramble_t);

    scrambleMask & operator+=(const scrambleMask);
    scrambleMask & operator-=(const scrambleMask);
    scrambleMask & operator=(const scrambleMask);

    bool operator!(void);

    const scrambleMask getShared(const scrambleMask &);
    bool isScrambleSet(const scramble_t);

    const char *debug(void);

    scrambleMask(void);
    scrambleMask(scramble_t);
    scrambleMask(const scrambleMask &);

    ~scrambleMask(void);
};

#endif // SCRAMBLE_MASK_H
