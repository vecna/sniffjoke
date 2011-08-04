#ifndef SCRAMBLEMASK_H
#define SCRAMBLEMASK_H

enum whenmark_t
{
    BEFORE_CHECKSUM = 1, AFTER_CHECKSUM = 2, BEFORE_HACK = 4, AFTER_HACK = 8
};

#define NO_ONE_SCRAMBLE "No scramble set"
#define TTL_SCRAMBLE_N  "TTL"
#define OPT_SCRAMBLE_N  "IPTCPOPT"
#define CKS_SCRAMBLE_N  "Checksum"
#define FNR_SCRAMBLE_N  "Fin-Rst"
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
    uint8_t innerMask;
    static char scrambleList[ SCRAMBLE_SUPPORTED * 14 ];

public:
    scrambleMask operator+=(const scramble_t);
    scrambleMask operator-=(const scramble_t);
    scrambleMask operator=(const scramble_t);
    bool operator!(void);

    const scrambleMask getShared(scrambleMask);
    bool isScrambleSet(const scramble_t);

    const char *debug(void)

    scrambleMask(void);
    scrambleMask(scramble_t);
    scrambleMask(scrambleMask);

    ~scrambleMask(void);
};

#endif // SCRAMBLE_MASK_H
