#ifndef SCRAMBLEIMPL_H
#define SCRAMBLEIMPL_H

#include "Utils.h"
#include "Packet.h"
#include "PacketQueue.h"
#include "PacketFilter.h"
#include "SessionTrack.h"
#include "TTLFocus.h"
#include "HDRoptions.h"
#include "PluginPool.h"
#include "Scramble.h"

class TTLScramble : public ScrambleImpl
{
public:
    TTLScramble (vector<Packet *> *);
    ~TTLScramble (void);

    bool apply(Packet &);
    bool mystification(Packet &);
    bool isScrambleAvailable(Packet & /* IPList & */);

    bool scramInitSetup(void);
    void scramRegisterSession(Packet &, SessionTrack &);

    bool pktKeepRefresh(Packet &);
    bool periodicEvent(void);

protected:
    void execTTLBruteforces(void);
    void injectTTLProbe(TTLFocus &);
    bool extractTTLinfo(const Packet &);
};

class CKSUMScramble : public ScrambleImpl
{
public:
    CKSUMScramble (vector<Packet *> *);
    ~CKSUMScramble (void);

    bool apply(Packet &);
    bool mystification(Packet &);
    bool isScrambleAvailable(Packet & /* IPList & */);

    bool scramInitSetup(void);
    void scramRegisterSession(Packet &, SessionTrack &);

    bool pktKeepRefresh(Packet &);
    bool periodicEvent(void);
};

#endif // SCRAMBLEIMPL_H
