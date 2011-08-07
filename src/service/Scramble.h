#ifndef SJ_SCRAMBLE_H
#define SJ_SCRAMBLE_H

#include "SessionTrack.h"
#include "Packet.h" /* Packet.h contains ScrambleMask.h */

enum whenmark_t
{
    BEFORE_CHECKSUM = 1, AFTER_CHECKSUM = 2, BEFORE_HACK = 4, AFTER_HACK = 8
};

class ScrambleImpl
{
private:
    Packet *injectProbe();
    vector<Packet *> *registeredPktVec;

public:
    const scramble_t scrambleID;
    const char *scrambleName;
    bool removeOrigPkt;
    uint8_t whenMask;

    /* bool return value mean if the orig packet will be removed or not,
     * both of them generate packets putting them in vector<Packet *> scramblePkt,
     * Scramble class will not inject them in the queue, only TCPTrack.cc does */
    virtual bool apply(Packet &) = 0;
    virtual bool mystification(Packet &) = 0;

    /* for every destination address is popoulated a scramble dependend data */
    virtual bool isScrambleAvailable(/* IPList & */ Packet &) = 0;

    /* return true if the packet need to be keep in queue for the scramble pourpose */
    virtual bool pktKeepRefresh(Packet &) = 0;

    /* periodically an event is triggered and the scramble will have something to do */
    virtual bool periodicEvent(void) = 0;

    /* some scramble require to open a database, check status, etc */
    virtual bool scramInitSetup(void) = 0;

    /* some scramble require to send probe and wait for answer, open cache, etch */
    virtual void scramRegisterSession(Packet &, SessionTrack &) = 0;

    ScrambleImpl(scramble_t, const char *, vector<Packet *> *, bool, whenmark_t);
    virtual ~ScrambleImpl() = 0;
};

/** SINGLETON CLASS: 
 ** with this, Admiral Adama, will save New Caprica! **/
class Scramble 
{
private:
    vector<ScrambleImpl *> scramble_pool;

public:
    /* this is the vector used by all ScrambleImpl, and used to acquire 
     * packets thru TCPTrack::acquirePktVector */
    vector<Packet *> scramblePktV; 

    void setupScramble();
    void registerSession(Packet &, SessionTrack &);

    bool applySingleScramble(scramble_t, Packet &);
    bool applyScramble(whenmark_t, Packet &);
    bool mystifyScramble(whenmark_t, Packet &);

    void setupIncoming_filter();
    bool analyzeIncoming(Packet &);

    bool isKeepRequired(Packet &);
    void periodicEvent();

    Scramble(void);
    ~Scramble(void);
};

#endif // SJ_SCRAMBLE_H
