/* SniffJoke.cc create the auto_ptr Scramble * "scramble" remind */

#include "IPList.h"
#include "SessionTrack.h"
#include "TTLFocus.h"
#include "TCPTrack.h"
#include "Packet.h"
#include "Scramble.h"
#include "ScrambleImpl.h"

/* this static buffer is used for debug/dump/write the scramble name sets in the bitMask */
char scrambleMask::scrambleList[ SCRAMBLE_SUPPORTED * 14 ];

/*
 * scrambleMask is used as variable inside Packet, Plugin and Scramble classess
 * to keep track of the series of scramble used, configured, supported, implemented, etc...
 */
scrambleMask & scrambleMask::operator+=(const scramble_t toAdd)
{
    innerMask |= (uint8_t)toAdd;
    return *this;
}

scrambleMask & scrambleMask::operator-=(const scramble_t toSub)
{
    innerMask |= (!(uint8_t)toSub);
    return *this;
}

scrambleMask & scrambleMask::operator=(const scramble_t newVal)
{
    innerMask = (uint8_t)newVal;
    return *this;
}

/* overloading again the same operators to support operations
 * between scrambleMask(s) */
scrambleMask & scrambleMask::operator+=(const scrambleMask toAdd)
{
    innerMask |= toAdd.innerMask;
    return *this;
}

scrambleMask & scrambleMask::operator-=(const scrambleMask toSub)
{
    innerMask |= (!(toSub.innerMask)); // boh ? XXX fixme antani, prima era ~=
    return *this;
}

scrambleMask & scrambleMask::operator=(const scrambleMask newVal)
{
    innerMask = (uint8_t)newVal.innerMask;
    return *this;
}

/* validity check replacing not/"!" */
bool scrambleMask::operator!(void)
{
    /* this works because enum scramble_t NOSCRAMBLESET has the 0 value */
    return (!(bool)innerMask);
}

bool scrambleMask::isScrambleSet(const scramble_t underTest)
{
    return (innerMask & (uint8_t)underTest);
}

/* scrambleMask.h need to be updated with these information about the morality of the single scramble */
bool scrambleMask::willCorrupt(void) const
{
#if 0
    uint32_t i;

    for( i = 0; i < SCRAMBLE_SUPPORTED; i++ )
    {

    }
#endif

    scramble_t tempCheck = TTL;
    return (innerMask & (uint8_t)tempCheck );
}

const char *scrambleMask::debug(void) const
{
    uint32_t i;
    char *p = &scrambleList[0];

    if(!innerMask)
        return reinterpret_cast<const char *>(NO_ONE_SCRAMBLE);

    memset(scrambleList, 0x00, sizeof(scrambleList));

    for( i = 0; i < SCRAMBLE_SUPPORTED; i++ )
    {
        if( ((uint8_t)sjImplementedScramble[i].scrambleBit) & innerMask )
        {
            if(strlen(p)) 
            {
                p[strlen(p)] = ',';
                p++;
            }

            snprintf(p, sizeof(scrambleList) - strlen(p), "%s", sjImplementedScramble[i].keyword);
        }
    }

    return const_cast<const char *>(&scrambleList[0]);
}

/* three kind of construction type: empty, single, mask */
scrambleMask::scrambleMask(void) : innerMask(NOSCRAMBLESET) { }
scrambleMask::scrambleMask(scramble_t init) : innerMask(init) { }
scrambleMask::scrambleMask(const scrambleMask &source) : innerMask(source.innerMask) { }

scrambleMask::~scrambleMask(void) { }

/*
 * Scramble keep track between the established session and the scramble 
 * usage, asyncronity, fake flow. but, I didn't remember why is here and not 
 * called by ScrambleImpl constructor.
 */
void Scramble::setupIncoming_filter(void)
{
}

/* when the scramble is ready to be setupped, this is called. why not in the constructor ? */
void Scramble::setupScramble(void)
{
    for (vector<ScrambleImpl *>::iterator it = scramble_pool.begin(); it != scramble_pool.end(); ++it)
    {
        ScrambleImpl *scI = *it;

        (*scI).scramInitSetup();
    }
}

/* when a new session is registered, need to be signaled to the scramble,  */
void Scramble::registerSession(Packet &pkt, SessionTrack &sex)
{
    for (vector<ScrambleImpl *>::iterator it = scramble_pool.begin(); it != scramble_pool.end(); ++it)
    {
        ScrambleImpl *scI = *it;

        (*scI).scramRegisterSession(pkt, sex);
    }
}

/* on the active session apply the scrambles anche check if a specific request exists */ 
bool Scramble::applyScramble(whenmark_t when, Packet &pkt)
{
    bool removeOrig = false;

    for (vector<ScrambleImpl *>::iterator it = scramble_pool.begin(); it != scramble_pool.end(); ++it)
    {
        ScrambleImpl *scI = *it;

        removeOrig = (*scI).apply(pkt);
    }

    return removeOrig;
}

bool Scramble::applySingleScramble(scramble_t request, Packet &pkt)
{
    bool removeOrig = false;
    ScrambleImpl *scI = NULL;

    for (vector<ScrambleImpl *>::iterator it = scramble_pool.begin(); it != scramble_pool.end(); ++it)
    {
        if( (*it)->scrambleID == request )
        {
            /* see below, acts as marker */
            scI = (*it);

            removeOrig = scI->apply(pkt);
        }
    }

#if 0 

/home/vecna/Desktop/sniffjoke-project/sniffjoke/src/service/Scramble.cc: In member function ‘bool Scramble::applySingleScramble(scramble_t, Packet&)’:
/home/vecna/Desktop/sniffjoke-project/sniffjoke/src/service/Scramble.cc:50: error: request for member ‘apply’ in ‘((Scramble*)this)->Scramble::scramble_pool.std::vector<_Tp, _Alloc>::operator[] [with _Tp = ScrambleImpl*, _Alloc = std::allocator<ScrambleImpl*>](((unsigned int)scrambleIndex))’, which is of non-class type ‘ScrambleImpl*’

    uint8_t scrambleIndex = (uint8_t)request;
    /* calling scramble_pool[x] popoulate scramble_pool[x].scramblePkt packet vector */
    removeOrig = scramble_pool[scrambleIndex].apply(pkt);

#endif

    if(scI == NULL)
        RUNTIME_EXCEPTION("requested invalid/not found scramble with id %d", (uint32_t)request);

    return removeOrig;
}

bool Scramble::mystifyScramble(whenmark_t when, Packet &pkt)
{
    pkt.SELFLOG("when %d in mystify not implemented", (uint32_t)when);
    return true;
}

bool Scramble::analyzeIncoming(Packet &pkt)
{
    return false;
}

bool Scramble::isKeepRequired(Packet &pkt)
{
    bool retval = false;
    /*
     * ATM we can put TCP only in KEEP status because due to the actual ttl 
     * bruteforce implementation a pure UDP flaw could go in starvation.
     */
    for (vector<ScrambleImpl *>::iterator it = scramble_pool.begin(); it != scramble_pool.end(); ++it)
    {
        ScrambleImpl *scI = *it;

        retval |= (*scI).pktKeepRefresh(pkt);
    }

    return retval;
}

void Scramble::periodicEvent(void)
{
    for (vector<ScrambleImpl *>::iterator it = scramble_pool.begin(); it != scramble_pool.end(); ++it)
    {
        ScrambleImpl *scI = *it;

        (*scI).periodicEvent();
    }
}

/* constructor: created as singleton */
Scramble::Scramble(void)
{
    LOG_VERBOSE("");

    scramble_pool.push_back(new TTLScramble( &scramblePktV ));
    scramble_pool.push_back(new CKSUMScramble( &scramblePktV ));
}

Scramble::~Scramble(void)
{
    LOG_VERBOSE("~Scramble");

    for (vector<ScrambleImpl *>::iterator it = scramble_pool.begin(); it != scramble_pool.end(); ++it) 
    {
        ScrambleImpl *scI = (*it);
        delete scI;
    }
}

ScrambleImpl::ScrambleImpl(scramble_t sID, const char *sN, vector<Packet *> *rV, bool rOp, whenmark_t when) :
registeredPktVec(rV),
scrambleID(sID),
scrambleName(sN),
removeOrigPkt(rOp),
whenMask(when)
{
}

ScrambleImpl::~ScrambleImpl(void)
{
}
