#ifndef SJ_TTLFOCUSLIST_H
#define SJ_TTLFOCUSLIST_H


#include "TTLFocus.h"

#include <list>
using namespace std;

class TTLFocusList : public list<TTLFocus> {
public:
	TTLFocus* get(unsigned int daddr);
};

#endif /* SJ_TTLFOCUSLIST_H */
