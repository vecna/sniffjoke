#ifndef SJ_TTLFOCUSLIST_H
#define SJ_TTLFOCUSLIST_H


#include "TTLFocus.h"

#include <list>
using namespace std;

class TTLFocusList : public list<TTLFocus> {
public:
	TTLFocus* get(bool);
	TTLFocus* get(unsigned int);
};

#endif /* SJ_TTLFOCUSLIST_H */
