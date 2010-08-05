#ifndef SJ_TTLFOCUSLIST_H
#define SJ_TTLFOCUSLIST_H

#include "TTLFocus.h"

class TTLFocusList {
public:
    TTLFocus *front;
    TTLFocus *back;

    TTLFocusList();
    ~TTLFocusList();
    void insert(TTLFocus* ttlfocus);
    void remove(TTLFocus* ttlfocus);
    TTLFocus* get(bool must_continue);
    TTLFocus* get(unsigned int daddr);
};

#endif /* SJ_TTLFOCUSLIST_H */
