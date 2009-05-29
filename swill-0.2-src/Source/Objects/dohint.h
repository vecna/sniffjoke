#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#define assert(x)  if (!(x)) { fprintf(stderr,"%s:%d. Failed assertion." #x "\n", __FILE__, __LINE__); abort(); }


#include "doh.h"
#include "dohobj.h"
