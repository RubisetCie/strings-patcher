/*
 * Author: Matthieu Carteron <rubisetcie@gmail.com>
 * date:   2025-09-05
 *
 * Provides PE files reading functions.
 */

#ifndef PEFILE_H_INCLUDED
#define PEFILE_H_INCLUDED

#include <stdio.h>

int pe_process(FILE *in
              ,FILE *out
              ,const char *section
#ifndef NO_ENCODING
              ,const char *encstr
              ,const char *encttx
#endif
              ,const char *search
              ,const char *replace
              ,int exact);

#endif
