/*
 * Author: Matthieu Carteron <rubisetcie@gmail.com>
 * date:   2025-09-05
 *
 * Common functions to search and replace strings inside a table.
 */

#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

int search_and_replace(char *data, const char *search, const char *replace, size_t len);
int search_and_replace_exact(char *data, const char *search, const char *replace, size_t len);

#ifndef NO_ENCODING
#include <iconv.h>
int encode_string(iconv_t ectx, char *in, char *out, size_t inlen, size_t outlen);
#endif

void print_strings(char *data
                  ,size_t offset_start
                  ,size_t len
#ifndef NO_ENCODING
                  ,const char *enc_str
                  ,const char *enc_ttx
#endif
                   );

#endif
