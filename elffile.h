/*
 * Author: Matthieu Carteron <rubisetcie@gmail.com>
 * date:   2025-09-05
 *
 * Provides ELF files reading functions.
 */

#ifndef ELFFILE_H_INCLUDED
#define ELFFILE_H_INCLUDED

#include <stdio.h>

int elf_process(FILE *in, FILE *out, const char *section, const char *search, const char *replace, int exact);

#endif
