/*
 * Author: Matthieu Carteron <rubisetcie@gmail.com>
 * date:   2025-09-05
 *
 * Provides ELF files reading functions.
 */

#ifndef _WIN32
#include <byteswap.h>
#endif
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "elffile.h"

#define DEFAULT_SECTION ".rodata"

#define IS_32_BITS(c) c == 1
#define IS_LIT_ENDIAN(e) e == 1
#define IS_BIG_ENDIAN(e) e == 2

/* Provide functions to handle different endiannesses */

static uint16_t swap_data_16(uint8_t endianness, uint16_t d)
{
#ifndef _WIN32
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return IS_LIT_ENDIAN(endianness) ? bswap_16(d) : d;
#else
    return IS_BIG_ENDIAN(endianness) ? bswap_16(d) : d;
#endif
#else
    /* Assume Windows is always little-endian */
    return IS_BIG_ENDIAN(endianness) ? ((d << 8) | (d >> 8)) : d;
#endif
}

static uint32_t swap_data_32(uint8_t endianness, uint32_t d)
{
#ifndef _WIN32
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return IS_LIT_ENDIAN(endianness) ? bswap_32(d) : d;
#else
    return IS_BIG_ENDIAN(endianness) ? bswap_32(d) : d;
#endif
#else
    /* Assume Windows is always little-endian */
    return IS_BIG_ENDIAN(endianness) ?
        (((d) & 0xff000000) >> 24) |
        (((d) & 0x00ff0000) >>  8) |
        (((d) & 0x0000ff00) <<  8) |
        (((d) & 0x000000ff) << 24)
        : d;
#endif
}

static uint64_t swap_data_64(uint8_t endianness, uint64_t d)
{
#ifndef _WIN32
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return IS_LIT_ENDIAN(endianness) ? bswap_64(d) : d;
#else
    return IS_BIG_ENDIAN(endianness) ? bswap_64(d) : d;
#endif
#else
    /* Assume Windows is always little-endian */
    return IS_BIG_ENDIAN(endianness) ?
        (((d) & 0xff00000000000000ull) >> 56) |
        (((d) & 0x00ff000000000000ull) >> 40) |
        (((d) & 0x0000ff0000000000ull) >> 24) |
        (((d) & 0x000000ff00000000ull) >>  8) |
        (((d) & 0x00000000ff000000ull) <<  8) |
        (((d) & 0x0000000000ff0000ull) << 24) |
        (((d) & 0x000000000000ff00ull) << 40) |
        (((d) & 0x00000000000000ffull) << 56)
        : d;

#endif
}

/* Useful to represent either 32-bits and 64-bits data */
typedef union Word
{
    uint32_t e32;
    uint64_t e64;
} Word;

/* Struct containing the attributes specific to decode ELF */
typedef struct ElfAttrs
{
    uint8_t class;
    uint8_t endianness;
} ElfAttrs;

static Word swap_data_word(uint8_t endianness, uint8_t class, Word w)
{
    if (IS_32_BITS(class))
        w.e32 = swap_data_32(endianness, w.e32);
    else
        w.e64 = swap_data_64(endianness, w.e64);

    return w;
}

static long word_to_long(uint8_t class, Word w)
{
    if (IS_32_BITS(class))
        return (long)w.e32;
    else
        return (long)w.e64;
}

static int read_word(FILE *f, Word *ptr, uint8_t class)
{
    const size_t r;
    if (IS_32_BITS(r))
        return fread(&ptr->e32, sizeof(uint32_t), 1, f);
    else
        return fread(&ptr->e64, sizeof(uint64_t), 1, f);
}

static int advance_and_read(FILE *f, void *ptr, size_t size, long int offset)
{
    if (fseek(f, offset, SEEK_CUR) != 0)
        return 0;

    if (fread(ptr, size, 1, f) != 1)
        return 0;

    return 1;
}

static int advance_and_read_word(FILE *f, Word *ptr, uint8_t class, long int offset)
{
    if (fseek(f, offset, SEEK_CUR) != 0)
        return 0;

    if (read_word(f, ptr, class) != 1)
        return 0;

    return 1;
}

static int write_input_to_output_until(FILE *in, FILE *out, long offset)
{
    char buffer[1024];
    long i = 0, l;

    /* Write by chunks of 1024, until the offset is near */
    while (i + 1024 < offset)
    {
        if (fread(buffer, sizeof(buffer), 1, in) != 1)
        {
            fprintf(stderr, "Failed to read from the input file: %s!\n", strerror(errno));
            return 0;
        }
        if (fwrite(buffer, sizeof(buffer), 1, out) != 1)
        {
            fprintf(stderr, "Failed to write to the output file: %s!\n", strerror(errno));
            return 0;
        }
        i += 1024;
    }

    /* Compute the remaining length */
    l = offset - i;

    if (fread(buffer, l, 1, in) != 1)
    {
        fprintf(stderr, "Failed to read from the input file: %s!\n", strerror(errno));
        return 0;
    }
    if (fwrite(buffer, l, 1, out) != 1)
    {
        fprintf(stderr, "Failed to write to the output file: %s!\n", strerror(errno));
        return 0;
    }

    return 1;
}

static int write_input_to_output_end(FILE *in, FILE *out)
{
    char buffer[1024];
    long i, l, end;

    /* Get the end position of the file */
    i = ftell(in);
    fseek(in, 0, SEEK_END);
    end = ftell(in);
    fseek(in, i, SEEK_SET);

    /* Write by chunks of 1024, until the end */
    while (i + 1024 < end)
    {
        if (fread(buffer, sizeof(buffer), 1, in) != 1)
        {
            fprintf(stderr, "Failed to read from the input file: %s!\n", strerror(errno));
            return 0;
        }
        if (fwrite(buffer, sizeof(buffer), 1, out) != 1)
        {
            fprintf(stderr, "Failed to write to the output file: %s!\n", strerror(errno));
            return 0;
        }
        i += 1024;
    }

    /* Compute the remaining length */
    l = end - i;

    if (fread(buffer, l, 1, in) != 1)
    {
        fprintf(stderr, "Failed to read from the input file: %s!\n", strerror(errno));
        return 0;
    }
    if (fwrite(buffer, l, 1, out) != 1)
    {
        fprintf(stderr, "Failed to write to the output file: %s!\n", strerror(errno));
        return 0;
    }

    return 1;
}

static int elf_find_strings_section(FILE *in, const char *section, Word *sectionStringsAddress, Word *sectionStringsLen, ElfAttrs *attrs)
{
    uint16_t sectionTableLen, sectionTableSize, sectionTableNames, i;
    uint32_t sectionNameIndex;
    Word sectionTableAddress, sectionNamesAddress, sectionNamesLen;
    char *shstrtab = NULL;
    size_t shstrtab_len;
    long sections_addr;
    int ret = 0;

    /* Assume the magic number has already been read */

    sectionStringsAddress->e64 = 0;
    sectionStringsLen->e64 = 0;

    /* Read the class to find out whether the executable is 32 or 64 bits */
    if (fread(&attrs->class, sizeof(uint8_t), 1, in) != 1)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Read the endianness */
    if (fread(&attrs->endianness, sizeof(uint8_t), 1, in) != 1)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Read the absolute location of the section table */
    if (!advance_and_read_word(in, &sectionTableAddress, attrs->class, IS_32_BITS(attrs->class) ? 26 : 34))
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }
    sectionTableAddress = swap_data_word(attrs->endianness, attrs->class, sectionTableAddress);

    /* Read the size of an entry in the section table */
    if (!advance_and_read(in, &sectionTableSize, sizeof(uint16_t), 10))
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }
    sectionTableSize = swap_data_16(attrs->endianness, sectionTableSize);

    /* Read the length of the section table */
    if (fread(&sectionTableLen, sizeof(uint16_t), 1, in) != 1)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }
    sectionTableLen = swap_data_16(attrs->endianness, sectionTableLen);

    /* Read the location of the section names */
    if (fread(&sectionTableNames, sizeof(uint16_t), 1, in) != 1)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }
    sectionTableNames = swap_data_16(attrs->endianness, sectionTableNames);

    /* Goto the section table */
    sections_addr = word_to_long(attrs->class, sectionTableAddress);
    if (fseek(in, sections_addr, SEEK_SET) != 0)
    {
        fprintf(stderr, "Failed to go to the section headers table: %s!\n", strerror(errno));
        return 6;
    }

    /* Seek the section names header */
    if (fseek(in, sectionTableNames * sectionTableSize, SEEK_CUR) != 0)
    {
        fprintf(stderr, "Failed to go to the section name table: %s!\n", strerror(errno));
        return 6;
    }

    /* Read the offset of the section names */
    if (!advance_and_read_word(in, &sectionNamesAddress, attrs->class, IS_32_BITS(attrs->class) ? 16 : 24))
    {
        fprintf(stderr, "Failed to read the section names header: %s!\n", strerror(errno));
        return 6;
    }
    sectionNamesAddress = swap_data_word(attrs->endianness, attrs->class, sectionNamesAddress);

    /* Read the length of the section names */
    if (read_word(in, &sectionNamesLen, attrs->class) != 1)
    {
        fprintf(stderr, "Failed to read the section names header: %s!\n", strerror(errno));
        return 6;
    }
    sectionNamesLen = swap_data_word(attrs->endianness, attrs->class, sectionNamesLen);

    /* Goto the section names */
    if (fseek(in, word_to_long(attrs->class, sectionNamesAddress), SEEK_SET) != 0)
    {
        fprintf(stderr, "Failed to go to the section name table: %s!\n", strerror(errno));
        return 6;
    }

    /* Allocate enough memory to read the string */
    shstrtab_len = word_to_long(attrs->class, sectionNamesLen);
    if ((shstrtab = malloc(shstrtab_len)) == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for section names: %s!\n", strerror(errno));
        return 7;
    }

    /* Read the full section names table */
    if (fread(shstrtab, shstrtab_len, 1, in) != 1)
    {
        fprintf(stderr, "Failed to read the section names: %s!\n", strerror(errno));
        ret = 7; goto RET;
    }

    /* Return to the section table */
    if (fseek(in, sections_addr, SEEK_SET) != 0)
    {
        fprintf(stderr, "Failed to go to the section headers table: %s!\n", strerror(errno));
        ret = 6; goto RET;
    }

    /* Iterate through the list of entries */
    for (i = 0; i < sectionTableLen; i++)
    {
        /* Read the section name index */
        if (fread(&sectionNameIndex, sizeof(uint32_t), 1, in) != 1)
            goto NEXT;

        /* Check the name of the section against the desired section name */
        if (strcmp(section, &shstrtab[sectionNameIndex]) == 0)
        {
            /* If match, retrieve its offset and length */
            if (!advance_and_read_word(in, sectionStringsAddress, attrs->class, IS_32_BITS(attrs->class) ? 12 : 20))
            {
                fprintf(stderr, "Failed to iterate over the list of sections: %s!\n", strerror(errno));
                ret = 8; goto RET;
            }
            *sectionStringsAddress = swap_data_word(attrs->endianness, attrs->class, *sectionStringsAddress);

            if (read_word(in, sectionStringsLen, attrs->class) != 1)
            {
                fprintf(stderr, "Failed to iterate over the list of sections: %s!\n", strerror(errno));
                ret = 8; goto RET;
            }
            *sectionStringsLen = swap_data_word(attrs->endianness, attrs->class, *sectionStringsLen);

            break;
        }

      NEXT:

        /* Advance to the next entry */
        if (fseek(in, sectionTableSize - sizeof(uint32_t), SEEK_CUR) != 0)
        {
            fprintf(stderr, "Failed to iterate over the list of sections: %s!\n", strerror(errno));
            ret = 8; goto RET;
        }
    }

    if (sectionStringsAddress->e64 == 0)
    {
        fprintf(stderr, "Failed to find section named %s!\n", section);
        ret = 9;
    }

  RET:

    /* Free the allocated memory */
    free(shstrtab);

    return ret;
}

int elf_process(FILE *in, FILE *out, const char *section, const char *search, const char *replace, int exact)
{
    ElfAttrs attrs;
    Word sectionStringsAddress, sectionStringsLen;
    size_t strtab_len;
    char *strtab = NULL;
    long strtab_loc;
    int ret = 0;

    /* Pick a default section in case none is specified */
    if (section == NULL)
        section = DEFAULT_SECTION;

    /* Start by finding the strings section location */
    if ((ret = elf_find_strings_section(in, section, &sectionStringsAddress, &sectionStringsLen, &attrs)) != 0)
        return ret;

    /* Write everything before the strings section to the output (if specified) */
    strtab_loc = word_to_long(attrs.class, sectionStringsAddress);
    if (out != NULL)
    {
        if (fseek(in, 0, SEEK_SET) != 0)
        {
            fprintf(stderr, "Failed to write to the output file: %s!\n", strerror(errno));
            return 14;
        }
        if (!write_input_to_output_until(in, out, strtab_loc))
            return 14;
    }

    /* Goto the location */
    if (fseek(in, strtab_loc, SEEK_SET) != 0)
    {
        fprintf(stderr, "Failed to go to the strings section: %s!\n", strerror(errno));
        return 10;
    }

    /* Allocate memory for the whole strings table */
    strtab_len = word_to_long(attrs.class, sectionStringsLen);
    if ((strtab = malloc(strtab_len)) == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for strings table: %s!\n", strerror(errno));
        return 13;
    }

    /* Read the whole strings table */
    if (fread(strtab, strtab_len, 1, in) != 1)
    {
        fprintf(stderr, "Failed to read the strings table: %s!\n", strerror(errno));
        ret = 13; goto RET;
    }

    if (replace != NULL)
    {
        /* Search for the occurrence of the search in the list of strings */
        if (exact == 0)
            ret = search_and_replace(strtab, search, replace, strtab_len);
        else
            ret = search_and_replace_exact(strtab, search, replace, strtab_len);

        /* Write the modified strings table into either the output or the input file */
        if (out != NULL)
        {
            if (fwrite(strtab, strtab_len, 1, out) != 1)
            {
                fprintf(stderr, "Failed to write to the output file: %s!\n", strerror(errno));
                return 14;
            }

            /* Write the rest of the file to the output */
            if (!write_input_to_output_end(in, out))
                return 14;
        }
        else
        {
            /* Return to the strings table location */
            if (fseek(in, strtab_loc, SEEK_SET) != 0)
            {
                fprintf(stderr, "Failed to go to the strings section: %s!\n", strerror(errno));
                return 10;
            }

            if (fwrite(strtab, strtab_len, 1, in) != 1)
            {
                fprintf(stderr, "Failed to write to the input file: %s!\n", strerror(errno));
                return 15;
            }
        }
    }
    else
    {
        /* Just lay down the list of strings in the section (with their offset) */
        print_strings(strtab, strtab_loc, strtab_len);
    }

  RET:

    /* Free the allocated memory */
    free(strtab);

    return ret;
}
