/*
 * Author: Matthieu Carteron <rubisetcie@gmail.com>
 * date:   2025-09-05
 *
 * Provides PE files reading functions.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "pefile.h"

#define DEFAULT_SECTION ".rdata"
#define PE_SIGNATURE "\x50\x45\x00\x00"

static int advance_and_read(FILE *f, void *ptr, size_t size, long int offset)
{
    if (fseek(f, offset, SEEK_CUR) != 0)
        return 0;

    if (fread(ptr, size, 1, f) != 1)
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

static int pe_find_strings_section(FILE *in, const char *section, uint32_t *sectionStringsAddress, uint32_t *sectionStringsLen)
{
    uint32_t headerLocation;
    uint16_t sectionNums, optionalHeaderSize, i;
    char signature[4], sectionName[8];

    *sectionStringsAddress = 0;
    *sectionStringsLen = 0;

    /* Skip to the PE header (offset 0x3C) */
    if (fseek(in, 0x3c, SEEK_SET) != 0)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Read the offset of the PE header */
    if (fread(&headerLocation, sizeof(uint32_t), 1, in) != 1)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Goto the PE header */
    if (fseek(in, headerLocation, SEEK_SET) != 0)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Read the signature of the PE header */
    if (fread(signature, sizeof(char), 4, in) != 4)
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Check the signature of the PE header */
    if (strncmp(signature, PE_SIGNATURE, sizeof(PE_SIGNATURE)-1) != 0)
    {
        fprintf(stderr, "Bad PE header signature: %2X%2X%2X%2X!\n", signature[0], signature[1], signature[2], signature[3]);
        return 4;
    }

    /* Read the number of sections */
    if (!advance_and_read(in, &sectionNums, sizeof(uint16_t), 2))
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Read the size of the optional header */
    if (!advance_and_read(in, &optionalHeaderSize, sizeof(uint16_t), 12))
    {
        fprintf(stderr, "Failed to read executable header: %s!\n", strerror(errno));
        return 5;
    }

    /* Move past the optional header to reach the sections header */
    if (fseek(in, optionalHeaderSize + 2, SEEK_CUR) != 0)
    {
        fprintf(stderr, "Failed to go to the section headers table: %s!\n", strerror(errno));
        return 6;
    }

    /* Iterate through the list of sections */
    for (i = 0; i < sectionNums; i++)
    {
        /* Read the section name */
        if (fread(sectionName, sizeof(char), 8, in) != 8)
            goto NEXT;

        /* Check the name of the section against the desired section name */
        if (strncmp(section, sectionName, 8) == 0)
        {
            /* If match, retrieve its pointer and size */
            if (!advance_and_read(in, sectionStringsLen, sizeof(uint32_t), 8))
            {
                fprintf(stderr, "Failed to iterate over the list of sections: %s!\n", strerror(errno));
                return 8;
            }

            if (fread(sectionStringsAddress, sizeof(uint32_t), 1, in) != 1)
            {
                fprintf(stderr, "Failed to iterate over the list of sections: %s!\n", strerror(errno));
                return 8;
            }

            break;
        }

      NEXT:

        /* Advance to the next entry */
        if (fseek(in, 32, SEEK_CUR) != 0)
        {
            fprintf(stderr, "Failed to iterate over the list of sections: %s!\n", strerror(errno));
            return 8;
        }
    }

    if (*sectionStringsAddress == 0)
    {
        fprintf(stderr, "Failed to find section named %s!\n", section);
        return 9;
    }

    return 0;
}

int pe_process(FILE *in, FILE *out, const char *section, const char *search, const char *replace, int exact)
{
    uint32_t sectionStringsAddress, sectionStringsLen;
    char *strtab = NULL;
    int ret = 0;

    /* Pick a default section in case none is specified */
    if (section == NULL)
        section = DEFAULT_SECTION;

    /* Start by finding the strings section location */
    if ((ret = pe_find_strings_section(in, section, &sectionStringsAddress, &sectionStringsLen)) != 0)
        return ret;

    /* Write everything before the strings section to the output (if specified) */
    if (out != NULL)
    {
        if (fseek(in, 0, SEEK_SET) != 0)
        {
            fprintf(stderr, "Failed to write to the output file: %s!\n", strerror(errno));
            return 14;
        }
        if (!write_input_to_output_until(in, out, sectionStringsAddress))
            return 14;
    }

    /* Goto the location */
    if (fseek(in, sectionStringsAddress, SEEK_SET) != 0)
    {
        fprintf(stderr, "Failed to go to the strings section: %s!\n", strerror(errno));
        return 10;
    }

    /* Allocate memory for the whole strings table */
    if ((strtab = malloc(sectionStringsLen)) == NULL)
    {
        fprintf(stderr, "Failed to allocate memory for strings table: %s!\n", strerror(errno));
        return 13;
    }

    /* Read the whole strings table */
    if (fread(strtab, sectionStringsLen, 1, in) != 1)
    {
        fprintf(stderr, "Failed to read the strings table: %s!\n", strerror(errno));
        ret = 13; goto RET;
    }

    if (replace != NULL)
    {
        /* Search for the occurrence of the search in the list of strings */
        if (exact == 0)
            ret = search_and_replace(strtab, search, replace, sectionStringsLen);
        else
            ret = search_and_replace_exact(strtab, search, replace, sectionStringsLen);

        /* Write the modified strings table into either the output or the input file */
        if (out != NULL)
        {
            if (fwrite(strtab, sectionStringsLen, 1, out) != 1)
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
            if (fseek(in, sectionStringsAddress, SEEK_SET) != 0)
            {
                fprintf(stderr, "Failed to go to the strings section: %s!\n", strerror(errno));
                return 10;
            }

            if (fwrite(strtab, sectionStringsLen, 1, in) != 1)
            {
                fprintf(stderr, "Failed to write to the input file: %s!\n", strerror(errno));
                return 15;
            }
        }
    }
    else
    {
        /* Just lay down the list of strings in the section (with their offset) */
        print_strings(strtab, sectionStringsAddress, sectionStringsLen);
    }

  RET:

    /* Free the allocated memory */
    free(strtab);

    return ret;
}
