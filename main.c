/*
 * Author: Matthieu Carteron <rubisetcie@gmail.com>
 * date:   2025-09-05
 *
 * Alter strings in a compiled executable binary (Linux ELF and Windows PE).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>
#include <locale.h>
#include <langinfo.h>
#include "pefile.h"
#include "elffile.h"

#define MAGIC_ELF "\x7f\x45\x4c\x46"
#define MAGIC_PE "MZ"

static void usage(char *progname)
{
    printf("Usage: %s [<options>] <file> <string> <replace>\n\n\
Options:\n\
  -c,--encoding : Convert the input string and replacement to a given encoding (UTF-8, ISO8859-1, etc)\n\
  -e,--exact    : Proceed the replacement with an exact match (default is more lenient)\n\
  -s,--section  : Override the section name in which to search for strings (default: .rodata)\n\
  -o,--output   : Output file\n\
  -h,--help     : Show help usage\n\n\
If no input or replacement is supplied, it will just print all the strings in the executable.\nIf the string is NOT found, returns 1. If the replacement couldn't fit, returns 2. Returns 0 otherwise.\n", progname);
}

int main(int argc, char *const argv[])
{
    int i = 1, exact = 0;
    char magic[4];
    const char *filename = NULL;
    const char *output = NULL;
    const char *codeset = NULL;
    const char *encoding = NULL;
    const char *section = NULL;
    char *search = NULL, *sheap = NULL;
    char *replace = NULL, *rheap = NULL;
    FILE *fileIn = NULL;
    FILE *fileOut = NULL;

    /* Checks the arguments */
    while (i < argc)
    {
        char *const arg = argv[i++];

        if (strcmp(arg, "-?") == 0 ||
            strcmp(arg, "-h") == 0 ||
            strcmp(arg, "--help") == 0)
        {
            usage(argv[0]);
            return 0;
        }
        else if (strcmp(arg, "-e") == 0 ||
                 strcmp(arg, "--exact") == 0)
        {
            exact = 1;
        }
        else if (strcmp(arg, "-s") == 0 ||
                 strcmp(arg, "--section") == 0)
        {
            if (i >= argc || argv[i][0] == '-')
            {
                fputs("Missing section name after parameter!\n", stderr);
                return 11;
            }
            else
                section = argv[i++];
        }
        else if (strcmp(arg, "-o") == 0 ||
                 strcmp(arg, "--output") == 0)
        {
            if (i >= argc || argv[i][0] == '-')
            {
                fputs("Missing output after parameter!\n", stderr);
                return 11;
            }
            else
                output = argv[i++];
        }
        else if (strcmp(arg, "-c") == 0 ||
                 strcmp(arg, "--encoding") == 0)
        {
            if (i >= argc || argv[i][0] == '-')
            {
                fputs("Missing encoding after parameter!\n", stderr);
                return 11;
            }
            else
            {
                char *enc = argv[i++], *curr = enc;
                iconv_t ctx;

                /* Convert the input to uppercase for good measure */
                while (*curr != 0)
                {
                    *curr = toupper(*curr);
                    curr++;
                }

                /* Query the system codeset */
                setlocale(LC_ALL, ""); /* Need to set the user's locale before querying, according to the function's man page! */
                codeset = nl_langinfo(CODESET);

                /* Check if the encoding conversion is supported by iconv */
                if ((ctx = iconv_open(enc, codeset)) == (iconv_t)-1)
                {
                    fprintf(stderr, "Encoding conversion not supported between: %s -> %s\n", codeset, enc);
                    return 13;
                }
                iconv_close(ctx);
                encoding = enc;
            }
        }
        else if (arg[0] == '-')
        {
            fprintf(stderr, "Unrecognized parameter: %s\n", arg);
            return 11;
        }
        else
        {
            if (filename == NULL)
                filename = arg;
            else if (search == NULL)
                search = arg;
            else if (replace == NULL)
                replace = arg;
            else
            {
                fputs("Only one file can be supplied!\n", stderr);
                return 11;
            }
        }
    }

    /* Encode the search and replace strings */
    if (encoding != NULL && (search != NULL || replace != NULL))
    {
        iconv_t ctx = iconv_open(encoding, codeset);
        if (ctx == (iconv_t)-1)
            return 13;

        if (search != NULL)
        {
            const size_t len = strlen(search);
            size_t newlen = len + len + 1; /* Double the length of the string is a good enough heuristic */

            if ((sheap = malloc(newlen)) != NULL)
            {
                if ((newlen = encode_string(ctx, search, sheap, len, newlen)) != -1)
                {
                    sheap[newlen] = 0;
                    search = sheap;
                }
            }
        }

        if (replace != NULL)
        {
            const size_t len = strlen(replace);
            size_t newlen = len + len + 1; /* Double the length ... heuristic */

            if ((rheap = malloc(newlen)) != NULL)
            {
                if ((newlen = encode_string(ctx, replace, rheap, len, newlen)) != -1)
                {
                    rheap[newlen] = 0;
                    replace = rheap;
                }
            }
        }

        iconv_close(ctx);
    }

    /* If no files are specified */
    if (filename == NULL)
    {
        usage(argv[0]);
        i = 12; goto EXIT;
    }
    if (replace == NULL)
        output = NULL;

    /* Check the input and the output are not the same */
    if (output != NULL)
    {
        if (strcmp(filename, output) == 0)
        {
            fputs("The input and the output can't be the same!\n", stderr);
            i = 12; goto EXIT;
        }

        if ((fileOut = fopen(output, "wb")) == NULL)
        {
            fprintf(stderr, "Failed to open the output file: %s!\n", strerror(errno));
            i = 3; goto EXIT;
        }

        fileIn = fopen(filename, "rb");
    }
    else
    {
        if (replace != NULL)
            fileIn = fopen(filename, "rb+");
        else
            fileIn = fopen(filename, "rb");
    }

    /* Open the input executable file (if output isn't specified, replace in the input directly) */
    if (fileIn == NULL)
    {
        fprintf(stderr, "Failed to open the input file: %s!\n", strerror(errno));
        i = 3; goto EXIT;
    }

    /* Determine the type of executable using the magic number */
    fread(magic, sizeof(char), 4, fileIn);

    if (strncmp(magic, MAGIC_ELF, sizeof(MAGIC_ELF)-1) == 0)
        i = elf_process(fileIn, fileOut, section, encoding, codeset, search, replace, exact);
    else if (strncmp(magic, MAGIC_PE, sizeof(MAGIC_PE)-1) == 0)
        i = pe_process(fileIn, fileOut, section, encoding, codeset, search, replace, exact);
    else
    {
        fprintf(stderr, "Executable format unrecognized: %2X%2X%2X%2X!\n", magic[0], magic[1], magic[2], magic[3]);
        i = 4;
    }

    fclose(fileIn);

  EXIT:
    if (fileOut != NULL)
        fclose(fileOut);

    free(sheap);
    free(rheap);
    return i;
}
