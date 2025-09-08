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
#include "pefile.h"
#include "elffile.h"

#define MAGIC_ELF "\x7f\x45\x4c\x46"
#define MAGIC_PE "MZ"

static void usage(char *progname)
{
    printf("Usage: %s [<options>] <file> <string> <replace>\n\n\
Options:\n\
  -e,--exact   : Proceed the replacement with an exact match (default is more lenient)\n\
  -s,--section : Override the section name in which to search for strings (default: .rodata)\n\
  -o,--output  : Output file\n\
  -h,--help    : Show help usage\n\n\
If no input or replacement is supplied, it will just print all the strings in the executable.\nIf the string is NOT found, returns 1. If the replacement couldn't fit, returns 2. Returns 0 otherwise.\n", progname);
}

int main(int argc, char *const argv[])
{
    int i = 1, exact = 0;
    char magic[4];
    const char *filename = NULL;
    const char *output = NULL;
    const char *section = NULL;
    const char *search = NULL;
    const char *replace = NULL;
    FILE *fileIn = NULL;
    FILE *fileOut = NULL;

    /* Checks the arguments */
    while (i < argc)
    {
        const char *arg = argv[i++];

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

    /* If no files are specified */
    if (filename == NULL)
    {
        usage(argv[0]);
        return 12;
    }
    if (replace == NULL)
        output = NULL;

    /* Check the input and the output are not the same */
    if (output != NULL)
    {
        if (strcmp(filename, output) == 0)
        {
            fputs("The input and the output can't be the same!\n", stderr);
            return 12;
        }

        if ((fileOut = fopen(output, "wb")) == NULL)
        {
            fprintf(stderr, "Failed to open the output file: %s!\n", strerror(errno));
            return 3;
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
        return 3;
    }

    /* Determine the type of executable using the magic number */
    fread(magic, sizeof(char), 4, fileIn);

    if (strncmp(magic, MAGIC_ELF, sizeof(MAGIC_ELF)-1) == 0)
        i = elf_process(fileIn, fileOut, section, search, replace, exact);
    else if (strncmp(magic, MAGIC_PE, sizeof(MAGIC_PE)-1) == 0)
        i = pe_process(fileIn, fileOut, section, search, replace, exact);
    else
    {
        fprintf(stderr, "Executable format unrecognized: %2X%2X%2X%2X!\n", magic[0], magic[1], magic[2], magic[3]);
        i = 4;
    }

    fclose(fileIn);

    if (fileOut != NULL)
        fclose(fileOut);

    return i;
}
