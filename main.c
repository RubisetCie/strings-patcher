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

#ifndef NO_ENCODING
#include <iconv.h>
#ifndef _WIN32
#include <locale.h>
#include <langinfo.h>
#else
#include <winnls.h>
#endif
#endif

#include "pefile.h"
#include "elffile.h"

#define MAGIC_ELF "\x7f\x45\x4c\x46"
#define MAGIC_PE "MZ"

static void usage(char *progname)
{
    printf("Usage: %s [<options>] <file> <string> <replace>\n\n\
Options:\n"
#ifndef NO_ENCODING
"  -c,--encoding : Convert the input string and replacement to a given encoding (UTF-8, ISO8859-1, etc)\n"
#endif
"  -e,--exact    : Proceed the replacement with an exact match (default is more lenient)\n\
  -s,--section  : Override the section name in which to search for strings (default: .rodata)\n\
  -o,--output   : Output file\n\
  -h,--help     : Show help usage\n\n\
If no input or replacement is supplied, it will just print all the strings in the executable.\nIf the string is NOT found, returns 1. If the replacement couldn't fit, returns 2. Returns 0 otherwise.\n", progname);
}

/* Return the system codeset to standard iconv encoding */
static const char* getCodeset()
{
#ifndef _WIN32
    setlocale(LC_ALL, ""); /* Need to set the user's locale before querying, according to the function's man page! */
    return nl_langinfo(CODESET);
#else
    const UINT acp = GetACP();

    /* Code Page Identifiers (referenced from: https://learn.microsoft.com/en-us/windows/win32/intl/code-page-identifiers) */
    switch (acp)
    {
        case 437: return "IBM437";
        case 708:
        case 709:
        case 710:
        case 720: return "ISO-8859-6";
        case 737: return "CP737";
        case 775: return "CP775";
        case 850: return "CP850";
        case 852: return "CP852";
        case 855: return "CP855";
        case 857: return "CP857";
        case 858: return "CP858";
        case 860: return "CP860";
        case 861: return "CP861";
        case 862: return "CP862";
        case 863: return "CP863";
        case 864: return "CP864";
        case 865: return "CP865";
        case 866: return "CP866";
        case 869: return "CP869";
        case 874: return "WINDOWS-874";
        case 932: return "SHIFT_JIS";
        case 936: return "GB2312";
        case 949: return "KS_C_5601-1987";
        case 950: return "BIG5";
        case 1200: return "UTF-16LE";
        case 1201: return "UTF-16BE";
        case 1250: return "WINDOWS-1250";
        case 1251: return "WINDOWS-1251";
        case 1252: return "WINDOWS-1252";
        case 1253: return "WINDOWS-1253";
        case 1254: return "WINDOWS-1254";
        case 1255: return "WINDOWS-1255";
        case 1256: return "WINDOWS-1256";
        case 1257: return "WINDOWS-1257";
        case 1258: return "WINDOWS-1258";
        case 1361: return "JOHAB";
        case 10000: return "MACINTOSH";
        case 10004: return "MACARABIC";
        case 10005: return "MACHEBREW";
        case 10006: return "MACGREEK";
        case 10007: return "MACCYRILLIC";
        case 10010: return "MACROMAN";
        case 10017: return "MACUKRAINE";
        case 10021: return "MACTHAI";
        case 10029: return "MACCENTRALEUROPE";
        case 10079: return "MACICELAND";
        case 10081: return "MACTURKISH";
        case 10082: return "MACCROATIAN";
        case 12000: return "UTF-32LE";
        case 12001: return "UTF-32BE";
        case 20127: return "ASCII";
        case 20866: return "KOI8-R";
        case 20932: return "JIS_X0212";
        case 20936: return "GB2312";
        case 21866: return "KOI8-U";
        case 28591: return "ISO-8859-1";
        case 28592: return "ISO-8859-2";
        case 28593: return "ISO-8859-3";
        case 28594: return "ISO-8859-4";
        case 28595: return "ISO-8859-5";
        case 28596: return "ISO-8859-6";
        case 28597: return "ISO-8859-7";
        case 28598: return "ISO-8859-8";
        case 28599: return "ISO-8859-9";
        case 28603: return "ISO-8859-13";
        case 28605: return "ISO-8859-15";
        case 38598: return "ISO-8859-8";
        case 50220:
        case 50221:
        case 50222: return "CSISO2022JP";
        case 50225: return "CSISO2022KR";
        case 50227:
        case 50229: return "CSISO2022CN";
        case 51932: return "EUCJP";
        case 51936: return "EUCCN";
        case 51949:
        case 51950: return "EUCKR";
        case 52936: return "HZ-GB-2312";
        case 54936: return "GB18030";
        case 65000: return "UTF-7";
        case 65001: return "UTF-8";
        default:    return ""; /* Invalid */
    }
#endif
}

int main(int argc, char *const argv[])
{
    int i = 1, exact = 0;
    char magic[4];
    const char *filename = NULL;
    const char *output = NULL;
    const char *section = NULL;
#ifndef NO_ENCODING
    const char *codeset = NULL;
    const char *encoding = NULL;
    char *sheap = NULL;
    char *rheap = NULL;
#endif
    char *search = NULL;
    char *replace = NULL;
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
#ifndef NO_ENCODING
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
                codeset = getCodeset();

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
#endif
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

#ifndef NO_ENCODING
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
#endif

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
        i = elf_process(fileIn, fileOut, section,
#ifndef NO_ENCODING
                        encoding, codeset,
#endif
                        search, replace, exact);
    else if (strncmp(magic, MAGIC_PE, sizeof(MAGIC_PE)-1) == 0)
        i = pe_process(fileIn, fileOut, section,
#ifndef NO_ENCODING
                       encoding, codeset,
#endif
                       search, replace, exact);
    else
    {
        fprintf(stderr, "Executable format unrecognized: %2X%2X%2X%2X!\n", magic[0], magic[1], magic[2], magic[3]);
        i = 4;
    }

    fclose(fileIn);

  EXIT:
    if (fileOut != NULL)
        fclose(fileOut);

#ifndef NO_ENCODING
    free(sheap);
    free(rheap);
#endif

    return i;
}
