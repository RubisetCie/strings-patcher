/*
 * Author: Matthieu Carteron <rubisetcie@gmail.com>
 * date:   2025-09-05
 *
 * Common functions to search and replace strings inside a table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

static unsigned int count_occurrences(const char *str, const char *word, size_t *strLen, size_t wordLen, size_t len)
{
    size_t c = 0;
    unsigned int count = 0;

    *strLen = 0;
    while ((*strLen) < len)
    {
        /* End the search */
        if (str[(*strLen)] == 0)
            return count;

        /* Count the matches */
        if (str[(*strLen)] == word[c])
            c++;
        else
            c = 0;

        if (c >= wordLen)
        {
            c = 0;
            count++;
        }
        (*strLen)++;
    }

    return count;
}

static size_t available_length(const char *str, size_t len)
{
    size_t i = 0;
    char lc = 1;

    /* Walk through the string to detect the end of it */
    while (i < len)
    {
        if (str[i] != 0 && lc == 0)
            return i - 1;

        /* Save the last character */
        lc = str[i];
        i++;
    }

    /* Occurs if the string is located at the very end */
    return len - 1;
}

static void string_substitute(char *output, const char *input, const char *search, const char *replace, size_t searchLen, size_t replaceLen, size_t inputLen)
{
    size_t i = 0, j = 0, c = 0;

    while (i < inputLen)
    {
        if (input[i] == search[c])
            c++;
        else
        {
            c++;
            memcpy(&output[j], &input[i] - (c-1), c);
            j += c;
            c = 0;
        }

        if (c >= searchLen)
        {
            /* Write the replacement instead of copying the input */
            memcpy(&output[j], replace, replaceLen);
            j += replaceLen;
            c = 0;
        }
        i++;
    }
}

int search_and_replace(char *data, const char *search, const char *replace, size_t len)
{
    const size_t searchLen = strlen(search);
    const size_t replaceLen = strlen(replace);
    size_t i, c = 0, offset = 0, curLen;
    int ret = 1, state = 0;
    char *buffer = NULL;

    for (i = 0; i < len; i++)
    {
        if (state == 0)
        {
            /* Treat the null characters as terminations */
            if (data[i] == 0)
                continue;
            else
            {
                offset = i;
                state = 2;
            }
        }
        else if (state == 1)
        {
            if (data[i] == 0)
                state = 0;
            continue;
        }
        else
        {
            if (data[i] == 0)
            {
                c = 0;
                state = 0;
            }
        }

        /* Match the search character by character */
        if (data[i] == search[c])
            c++;
        else
            c = 0;

        /* If a match is found */
        if (c >= searchLen)
        {
            c = 0;
            ret = 0;
            state = 1;

            /* Count the occurrences of the search */
            const size_t count = count_occurrences(&data[offset], search, &curLen, searchLen, len - offset);

            /* Compute the required length */
            const size_t newLen = curLen + count * (replaceLen - searchLen);
            const size_t available = available_length(&data[offset], len - offset);
            if (newLen > available)
            {
                ret = 2;
                continue;
            }

            /* Allocate a buffer to store the substitued string */
            if (buffer != NULL)
            {
                if ((buffer = realloc(buffer, newLen)) == NULL)
                    continue;
            }
            else
            {
                if ((buffer = malloc(newLen)) == NULL)
                    continue;
            }

            /* Proceed to the substitution in the string */
            string_substitute(buffer, &data[offset], search, replace, searchLen, replaceLen, curLen);

            /* Write the string */
            memcpy(&data[offset], buffer, newLen);

            /* Add zeros padding */
            memset(&data[offset] + newLen, 0, available - newLen);
        }
    }

    free(buffer);

    return ret;
}

int search_and_replace_exact(char *data, const char *search, const char *replace, size_t len)
{
    const size_t searchLen = strlen(search);
    const size_t replaceLen = strlen(replace);
    size_t i, c = 0, offset = 0;
    int ret = 1, state = 0;

    for (i = 0; i < len; i++)
    {
        if (state == 0)
        {
            /* Treat the null characters as terminations */
            if (data[i] == 0)
                continue;
            else
            {
                offset = i;
                state = 2;
            }
        }
        else if (state == 1)
        {
            if (data[i] == 0)
                state = 0;
            continue;
        }

        /* Match the search character by character */
        if (data[i] == search[c])
            c++;
        else
        {
            c = 0;
            state = 1;
        }

        /* If a match is found */
        if (c > searchLen && data[i] == 0)
        {
            c = 0;
            ret = 0;
            state = 0;

            const size_t available = available_length(&data[offset], len - offset);
            if (replaceLen > available)
            {
                ret = 2;
                continue;
            }

            /* Write the string */
            memcpy(&data[offset], replace, replaceLen);

            /* Add zeros padding */
            memset(&data[offset] + replaceLen, 0, available - replaceLen);
        }
    }

    return ret;
}

void print_strings(const char *data, size_t offset_start, size_t len)
{
    size_t i, l = 0;
    const char *s = NULL;

    for (i = 0; i < len; i++)
    {
        if (data[i] == 0)
        {
            if (l > 0)
            {
                /* Print the string (may contains unprintable characters) */
                printf("%08X:%.*s\n", offset_start + i - l, l, s);

                l = 0;
                s = NULL;
            }
        }
        else
        {
            if (s == NULL)
                s = &data[i];
            l++;
        }
    }
}
