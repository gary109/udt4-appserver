#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <ctype.h>

#define NO_DEBUG     0
#define DEBUG_LEVEL1 1
#define DEBUG_LEVEL2 2
#define DEBUG_LEVEL3 3

#ifdef WIN32
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
//typedef unsigned long uint32_t;
#endif

/* cl.exe has a different 'inline' keyword for some dumb reason */
#ifdef WIN32
#define _inline_ __inline
#else
#define _inline_ inline
#endif

#define PERROR_GOTO(cond,err,label){        \
        if(cond)                            \
        {                                   \
            if(debug_level >= DEBUG_LEVEL1) \
                perror(err) ;               \
            goto label;                     \
        }}

#define ERROR_GOTO(cond,str,label){                  \
        if(cond)                                     \
        {                                            \
            if(debug_level >= DEBUG_LEVEL2)          \
                fprintf(stderr, "Error: %s\n", str); \
            goto label;                              \
        }}

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#ifdef SOLARIS
/* Copied from sys/time.h on linux system since solaris system that I tried to
 * compile on didn't have timeradd macro. */
#define timeradd(a, b, result)                                                \
    do {                                                                      \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                         \
        (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                      \
        if ((result)->tv_usec >= 1000000)                                     \
        {                                                                     \
            ++(result)->tv_sec;                                               \
            (result)->tv_usec -= 1000000;                                     \
        }                                                                     \
    } while (0)
#endif /* SOLARIS */

static _inline_ int isnum(char *s)
{
    for(; *s != '\0'; s++)
    {
        if(!isdigit((int)*s))
            return 0;
    }

    return 1;
}

#endif /* COMMON_H */