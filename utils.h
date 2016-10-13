
/* asprintf */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdarg.h>

#ifdef HAVE_POW
#include <math.h>
#endif

#ifndef U64
#define U64
typedef unsigned long long u64;
#endif

struct stringStruct {
    size_t  max;
    size_t  len;
    char *  text; /* pointer to an allocation of max + 1 */
};

typedef struct stringStruct String;

int addstrold(char **, size_t *, const char *, ...);
int addstr(String *, const char *, ...);
void strcpy_nospaces(char *, char *);
int gauge_to_si(u64, char **);
void benchmark_start(char const *, ...);
void benchmark_end(void);
char *implode(char const *, char **);
