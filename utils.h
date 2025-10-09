
/* asprintf */
#ifndef _GNU_SOURCE
#	define _GNU_SOURCE
#endif

#include <stdarg.h>
#include <stdio.h>

struct stringStruct {
	size_t max;
	size_t len;
	char *text; /* pointer to an allocation of max + 1 */
};

typedef struct stringStruct String;

int addstrold(char **, size_t *, const char *, ...);
int addstr(String *, const char *, ...);
void strcpy_nospaces(char *, char *);
int gauge_to_si(unsigned long long, char **);
void benchmark_start(char const *, ...);
void benchmark_end(void);
char *implode(char const *, char **);
