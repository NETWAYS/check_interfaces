#include "utils.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Add a string
 */

int addstrold(char **strp, size_t *strs, const char *format, ...) {
	va_list val;
	size_t written;

	va_start(val, format);

	written = vsnprintf(*strp, *strs, format, val);
	va_end(val);

	if (written >= *strs) {
		// buffer full
		*strs = 0;
		return (1);
	}

	*strs = (*strs - written);
	*strp = (*strp + written);
	return (0);
}

int addstr(String *str, const char *format, ...) {
	va_list val;
	size_t written;
	size_t available;
	char *pos;

	available = str->max - str->len;
	pos = str->text + str->len;

	va_start(val, format);

	written = vsnprintf(pos, available, format, val);
	va_end(val);

	if (written >= available) {
		/* buffer full */
		str->text[(str->max)] = 0;
		str->len = str->max;
		return (1);
	}

	str->len = str->len + written;
	return (0);
}

/*
 * Replace troublesome characters in a string with underscores
 * - only use for strings we already know the size of */

void strcpy_nospaces(char *dest, char *src) {
	static unsigned char allowed[256] =
		"_________________________________!_#_%__()*+,-.-0123456789_____?@"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ[_]^__abcdefghijklmnopqrstuvwxyz{_}_________"
		"__"
		"______________________________________________________________________"
		"__"
		"_______________________________________________";

	while (*src) {
		*(dest++) = allowed[(unsigned char)*(src++)];
	}
	*dest = 0;
}

/*
 * convert a (possibly large) integer to a string with unit suffix
 *
 * add the following check to configure.ac
 * AC_SEARCH_LIBS(pow, [c m], AC_DEFINE([HAVE_POW]))
 */

int gauge_to_si(u64 bignum, char **str) {
	long unsigned int i = 0;
	u64 tmpll;
	static char units[] = "kMGTPE";

	tmpll = bignum;

	while ((tmpll /= 1000ULL) && (i < (sizeof(units) - 1))) {
		i++;
	}

#ifdef HAVE_POW
	if (i) {
		return asprintf(str, "%0.2f%c", ((double)bignum / pow(1000, i)),
						units[i - 1]);
	} else {
		return asprintf(str, "%Ld", bignum);
	}
#else
	return asprintf(str, "%Ld", bignum);
#endif
}

static struct timespec benchmark_start_time;

static char *benchmark_task;

void benchmark_start(char const *format, ...) {
	{
		va_list args;
		va_start(args, format);
		int benchmark_task_length = vsnprintf(NULL, 0u, format, args);
		va_end(args);
		benchmark_task = (char *)malloc(benchmark_task_length + 1);
		benchmark_task[benchmark_task_length] = 0;
	}
	{
		va_list args;
		va_start(args, format);
		vsprintf(benchmark_task, format, args);
		va_end(args);
	}
	fprintf(stderr, "[Starting benchmark] %s\n", benchmark_task);
	clock_gettime(CLOCK_MONOTONIC, &benchmark_start_time);
}

void benchmark_end(void) {
	{
		struct timespec benchmark_end_time;
		clock_gettime(CLOCK_MONOTONIC, &benchmark_end_time);
		fprintf(stderr, "[Finished benchmark after %f ms] %s\n",
				((double)benchmark_end_time.tv_sec * 1000.0 +
				 (double)benchmark_end_time.tv_nsec / 1000000.0) -
					((double)benchmark_start_time.tv_sec * 1000.0 +
					 (double)benchmark_start_time.tv_nsec / 1000000.0),
				benchmark_task);
	}
	free(benchmark_task);
}

char *implode(char const *glue, char **pieces) {
	size_t total_len = 0u;
	char **walk_pieces = pieces;
	while (*walk_pieces != NULL) {
		total_len += strlen(*walk_pieces++);
	}

	ptrdiff_t walk_pieces_diff = walk_pieces - pieces;
	if (walk_pieces_diff >= 2) {
		total_len += strlen(glue) * (size_t)(walk_pieces_diff - 1);
	}

	char *result = (char *)malloc(total_len + 1u);

	if (walk_pieces_diff > 0) {
		strcpy(result, *pieces);
		if (walk_pieces_diff >= 2) {
			char *walk_result = result;
			walk_pieces = pieces + 1;
			while (*walk_pieces != NULL) {
				while (*walk_result) {
					++walk_result;
				}
				strcpy(walk_result, glue);

				while (*walk_result) {
					++walk_result;
				}
				strcpy(walk_result, *walk_pieces++);
			}
		}
	} else {
		*result = 0;
	}

	return result;
}
