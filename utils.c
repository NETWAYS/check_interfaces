#include "utils.h"

/*
 * Add a string
 */

int addstrold(char **strp, size_t *strs, const char *format, ...)
{
	va_list val;
	size_t written;


	va_start(val, format);

	written = vsnprintf(*strp, *strs, format, val);
	va_end(val);

	if (written >= *strs)
	{
		// buffer full
		*strs = 0;
		return(1);
	}
	
	*strs = (*strs - written);
	*strp = (*strp + written);
	return(0);
}

int addstr(String *str, const char *format, ...)
{
	va_list val;
	size_t written;
    size_t available;
    char *pos;

    available = str->max - str->len;
    pos = str->text + str->len;


	va_start(val, format);

	written = vsnprintf(pos, available, format, val);
	va_end(val);

	if (written >= available)
	{
		/* buffer full */
		str->text[(str->max)] = 0;
        str->len = str->max;
		return(1);
	}
	
	str->len = str->len + written;
	return(0);
}





/* 
 * Replace troublesome characters in a string with underscores
 * - only use for strings we already know the size of */

void strcpy_nospaces(char *dest, char *src)
{
	static unsigned char allowed[256] = "_________________________________!_#_%__()*+,-.-0123456789_____?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[_]^__abcdefghijklmnopqrstuvwxyz{_}__________________________________________________________________________________________________________________________________";



	while(*src)
	{
		*(dest++) = allowed[(unsigned char) *(src++)];
	}
	*dest = 0;
}



/*
 * convert a (possibly large) integer to a string with unit suffix
 *
 * add the following check to configure.ac
 * AC_SEARCH_LIBS(pow, [c m], AC_DEFINE([HAVE_POW]))
 */

int gauge_to_si(u64 bignum, char **str)
{
	int i = 0;
	u64 tmpll;
	static char units[] = "kMGTPE";

	tmpll = bignum;

	while ((tmpll /= 1000ULL) && (i < (sizeof(units) - 1)))
	{
		i++;
	}

#ifdef HAVE_POW
	if (i)
	{
		return asprintf(str, "%0.2f%c", ((double)bignum / pow(1000, i)), units[i-1]);
	}
    else
    {
		return asprintf(str, "%Ld", bignum);
	}
#else
    return asprintf(str, "%Ld", bignum);
#endif
	
}

