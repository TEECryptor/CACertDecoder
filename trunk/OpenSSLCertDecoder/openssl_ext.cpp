#include "stdafx.h"
#include "openssl_ext.h"


int mypint(const unsigned char ** s, int n, int min, int max, int * e)
{
	int retval = 0;
	while (n) 
	{
		if (**s < '0' || **s > '9') 
		{ 
			*e = 1; 
			return 0; 
		}

		retval *= 10;
		retval += **s - '0';
		--n; 
		++(*s);
	}

	if (retval < min || retval > max) *e = 1;

	return retval;
}

time_t ASN1_TIME_get(ASN1_TIME *a, int *err)
{	
	char days[2][12] = {{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
						{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }};
	int dummy;
	const unsigned char *s;
	int generalized;
	struct tm t;
	int i, year, isleap, offset;
	time_t retval;

	if (err == NULL) err = &dummy;

	if (a->type == V_ASN1_GENERALIZEDTIME) 
	{
		generalized = 1;
	} 
	else if (a->type == V_ASN1_UTCTIME) 
	{
		generalized = 0;
	} 
	else 
	{
		*err = 1;
		return 0;
	}

	s = a->data; // Data should be always null terminated
	if (s == NULL || s[a->length] != '\0') 
	{
		*err = 1;
		return 0;
	}

	*err = 0;
	if (generalized) 
	{
		t.tm_year = mypint(&s, 4, 0, 9999, err) - 1900;
	} 
	else 
	{
		t.tm_year = mypint(&s, 2, 0, 99, err);
		if (t.tm_year < 50) t.tm_year += 100;
	}

	t.tm_mon = mypint(&s, 2, 1, 12, err) - 1;
	t.tm_mday = mypint(&s, 2, 1, 31, err);

	// NOTE: It's not yet clear, if this implementation is 100% correct
	// for GeneralizedTime... but at least misinterpretation is
	// impossible --- we just throw an exception

	t.tm_hour = mypint(&s, 2, 0, 23, err);
	t.tm_min = mypint(&s, 2, 0, 59, err);
	if (*s >= '0' && *s <= '9') 
	{
		t.tm_sec = mypint(&s, 2, 0, 59, err);
	} 
	else 
	{
		t.tm_sec = 0;
	}

	if (*err) return 0; // Format violation

	if (generalized) 
	{
		// skip fractional seconds if any
		while (*s == '.' || *s == ',' || (*s >= '0' && *s <= '9')) ++s;

		// special treatment for local time
		if (*s == 0) 
		{
			t.tm_isdst = -1;
			retval = mktime(&t); // Local time is easy :)
			if (retval == (time_t)-1) 
			{
				*err = 2;
				retval = 0;
			}

			return retval;
		}
	}

	if (*s == 'Z') 
	{
		offset = 0;
		++s;
	} 
	else if (*s == '-' || *s == '+') 
	{
		i = (*s++ == '-');
		offset = mypint(&s, 2, 0, 12, err);
		offset *= 60;
		offset += mypint(&s, 2, 0, 59, err);

		if (*err) return 0; // Format violation

		if (i) offset = -offset;
	} 
	else 
	{
		*err = 1;
		return 0;
	}

	if (*s) 
	{
		*err = 1;
		return 0;
	}

	// And here comes the hard part --- there's no standard function to
	// convert struct tm containing UTC time into time_t without
	// messing global timezone settings (breaks multithreading and may
	// cause other problems) and thus we have to do this "by hand"
	//
	// NOTE: Overflow check does not detect too big overflows, but is
	// sufficient thanks to the fact that year numbers are limited to four
	// digit non-negative values.

	retval = t.tm_sec;
	retval += (t.tm_min - offset) * 60;
	retval += t.tm_hour * 3600;
	retval += (t.tm_mday - 1) * 86400;
	year = t.tm_year + 1900;

	if ( sizeof (time_t) == 4) 
	{
		// This is just to avoid too big overflows being undetected, finer
		// overflow detection is done below.
		if (year < 1900 || year > 2040) *err = 2;
	}

	// FIXME: Does POSIX really say, that all years divisible by 4 are
	// leap years (for consistency)??? Fortunately, this problem does
	// not exist for 32-bit time_t and we should'nt be worried about
	// this until the year of 2100 :)
	isleap = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);
	for (i = t.tm_mon - 1; i >= 0; --i) 
	{
		retval += days[isleap][i] * 86400;
	}

	retval += (year - 1970) * 31536000;
	if (year < 1970) 
	{
		retval -= ((1970 - year + 2) / 4) * 86400;
		if ( sizeof (time_t) > 4) 
		{
			for (i = 1900; i >= year; i -= 100) 
			{
				if (i % 400 == 0) continue ;
				retval += 86400;
			}
		}
		if (retval >= 0) *err = 2;

	} 
	else 
	{
		retval += ((year - 1970 + 1) / 4) * 86400;
		if ( sizeof (time_t) > 4) 
		{
			for (i = 2100; i < year; i += 100) 
			{
				// The following condition is the reason to
				// start with 2100 instead of 2000
				if (i % 400 == 0) continue ;
				retval -= 86400;
			}
		}

		if (retval < 0) *err = 2;
	}

	if (*err) retval = 0;

	return retval;
}